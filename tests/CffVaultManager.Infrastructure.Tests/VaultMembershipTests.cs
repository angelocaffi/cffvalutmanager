using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Crypto;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using CffVaultManager.Infrastructure.VaultCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// End-to-end coverage of the organization-vault sharing services (creation, membership invite /
/// revoke / listing, public-key mediation) and the permission-gating change to the vault-core
/// services, against an in-memory SQLite database. Provisioning/registration go through the real
/// services so users and personal vaults are genuine. Access failures are asserted as
/// <see cref="KeyNotFoundException"/> and insufficient-permission failures as
/// <see cref="InsufficientVaultPermissionException"/> (see docs/features/sharing-access-control.md).
/// </summary>
public sealed class VaultMembershipTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;

    // Real client-side crypto, used by a couple of tests to produce genuinely realistic wrapped-DEK
    // bytes; the services under test only store/compare these opaque bytes and never decrypt them.
    private static readonly X25519KeyExchangeService KeyExchange = new(new AesGcmCipherService());

    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);

    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    private static readonly byte[] Payload = { 9, 8, 7, 6 };

    public VaultMembershipTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            ctx.Database.EnsureCreated();
        }

        _authHashHasher = new ServerAuthHashHasher(new Argon2KeyDerivationService(), CheapKdf);
    }

    public void Dispose() => _connection.Dispose();

    // ---- CreateOrganizationVaultAsync -------------------------------------------------------

    [Fact]
    public async Task CreateOrganizationVaultAsync_creates_org_vault_and_owner_membership_for_creator()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();

        // Realistic wrapped-DEK bytes produced with the real X25519 scheme (opaque to the service).
        var (wrapped, ephemeral) = RealWrappedDek();

        VaultDto created;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            created = await new VaultService(ctx).CreateOrganizationVaultAsync(
                adminId, tenantId, new CreateOrganizationVaultRequest("Team", wrapped, ephemeral));
        }

        Assert.True(created.IsOrganizationVault);
        Assert.Equal("Team", created.Name);

        using var verify = CreateContext(SuperAdmin());
        var vault = await verify.Vaults.IgnoreQueryFilters().SingleAsync(v => v.Id == created.Id);
        Assert.True(vault.IsOrganizationVault);
        Assert.Null(vault.OwnerUserId);
        Assert.Equal(tenantId, vault.TenantId);

        var membership = await verify.VaultMemberships.IgnoreQueryFilters()
            .SingleAsync(m => m.VaultId == created.Id && m.UserId == adminId);
        Assert.Equal(VaultPermission.Owner, membership.Permission);
        Assert.Null(membership.RevokedAt);
        Assert.Equal(wrapped, membership.WrappedVaultDek);
        Assert.Equal(ephemeral, membership.EphemeralPublicKey);
    }

    // ---- ListAccessibleOrgVaultsAsync -------------------------------------------------------

    [Fact]
    public async Task ListAccessibleOrgVaultsAsync_returns_only_org_vaults_with_active_membership()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        var orgVaultA = await CreateOrgVaultAsync(tenantId, adminId, "A");
        var orgVaultB = await CreateOrgVaultAsync(tenantId, adminId, "B");
        await InviteMemberAsync(orgVaultA, adminId, tenantId, operatorId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, operatorId));
        var vaults = await new VaultService(ctx).ListAccessibleOrgVaultsAsync(operatorId);

        // Only the vault the operator was invited to; never the un-invited org vault or a personal one.
        Assert.Single(vaults);
        Assert.Equal(orgVaultA, vaults[0].Id);
        Assert.DoesNotContain(vaults, v => v.Id == orgVaultB);
        Assert.All(vaults, v => Assert.True(v.IsOrganizationVault));
    }

    [Fact]
    public async Task ListAccessibleOrgVaultsAsync_excludes_a_revoked_memberships_vault()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Read);

        // Revoke the operator, rewrapping only for the one remaining member (the admin creator).
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId,
                new RevokeMembershipRequest(operatorId,
                    Array.Empty<ReencryptedItem>(),
                    new[] { new NewMembership(adminId, WrappedDek(), EphemeralKey()) }));
        }

        using var ctx2 = CreateContext(Tenant(tenantId, operatorId));
        var vaults = await new VaultService(ctx2).ListAccessibleOrgVaultsAsync(operatorId);
        Assert.Empty(vaults);
    }

    // ---- InviteAsync ------------------------------------------------------------------------

    [Fact]
    public async Task InviteAsync_grants_read_access_and_creates_membership_row()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");

        var wrapped = WrappedDek();
        var ephemeral = EphemeralKey();

        VaultMembershipDto dto;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            dto = await new VaultMembershipService(ctx).InviteAsync(orgVault, adminId, tenantId,
                new CreateMembershipRequest(operatorId, VaultPermission.Read, wrapped, ephemeral));
        }

        Assert.Equal(operatorId, dto.UserId);
        Assert.Equal(orgVault, dto.VaultId);
        Assert.Equal(VaultPermission.Read, dto.Permission);

        using var verify = CreateContext(SuperAdmin());
        var membership = await verify.VaultMemberships.IgnoreQueryFilters()
            .SingleAsync(m => m.VaultId == orgVault && m.UserId == operatorId);
        Assert.Equal(VaultPermission.Read, membership.Permission);
        Assert.Equal(adminId, membership.InvitedByUserId);
        Assert.Null(membership.RevokedAt);
        Assert.Equal(wrapped, membership.WrappedVaultDek);
        Assert.Equal(ephemeral, membership.EphemeralPublicKey);
    }

    [Fact]
    public async Task InviteAsync_same_user_twice_throws_InvalidOperationException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new VaultMembershipService(ctx).InviteAsync(orgVault, adminId, tenantId,
                new CreateMembershipRequest(operatorId, VaultPermission.ReadWrite, WrappedDek(), EphemeralKey())));
    }

    [Fact]
    public async Task InviteAsync_user_from_a_different_tenant_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (tenant2, admin2, _) = await ProvisionAsync("beta", "admin@beta.com");
        var foreignUser = await RegisterUserAsync(tenant2, admin2, UniqueEmail());

        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultMembershipService(ctx).InviteAsync(orgVault, adminId, tenantId,
                new CreateMembershipRequest(foreignUser, VaultPermission.Read, WrappedDek(), EphemeralKey())));
    }

    [Fact]
    public async Task InviteAsync_into_a_personal_vault_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, personalVaultId) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultMembershipService(ctx).InviteAsync(personalVaultId, adminId, tenantId,
                new CreateMembershipRequest(operatorId, VaultPermission.Read, WrappedDek(), EphemeralKey())));
    }

    [Fact]
    public async Task InviteAsync_into_a_vault_in_a_different_tenant_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (tenant2, admin2, _) = await ProvisionAsync("beta", "admin@beta.com");
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        // An org vault owned by tenant 2; the tenant-1 admin must not see or invite into it.
        var foreignVault = await CreateOrgVaultAsync(tenant2, admin2, "Foreign");

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultMembershipService(ctx).InviteAsync(foreignVault, adminId, tenantId,
                new CreateMembershipRequest(operatorId, VaultPermission.Read, WrappedDek(), EphemeralKey())));
    }

    [Fact]
    public async Task InviteAsync_by_a_same_tenant_admin_who_is_not_a_member_throws_KeyNotFoundException()
    {
        // Regression test for a security-review finding: an Admin must not be able to grant
        // themselves (or anyone else) access to an org vault they were never invited to, purely by
        // virtue of holding the Admin role — "being Admin" is not a backdoor (see docs/multi-
        // tenancy.md, docs/features/roles-permissions.md: "Accedere a vault di organizzazione ...
        // Se invitato" applies to Admins too).
        var (tenantId, adminId, _) = await ProvisionAsync();
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "Team");

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var secondAdminId = await new UserRegistrationService(ctx, _authHashHasher).RegisterInTenantAsync(
            NewRegisterRequest(UniqueEmail(), UserRole.Admin), adminId, UserRole.Admin, tenantId);

        // secondAdminId is a same-tenant Admin but was never invited to orgVault (created by
        // adminId). They must not be able to self-invite, even though they hold the Admin role.
        using var ctx2 = CreateContext(Tenant(tenantId, secondAdminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultMembershipService(ctx2).InviteAsync(orgVault, secondAdminId, tenantId,
                new CreateMembershipRequest(secondAdminId, VaultPermission.ReadWrite, WrappedDek(), EphemeralKey())));
    }

    [Fact]
    public async Task RevokeAsync_by_a_same_tenant_admin_who_is_not_a_member_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "Team");
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var secondAdminId = await new UserRegistrationService(ctx, _authHashHasher).RegisterInTenantAsync(
            NewRegisterRequest(UniqueEmail(), UserRole.Admin), adminId, UserRole.Admin, tenantId);

        using var ctx2 = CreateContext(Tenant(tenantId, secondAdminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultMembershipService(ctx2).RevokeAsync(orgVault, secondAdminId, tenantId,
                new RevokeMembershipRequest(operatorId,
                    Array.Empty<ReencryptedItem>(),
                    new[] { new NewMembership(adminId, WrappedDek(), EphemeralKey()) })));
    }

    [Fact]
    public async Task InviteAsync_by_a_Read_only_member_throws_InsufficientVaultPermissionException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var readerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "Team");
        await InviteMemberAsync(orgVault, adminId, tenantId, readerId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, readerId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            new VaultMembershipService(ctx).InviteAsync(orgVault, readerId, tenantId,
                new CreateMembershipRequest(strangerId, VaultPermission.Read, WrappedDek(), EphemeralKey())));
    }

    [Fact]
    public async Task InviteAsync_by_a_ReadWrite_member_who_is_not_Owner_throws_InsufficientVaultPermissionException()
    {
        // Behavior change: a plain ReadWrite member used to be able to invite (gated by tenant
        // Admin role at the endpoint); now only the vault's own Owner can, regardless of tenant role.
        var (tenantId, adminId, _) = await ProvisionAsync();
        var writerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "Team");
        await InviteMemberAsync(orgVault, adminId, tenantId, writerId, VaultPermission.ReadWrite);

        using var ctx = CreateContext(Tenant(tenantId, writerId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            new VaultMembershipService(ctx).InviteAsync(orgVault, writerId, tenantId,
                new CreateMembershipRequest(strangerId, VaultPermission.Read, WrappedDek(), EphemeralKey())));
    }

    [Fact]
    public async Task InviteAsync_by_an_Operator_who_is_vault_Owner_succeeds_even_without_tenant_Admin_role()
    {
        // The whole point of the Owner role: vault membership authority is decoupled from the
        // caller's tenant-wide role. An Operator (not a tenant Admin) invited as Owner can manage
        // this vault's membership just like the Admin creator could.
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "Team");
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Owner);

        using var ctx = CreateContext(Tenant(tenantId, operatorId));
        var dto = await new VaultMembershipService(ctx).InviteAsync(orgVault, operatorId, tenantId,
            new CreateMembershipRequest(strangerId, VaultPermission.Read, WrappedDek(), EphemeralKey()));

        Assert.Equal(strangerId, dto.UserId);
    }

    // ---- GetPublicKeyAsync ------------------------------------------------------------------

    [Fact]
    public async Task GetPublicKeyAsync_when_user_has_no_public_key_throws_InvalidOperationException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        // A freshly registered user has no keypair yet.
        using (var verify = CreateContext(SuperAdmin()))
        {
            var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == operatorId);
            Assert.Null(user.PublicKey);
        }

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new VaultMembershipService(ctx).GetPublicKeyAsync(operatorId, adminId, tenantId));
    }

    [Fact]
    public async Task GetPublicKeyAsync_returns_the_key_after_it_is_set()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        var publicKey = PublicKeyBytes();
        await SetPublicKeyAsync(operatorId, publicKey);

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var dto = await new VaultMembershipService(ctx).GetPublicKeyAsync(operatorId, adminId, tenantId);
        Assert.Equal(publicKey, dto.PublicKey);
    }

    [Fact]
    public async Task GetPublicKeyAsync_for_a_user_in_a_different_tenant_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (tenant2, admin2, _) = await ProvisionAsync("beta", "admin@beta.com");
        var foreignUser = await RegisterUserAsync(tenant2, admin2, UniqueEmail());
        await SetPublicKeyAsync(foreignUser, PublicKeyBytes());

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultMembershipService(ctx).GetPublicKeyAsync(foreignUser, adminId, tenantId));
    }

    [Fact]
    public async Task GetPublicKeyAsync_for_a_nonexistent_user_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultMembershipService(ctx).GetPublicKeyAsync(Guid.NewGuid(), adminId, tenantId));
    }

    // ---- Permission gating: read-only members ----------------------------------------------

    [Fact]
    public async Task ReadMember_can_list_get_and_view_trash()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        var itemId = await CreateItemAsync(orgVault, adminId);
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, operatorId));
        var items = new VaultItemService(ctx);

        var list = await items.ListAsync(orgVault, operatorId, new VaultItemListQuery());
        Assert.Single(list);

        var fetched = await items.GetAsync(orgVault, itemId, operatorId);
        Assert.Equal(itemId, fetched.Id);

        Assert.Empty(await items.ListTrashAsync(orgVault, operatorId));
    }

    [Fact]
    public async Task ReadMember_item_write_operations_throw_InsufficientVaultPermissionException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        var itemId = await CreateItemAsync(orgVault, adminId);
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, operatorId));
        var items = new VaultItemService(ctx);
        var tagId = Guid.NewGuid();

        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            items.CreateAsync(orgVault, operatorId, new CreateVaultItemRequest(VaultItemType.Password, Payload)));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            items.UpdateAsync(orgVault, itemId, operatorId,
                new UpdateVaultItemRequest(VaultItemType.Password, Payload, FolderId: null, IsFavorite: false)));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            items.SoftDeleteAsync(orgVault, itemId, operatorId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            items.RestoreAsync(orgVault, itemId, operatorId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            items.PermanentlyDeleteAsync(orgVault, itemId, operatorId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            items.AssignTagAsync(orgVault, itemId, tagId, operatorId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            items.RemoveTagAsync(orgVault, itemId, tagId, operatorId));
    }

    [Fact]
    public async Task ReadMember_folder_writes_throw_but_list_succeeds()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, operatorId));
        var folders = new FolderService(ctx);

        Assert.Empty(await folders.ListAsync(orgVault, operatorId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            folders.CreateAsync(orgVault, operatorId, new CreateFolderRequest("Work")));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            folders.RenameAsync(orgVault, Guid.NewGuid(), operatorId, new RenameFolderRequest("Renamed")));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            folders.DeleteAsync(orgVault, Guid.NewGuid(), operatorId));
    }

    [Fact]
    public async Task ReadMember_tag_writes_throw_but_list_succeeds()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, operatorId));
        var tags = new TagService(ctx);

        Assert.Empty(await tags.ListAsync(orgVault, operatorId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            tags.CreateAsync(orgVault, operatorId, new CreateTagRequest("email")));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            tags.RenameAsync(orgVault, Guid.NewGuid(), operatorId, new RenameTagRequest("mail")));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            tags.DeleteAsync(orgVault, Guid.NewGuid(), operatorId));
    }

    [Fact]
    public async Task ReadWriteMember_can_create_a_vault_item()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var writerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        await InviteMemberAsync(orgVault, adminId, tenantId, writerId, VaultPermission.ReadWrite);

        using var ctx = CreateContext(Tenant(tenantId, writerId));
        var created = await new VaultItemService(ctx)
            .CreateAsync(orgVault, writerId, new CreateVaultItemRequest(VaultItemType.Password, Payload));

        Assert.NotEqual(Guid.Empty, created.Id);
    }

    [Fact]
    public async Task NonMember_gets_KeyNotFoundException_not_forbidden()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        var itemId = await CreateItemAsync(orgVault, adminId);

        using var ctx = CreateContext(Tenant(tenantId, strangerId));
        var items = new VaultItemService(ctx);
        var folders = new FolderService(ctx);
        var tags = new TagService(ctx);

        // A user with no membership must not even learn the vault exists: not found, not forbidden.
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            items.ListAsync(orgVault, strangerId, new VaultItemListQuery()));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => items.GetAsync(orgVault, itemId, strangerId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            items.CreateAsync(orgVault, strangerId, new CreateVaultItemRequest(VaultItemType.Password, Payload)));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => folders.ListAsync(orgVault, strangerId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => tags.ListAsync(orgVault, strangerId));
    }

    // ---- RevokeAsync ------------------------------------------------------------------------

    [Fact]
    public async Task RevokeAsync_happy_path_rotates_dek_revokes_member_and_writes_audit()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (orgVault, op1, op2) = await ThreeMemberVaultAsync(tenantId, adminId);
        var itemId = await CreateItemAsync(orgVault, adminId);

        var newPayload = RandomBytes(40);
        var adminWrap = WrappedDek();
        var adminEph = EphemeralKey();
        var op2Wrap = WrappedDek();
        var op2Eph = EphemeralKey();

        var request = new RevokeMembershipRequest(op1,
            new[] { new ReencryptedItem(itemId, newPayload) },
            new[]
            {
                new NewMembership(adminId, adminWrap, adminEph),
                new NewMembership(op2, op2Wrap, op2Eph),
            });

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId, request);
        }

        using (var verify = CreateContext(SuperAdmin()))
        {
            var revoked = await verify.VaultMemberships.IgnoreQueryFilters()
                .SingleAsync(m => m.VaultId == orgVault && m.UserId == op1);
            Assert.NotNull(revoked.RevokedAt);

            var item = await verify.VaultItems.IgnoreQueryFilters().SingleAsync(i => i.Id == itemId);
            Assert.Equal(newPayload, item.EncryptedPayload);

            var adminM = await verify.VaultMemberships.IgnoreQueryFilters()
                .SingleAsync(m => m.VaultId == orgVault && m.UserId == adminId);
            Assert.Equal(adminWrap, adminM.WrappedVaultDek);
            Assert.Equal(adminEph, adminM.EphemeralPublicKey);

            var op2M = await verify.VaultMemberships.IgnoreQueryFilters()
                .SingleAsync(m => m.VaultId == orgVault && m.UserId == op2);
            Assert.Equal(op2Wrap, op2M.WrappedVaultDek);
            Assert.Equal(op2Eph, op2M.EphemeralPublicKey);

            Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
                .AnyAsync(a => a.TenantId == tenantId && a.UserId == adminId && a.Action == AuditAction.Revoked));
        }

        // The revoked member can no longer resolve access; the remaining members still can.
        using (var ctx = CreateContext(Tenant(tenantId, op1)))
        {
            await Assert.ThrowsAsync<KeyNotFoundException>(() =>
                VaultAccessGuard.GetAccessibleVaultAsync(ctx, orgVault, op1, default));
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var (_, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(ctx, orgVault, adminId, default);
            Assert.Equal(VaultPermission.Owner, permission);
        }

        using (var ctx = CreateContext(Tenant(tenantId, op2)))
        {
            var (_, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(ctx, orgVault, op2, default);
            Assert.Equal(VaultPermission.ReadWrite, permission);
        }
    }

    [Fact]
    public async Task RevokeAsync_by_a_ReadWrite_member_who_is_not_Owner_throws_InsufficientVaultPermissionException()
    {
        // Same behavior change as invite: a plain ReadWrite member can no longer revoke, even
        // though the old model allowed any ReadWrite member (gated by tenant Admin role) to do so.
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (orgVault, op1, op2) = await ThreeMemberVaultAsync(tenantId, adminId);

        var request = new RevokeMembershipRequest(op2, Array.Empty<ReencryptedItem>(),
            new[] { new NewMembership(adminId, WrappedDek(), EphemeralKey()) });

        using var ctx = CreateContext(Tenant(tenantId, op1));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            new VaultMembershipService(ctx).RevokeAsync(orgVault, op1, tenantId, request));
    }

    [Fact]
    public async Task RevokeAsync_with_new_memberships_missing_a_remaining_member_throws_InvalidOperationException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (orgVault, op1, op2) = await ThreeMemberVaultAsync(tenantId, adminId);

        // Remaining members are admin + op2, but only admin is provided.
        var request = new RevokeMembershipRequest(op1,
            Array.Empty<ReencryptedItem>(),
            new[] { new NewMembership(adminId, WrappedDek(), EphemeralKey()) });

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId, request));
        _ = op2;
    }

    [Fact]
    public async Task RevokeAsync_with_new_memberships_including_an_extra_user_throws_InvalidOperationException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (orgVault, op1, op2) = await ThreeMemberVaultAsync(tenantId, adminId);
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        // admin + op2 are the real remaining members; a stranger who is not a member is also included.
        var request = new RevokeMembershipRequest(op1,
            Array.Empty<ReencryptedItem>(),
            new[]
            {
                new NewMembership(adminId, WrappedDek(), EphemeralKey()),
                new NewMembership(op2, WrappedDek(), EphemeralKey()),
                new NewMembership(strangerId, WrappedDek(), EphemeralKey()),
            });

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId, request));
    }

    [Fact]
    public async Task RevokeAsync_with_new_memberships_including_the_revoked_user_throws_InvalidOperationException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (orgVault, op1, op2) = await ThreeMemberVaultAsync(tenantId, adminId);

        // The just-revoked op1 must NOT be in the remaining set; op2 is wrongly omitted in its place.
        var request = new RevokeMembershipRequest(op1,
            Array.Empty<ReencryptedItem>(),
            new[]
            {
                new NewMembership(adminId, WrappedDek(), EphemeralKey()),
                new NewMembership(op1, WrappedDek(), EphemeralKey()),
            });

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId, request));
        _ = op2;
    }

    [Fact]
    public async Task RevokeAsync_with_reencrypted_items_missing_a_current_item_throws_InvalidOperationException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (orgVault, op1, op2) = await ThreeMemberVaultAsync(tenantId, adminId);
        var itemA = await CreateItemAsync(orgVault, adminId);
        var itemB = await CreateItemAsync(orgVault, adminId);

        // Two current items exist, but only one is re-encrypted.
        var request = new RevokeMembershipRequest(op1,
            new[] { new ReencryptedItem(itemA, RandomBytes(32)) },
            RemainingMemberships(adminId, op2));

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId, request));
        _ = itemB;
    }

    [Fact]
    public async Task RevokeAsync_with_reencrypted_items_from_another_vault_throws_InvalidOperationException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (orgVault, op1, op2) = await ThreeMemberVaultAsync(tenantId, adminId);
        await CreateItemAsync(orgVault, adminId);

        // An item that belongs to a different org vault, not this one.
        var otherVault = await CreateOrgVaultAsync(tenantId, adminId, "Other");
        var foreignItem = await CreateItemAsync(otherVault, adminId);

        var request = new RevokeMembershipRequest(op1,
            new[] { new ReencryptedItem(foreignItem, RandomBytes(32)) },
            RemainingMemberships(adminId, op2));

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId, request));
    }

    [Fact]
    public async Task RevokeAsync_for_a_user_with_no_active_membership_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        var request = new RevokeMembershipRequest(strangerId,
            Array.Empty<ReencryptedItem>(),
            new[] { new NewMembership(adminId, WrappedDek(), EphemeralKey()) });

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId, request));
    }

    [Fact]
    public async Task RevokeAsync_excludes_soft_deleted_items_from_the_required_reencrypted_set()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (orgVault, op1, op2) = await ThreeMemberVaultAsync(tenantId, adminId);
        var liveItem = await CreateItemAsync(orgVault, adminId);
        var deletedItem = await CreateItemAsync(orgVault, adminId);

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new VaultItemService(ctx).SoftDeleteAsync(orgVault, deletedItem, adminId);
        }

        // Only the live item needs re-encryption; omitting the soft-deleted one must succeed.
        var request = new RevokeMembershipRequest(op1,
            new[] { new ReencryptedItem(liveItem, RandomBytes(32)) },
            RemainingMemberships(adminId, op2));

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId, request);
        }

        using var verify = CreateContext(SuperAdmin());
        var revoked = await verify.VaultMemberships.IgnoreQueryFilters()
            .SingleAsync(m => m.VaultId == orgVault && m.UserId == op1);
        Assert.NotNull(revoked.RevokedAt);
    }

    // ---- ListMembersAsync -------------------------------------------------------------------

    [Fact]
    public async Task ListMembersAsync_returns_only_active_members()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (orgVault, op1, op2) = await ThreeMemberVaultAsync(tenantId, adminId);

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new VaultMembershipService(ctx).RevokeAsync(orgVault, adminId, tenantId,
                new RevokeMembershipRequest(op1, Array.Empty<ReencryptedItem>(), RemainingMemberships(adminId, op2)));
        }

        using var ctx2 = CreateContext(Tenant(tenantId, adminId));
        var members = await new VaultMembershipService(ctx2).ListMembersAsync(orgVault, adminId, tenantId);

        Assert.Equal(2, members.Count);
        Assert.Contains(members, m => m.UserId == adminId);
        Assert.Contains(members, m => m.UserId == op2);
        Assert.DoesNotContain(members, m => m.UserId == op1);
    }

    [Fact]
    public async Task ListMembersAsync_can_be_called_by_a_read_only_member()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, operatorId));
        var members = await new VaultMembershipService(ctx).ListMembersAsync(orgVault, operatorId, tenantId);

        Assert.Equal(2, members.Count);
        Assert.Contains(members, m => m.UserId == operatorId);
    }

    [Fact]
    public async Task ListMembersAsync_for_a_non_member_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");

        using var ctx = CreateContext(Tenant(tenantId, strangerId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultMembershipService(ctx).ListMembersAsync(orgVault, strangerId, tenantId));
    }

    // ---- VaultPermissionExtensions.CanWrite() covers Owner too -------------------------------

    [Fact]
    public async Task VaultItemService_CreateAsync_by_an_Owner_member_succeeds()
    {
        // The write gate on VaultItemService/FolderService/TagService switched from
        // "permission != ReadWrite" to "!permission.CanWrite()" to accommodate the new Owner
        // value — this proves an Owner member (not just ReadWrite) can still write.
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "Team");
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.Owner);

        var itemId = await CreateItemAsync(orgVault, operatorId);

        using var verify = CreateContext(SuperAdmin());
        Assert.True(await verify.VaultItems.IgnoreQueryFilters().AnyAsync(i => i.Id == itemId && i.VaultId == orgVault));
    }

    // ---- Personal-vault behavior is unchanged (via GetAccessibleVaultAsync) -----------------

    [Fact]
    public async Task GetAccessibleVaultAsync_resolves_personal_vault_to_readwrite_for_owner()
    {
        var (tenantId, adminId, personalVaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var (vault, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(ctx, personalVaultId, adminId, default);

        Assert.Equal(personalVaultId, vault.Id);
        Assert.False(vault.IsOrganizationVault);
        Assert.Equal(VaultPermission.ReadWrite, permission);
    }

    [Fact]
    public async Task GetAccessibleVaultAsync_hides_a_personal_vault_from_a_non_owner()
    {
        var (tenantId, adminId, personalVaultId) = await ProvisionAsync();
        var otherId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        using var ctx = CreateContext(Tenant(tenantId, otherId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            VaultAccessGuard.GetAccessibleVaultAsync(ctx, personalVaultId, otherId, default));
    }

    [Fact]
    public async Task GetAccessibleVaultAsync_org_member_cannot_access_an_unrelated_personal_vault()
    {
        var (tenantId, adminId, adminPersonalVaultId) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "A");
        await InviteMemberAsync(orgVault, adminId, tenantId, operatorId, VaultPermission.ReadWrite);

        // Being a member of an org vault grants nothing on the admin's separate personal vault.
        using var ctx = CreateContext(Tenant(tenantId, operatorId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            VaultAccessGuard.GetAccessibleVaultAsync(ctx, adminPersonalVaultId, operatorId, default));
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private CffVaultManagerDbContext CreateContext(ITenantContext tenantContext)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlite(_connection)
            .Options;
        return new CffVaultManagerDbContext(options, tenantContext);
    }

    private async Task<(Guid TenantId, Guid AdminId, Guid VaultId)> ProvisionAsync(
        string slug = "acme", string adminEmail = "admin@x.com")
    {
        ProvisionTenantResult result;
        using (var ctx = CreateContext(Unresolved()))
        {
            var service = new ProvisionTenantService(ctx, _authHashHasher);
            result = await service.ProvisionAsync(NewProvisionRequest(slug, adminEmail));
        }

        using var verify = CreateContext(SuperAdmin());
        var vaultId = (await verify.Vaults.IgnoreQueryFilters().SingleAsync(v => v.OwnerUserId == result.AdminUserId)).Id;
        return (result.TenantId, result.AdminUserId, vaultId);
    }

    private async Task<Guid> RegisterUserAsync(Guid tenantId, Guid adminId, string email)
    {
        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new UserRegistrationService(ctx, _authHashHasher);
        return await service.RegisterInTenantAsync(
            NewRegisterRequest(email, UserRole.Operator), adminId, UserRole.Admin, tenantId);
    }

    private async Task<Guid> CreateOrgVaultAsync(Guid tenantId, Guid callerId, string name)
    {
        using var ctx = CreateContext(Tenant(tenantId, callerId));
        var (wrapped, ephemeral) = RealWrappedDek();
        var dto = await new VaultService(ctx).CreateOrganizationVaultAsync(
            callerId, tenantId, new CreateOrganizationVaultRequest(name, wrapped, ephemeral));
        return dto.Id;
    }

    private async Task<VaultMembershipDto> InviteMemberAsync(
        Guid vaultId, Guid callerId, Guid tenantId, Guid userId, VaultPermission permission)
    {
        using var ctx = CreateContext(Tenant(tenantId, callerId));
        return await new VaultMembershipService(ctx).InviteAsync(vaultId, callerId, tenantId,
            new CreateMembershipRequest(userId, permission, WrappedDek(), EphemeralKey()));
    }

    private async Task<Guid> CreateItemAsync(Guid vaultId, Guid callerId)
    {
        // The caller must hold ReadWrite on the vault (creator or ReadWrite member).
        using var ctx = CreateContext(Tenant(await TenantOfAsync(callerId), callerId));
        var dto = await new VaultItemService(ctx)
            .CreateAsync(vaultId, callerId, new CreateVaultItemRequest(VaultItemType.Password, Payload));
        return dto.Id;
    }

    private async Task<(Guid VaultId, Guid Op1, Guid Op2)> ThreeMemberVaultAsync(Guid tenantId, Guid adminId)
    {
        var op1 = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var op2 = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var vaultId = await CreateOrgVaultAsync(tenantId, adminId, "A");
        await InviteMemberAsync(vaultId, adminId, tenantId, op1, VaultPermission.ReadWrite);
        await InviteMemberAsync(vaultId, adminId, tenantId, op2, VaultPermission.ReadWrite);
        return (vaultId, op1, op2);
    }

    private static NewMembership[] RemainingMemberships(params Guid[] userIds) =>
        userIds.Select(id => new NewMembership(id, WrappedDek(), EphemeralKey())).ToArray();

    private async Task<Guid> TenantOfAsync(Guid userId)
    {
        using var ctx = CreateContext(SuperAdmin());
        var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        return user.TenantId!.Value;
    }

    private async Task SetPublicKeyAsync(Guid userId, byte[] publicKey)
    {
        using var ctx = CreateContext(SuperAdmin());
        var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        user.PublicKey = publicKey;
        await ctx.SaveChangesAsync();
    }

    private static (byte[] Wrapped, byte[] Ephemeral) RealWrappedDek()
    {
        var (publicKey, _) = KeyExchange.GenerateKeyPair();
        var dek = RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);
        var (ephemeral, wrapped) = KeyExchange.WrapKey(publicKey, dek);
        return (wrapped.ToBytes(), ephemeral);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    private static byte[] WrappedDek() => RandomBytes(48);

    private static byte[] EphemeralKey() => RandomBytes(CryptoConstants.X25519KeyLengthBytes);

    private static byte[] PublicKeyBytes() => RandomBytes(CryptoConstants.X25519KeyLengthBytes);

    private static string UniqueEmail() => $"u{Guid.NewGuid():N}@x.com";

    private static ProvisionTenantRequest NewProvisionRequest(string slug, string adminEmail) => new(
        TenantName: slug,
        TenantSlug: slug,
        AdminEmail: adminEmail,
        AuthHash: RandomAuthHash(),
        EncryptedDek: Dek,
        MasterPasswordSalt: Salt,
        KdfMemoryKb: 65536,
        KdfIterations: 3,
        KdfVersion: 1);

    private static RegisterUserRequest NewRegisterRequest(string email, UserRole role) => new(
        Email: email,
        Role: role,
        AuthHash: RandomAuthHash(),
        EncryptedDek: Dek,
        MasterPasswordSalt: Salt,
        KdfMemoryKb: 65536,
        KdfIterations: 3,
        KdfVersion: 1);

    private static byte[] RandomAuthHash() => RandomNumberGenerator.GetBytes(32);

    private static ITenantContext Unresolved() => new TenantContext();

    private static ITenantContext Tenant(Guid tenantId, Guid userId)
    {
        var c = new TenantContext();
        c.SetTenant(tenantId, userId);
        return c;
    }

    private static ITenantContext SuperAdmin()
    {
        var c = new TenantContext();
        c.SetSuperAdmin(Guid.NewGuid());
        return c;
    }
}
