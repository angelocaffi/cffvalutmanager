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
/// Coverage for <see cref="ItemMembershipService"/> — live sharing of a single vault item (see
/// docs/features/sharing-access-control.md "Condivisione live di singola voce"): promotion on first
/// share, adding/revoking members with key rotation, the "shared with me" feed, and the additive
/// <c>MySharedAccess</c> field on <see cref="VaultItemService"/>'s own DTOs. Mirrors the fixture
/// style of <see cref="VaultMembershipTests"/>.
/// </summary>
public sealed class ItemMembershipTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;

    private static readonly X25519KeyExchangeService KeyExchange = new(new AesGcmCipherService());
    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);

    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    private static readonly byte[] Payload = { 9, 8, 7, 6 };

    public ItemMembershipTests()
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

    // ---- ShareAsync (first promotion) --------------------------------------------------------

    [Fact]
    public async Task ShareAsync_creates_owner_and_recipient_memberships_and_updates_payload()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var recipientId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(recipientId, PublicKeyBytes());

        var newPayload = RandomBytes(40);
        ItemMembershipDto dto;
        using (var ctx = CreateContext(Tenant(tenantId, ownerId)))
        {
            dto = await new ItemMembershipService(ctx).ShareAsync(vaultId, itemId, ownerId, tenantId,
                new ShareItemRequest(await EmailOfAsync(recipientId), ItemSharePermission.Viewer,
                    newPayload, WrappedKey(), EphemeralKey(), WrappedKey(), EphemeralKey()));
        }

        Assert.Equal(recipientId, dto.UserId);
        Assert.Equal(ItemSharePermission.Viewer, dto.Permission);

        using var verify = CreateContext(SuperAdmin());
        var ownerMembership = await verify.ItemMemberships.IgnoreQueryFilters()
            .SingleAsync(m => m.VaultItemId == itemId && m.UserId == ownerId);
        Assert.Equal(ItemSharePermission.Owner, ownerMembership.Permission);

        var item = await verify.VaultItems.IgnoreQueryFilters().SingleAsync(i => i.Id == itemId);
        Assert.Equal(newPayload, item.EncryptedPayload);

        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.TenantId == tenantId && a.UserId == ownerId && a.Action == AuditAction.ItemMembershipGranted));
    }

    [Fact]
    public async Task ShareAsync_when_already_shared_throws_InvalidOperationException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var recipient1 = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        var recipient2 = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(recipient1, PublicKeyBytes());
        await SetPublicKeyAsync(recipient2, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, recipient1);

        string recipient2Email = await EmailOfAsync(recipient2);
        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new ItemMembershipService(ctx).ShareAsync(vaultId, itemId, ownerId, tenantId,
                new ShareItemRequest(recipient2Email, ItemSharePermission.Viewer,
                    RandomBytes(32), WrappedKey(), EphemeralKey(), WrappedKey(), EphemeralKey())));
    }

    [Fact]
    public async Task ShareAsync_with_a_cross_tenant_recipient_email_throws_KeyNotFoundException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var (tenant2, admin2, _) = await ProvisionAsync("beta", "admin@beta.com");
        var foreignUser = await RegisterUserAsync(tenant2, admin2, UniqueEmail());
        await SetPublicKeyAsync(foreignUser, PublicKeyBytes());

        string foreignUserEmail = await EmailOfAsync(foreignUser);
        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new ItemMembershipService(ctx).ShareAsync(vaultId, itemId, ownerId, tenantId,
                new ShareItemRequest(foreignUserEmail, ItemSharePermission.Viewer,
                    RandomBytes(32), WrappedKey(), EphemeralKey(), WrappedKey(), EphemeralKey())));
    }

    [Fact]
    public async Task ShareAsync_when_recipient_has_no_key_pair_throws_InvalidOperationException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var recipientId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());

        string recipientEmail = await EmailOfAsync(recipientId);
        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new ItemMembershipService(ctx).ShareAsync(vaultId, itemId, ownerId, tenantId,
                new ShareItemRequest(recipientEmail, ItemSharePermission.Viewer,
                    RandomBytes(32), WrappedKey(), EphemeralKey(), WrappedKey(), EphemeralKey())));
    }

    [Fact]
    public async Task ShareAsync_with_yourself_as_recipient_throws_InvalidOperationException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        await SetPublicKeyAsync(ownerId, PublicKeyBytes());

        string ownerEmail = await EmailOfAsync(ownerId);
        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new ItemMembershipService(ctx).ShareAsync(vaultId, itemId, ownerId, tenantId,
                new ShareItemRequest(ownerEmail, ItemSharePermission.Viewer,
                    RandomBytes(32), WrappedKey(), EphemeralKey(), WrappedKey(), EphemeralKey())));
    }

    [Fact]
    public async Task ShareAsync_by_a_ReadOnly_org_vault_member_throws_InsufficientVaultPermissionException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var readerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var recipientId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        await SetPublicKeyAsync(recipientId, PublicKeyBytes());
        var orgVault = await CreateOrgVaultAsync(tenantId, adminId, "Team");
        var itemId = await CreateItemAsync(orgVault, adminId);
        await InviteMemberAsync(orgVault, adminId, tenantId, readerId, VaultPermission.Read);

        string recipientEmail = await EmailOfAsync(recipientId);
        using var ctx = CreateContext(Tenant(tenantId, readerId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            new ItemMembershipService(ctx).ShareAsync(orgVault, itemId, readerId, tenantId,
                new ShareItemRequest(recipientEmail, ItemSharePermission.Viewer,
                    RandomBytes(32), WrappedKey(), EphemeralKey(), WrappedKey(), EphemeralKey())));
    }

    // ---- AddMemberAsync -----------------------------------------------------------------------

    [Fact]
    public async Task AddMemberAsync_by_the_owner_succeeds()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var recipient1 = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        var recipient2 = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(recipient1, PublicKeyBytes());
        await SetPublicKeyAsync(recipient2, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, recipient1);

        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        var dto = await new ItemMembershipService(ctx).AddMemberAsync(itemId, ownerId, tenantId,
            new AddItemMemberRequest(await EmailOfAsync(recipient2), ItemSharePermission.Editor, WrappedKey(), EphemeralKey()));

        Assert.Equal(recipient2, dto.UserId);
        Assert.Equal(ItemSharePermission.Editor, dto.Permission);
    }

    [Fact]
    public async Task AddMemberAsync_by_a_Viewer_throws_InsufficientVaultPermissionException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        var recipientId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await SetPublicKeyAsync(recipientId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId);

        string recipientEmail = await EmailOfAsync(recipientId);
        using var ctx = CreateContext(Tenant(tenantId, viewerId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            new ItemMembershipService(ctx).AddMemberAsync(itemId, viewerId, tenantId,
                new AddItemMemberRequest(recipientEmail, ItemSharePermission.Viewer, WrappedKey(), EphemeralKey())));
    }

    [Fact]
    public async Task AddMemberAsync_for_a_user_already_a_member_throws_InvalidOperationException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var recipientId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(recipientId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, recipientId);

        string recipientEmail = await EmailOfAsync(recipientId);
        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new ItemMembershipService(ctx).AddMemberAsync(itemId, ownerId, tenantId,
                new AddItemMemberRequest(recipientEmail, ItemSharePermission.Editor, WrappedKey(), EphemeralKey())));
    }

    // ---- RevokeAsync --------------------------------------------------------------------------

    [Fact]
    public async Task RevokeAsync_happy_path_rotates_key_revokes_member_and_writes_audit()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        var editorId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await SetPublicKeyAsync(editorId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId);
        await AddMemberAsync(itemId, ownerId, tenantId, editorId, ItemSharePermission.Editor);

        var newPayload = RandomBytes(40);
        var ownerWrap = WrappedKey();
        var ownerEph = EphemeralKey();
        var editorWrap = WrappedKey();
        var editorEph = EphemeralKey();

        using (var ctx = CreateContext(Tenant(tenantId, ownerId)))
        {
            await new ItemMembershipService(ctx).RevokeAsync(itemId, ownerId, new RevokeItemMemberRequest(
                viewerId, newPayload,
                new[]
                {
                    new NewItemMembership(ownerId, ownerWrap, ownerEph),
                    new NewItemMembership(editorId, editorWrap, editorEph),
                }));
        }

        using var verify = CreateContext(SuperAdmin());
        var revoked = await verify.ItemMemberships.IgnoreQueryFilters().SingleAsync(m => m.VaultItemId == itemId && m.UserId == viewerId);
        Assert.NotNull(revoked.RevokedAt);

        var item = await verify.VaultItems.IgnoreQueryFilters().SingleAsync(i => i.Id == itemId);
        Assert.Equal(newPayload, item.EncryptedPayload);

        var ownerM = await verify.ItemMemberships.IgnoreQueryFilters().SingleAsync(m => m.VaultItemId == itemId && m.UserId == ownerId);
        Assert.Equal(ownerWrap, ownerM.WrappedItemKey);
        Assert.Equal(ownerEph, ownerM.EphemeralPublicKey);

        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.TenantId == tenantId && a.UserId == ownerId && a.Action == AuditAction.ItemMembershipRevoked));
    }

    [Fact]
    public async Task RevokeAsync_by_a_non_owner_throws_InsufficientVaultPermissionException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId);

        using var ctx = CreateContext(Tenant(tenantId, viewerId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            new ItemMembershipService(ctx).RevokeAsync(itemId, viewerId,
                new RevokeItemMemberRequest(ownerId, RandomBytes(32), Array.Empty<NewItemMembership>())));
    }

    [Fact]
    public async Task RevokeAsync_own_access_throws_InvalidOperationException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId);

        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new ItemMembershipService(ctx).RevokeAsync(itemId, ownerId,
                new RevokeItemMemberRequest(ownerId, RandomBytes(32),
                    new[] { new NewItemMembership(viewerId, WrappedKey(), EphemeralKey()) })));
    }

    [Fact]
    public async Task RevokeAsync_with_new_memberships_missing_a_remaining_member_throws_InvalidOperationException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        var editorId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await SetPublicKeyAsync(editorId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId);
        await AddMemberAsync(itemId, ownerId, tenantId, editorId, ItemSharePermission.Editor);

        // Remaining members are owner + editor, but only owner is provided.
        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new ItemMembershipService(ctx).RevokeAsync(itemId, ownerId, new RevokeItemMemberRequest(
                viewerId, RandomBytes(32), new[] { new NewItemMembership(ownerId, WrappedKey(), EphemeralKey()) })));
    }

    // ---- ListMembersAsync -------------------------------------------------------------------

    [Fact]
    public async Task ListMembersAsync_can_be_called_by_a_viewer_and_excludes_revoked()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId);

        using var ctx = CreateContext(Tenant(tenantId, viewerId));
        var members = await new ItemMembershipService(ctx).ListMembersAsync(itemId, viewerId);

        Assert.Equal(2, members.Count);
        Assert.Contains(members, m => m.UserId == ownerId && m.Permission == ItemSharePermission.Owner);
        Assert.Contains(members, m => m.UserId == viewerId && m.Permission == ItemSharePermission.Viewer);
    }

    [Fact]
    public async Task ListMembersAsync_for_a_non_member_throws_KeyNotFoundException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId);
        var strangerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());

        using var ctx = CreateContext(Tenant(tenantId, strangerId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new ItemMembershipService(ctx).ListMembersAsync(itemId, strangerId));
    }

    // ---- GetSharedWithMeAsync / GetSharedItemAsync / UpdateSharedItemAsync -------------------

    [Fact]
    public async Task GetSharedWithMeAsync_excludes_owner_rows_and_includes_viewer_editor_rows()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId);

        using var ctxOwner = CreateContext(Tenant(tenantId, ownerId));
        var ownerFeed = await new ItemMembershipService(ctxOwner).GetSharedWithMeAsync(ownerId);
        Assert.Empty(ownerFeed);

        using var ctxViewer = CreateContext(Tenant(tenantId, viewerId));
        var viewerFeed = await new ItemMembershipService(ctxViewer).GetSharedWithMeAsync(viewerId);
        Assert.Single(viewerFeed);
        Assert.Equal(itemId, viewerFeed[0].Id);
        Assert.Equal(ItemSharePermission.Viewer, viewerFeed[0].MyPermission);
        Assert.Equal(ownerId, viewerFeed[0].SharedByUserId);
    }

    [Fact]
    public async Task UpdateSharedItemAsync_by_a_Viewer_throws_InsufficientVaultPermissionException()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId);

        using var ctx = CreateContext(Tenant(tenantId, viewerId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            new ItemMembershipService(ctx).UpdateSharedItemAsync(itemId, viewerId, new UpdateSharedItemRequest(RandomBytes(32))));
    }

    [Fact]
    public async Task UpdateSharedItemAsync_by_an_Editor_succeeds()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);
        var editorId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(editorId, PublicKeyBytes());
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, editorId, ItemSharePermission.Editor);

        var newPayload = RandomBytes(32);
        using (var ctx = CreateContext(Tenant(tenantId, editorId)))
        {
            await new ItemMembershipService(ctx).UpdateSharedItemAsync(itemId, editorId, new UpdateSharedItemRequest(newPayload));
        }

        using var verify = CreateContext(SuperAdmin());
        var item = await verify.VaultItems.IgnoreQueryFilters().SingleAsync(i => i.Id == itemId);
        Assert.Equal(newPayload, item.EncryptedPayload);
    }

    // ---- Additive MySharedAccess on VaultItemService -----------------------------------------

    [Fact]
    public async Task VaultItemService_GetAsync_exposes_MySharedAccess_after_promotion()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, ownerId);

        using (var ctx = CreateContext(Tenant(tenantId, ownerId)))
        {
            var before = await new VaultItemService(ctx).GetAsync(vaultId, itemId, ownerId);
            Assert.Null(before.MySharedAccess);
        }

        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        var ownerWrap = WrappedKey();
        await ShareItemAsync(vaultId, itemId, ownerId, tenantId, viewerId, ownerWrappedItemKey: ownerWrap);

        using (var ctx = CreateContext(Tenant(tenantId, ownerId)))
        {
            var after = await new VaultItemService(ctx).GetAsync(vaultId, itemId, ownerId);
            Assert.NotNull(after.MySharedAccess);
            Assert.Equal(ItemSharePermission.Owner, after.MySharedAccess!.Permission);
            Assert.Equal(ownerWrap, after.MySharedAccess.WrappedItemKey);
        }
    }

    [Fact]
    public async Task VaultItemService_ListAsync_exposes_MySharedAccess_only_for_the_shared_item()
    {
        var (tenantId, ownerId, vaultId) = await ProvisionAsync();
        var sharedItemId = await CreateItemAsync(vaultId, ownerId);
        var plainItemId = await CreateItemAsync(vaultId, ownerId);
        var viewerId = await RegisterUserAsync(tenantId, ownerId, UniqueEmail());
        await SetPublicKeyAsync(viewerId, PublicKeyBytes());
        await ShareItemAsync(vaultId, sharedItemId, ownerId, tenantId, viewerId);

        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        var items = await new VaultItemService(ctx).ListAsync(vaultId, ownerId, new VaultItemListQuery());

        var shared = items.Single(i => i.Id == sharedItemId);
        var plain = items.Single(i => i.Id == plainItemId);
        Assert.NotNull(shared.MySharedAccess);
        Assert.Null(plain.MySharedAccess);
    }

    // ---- Helpers ------------------------------------------------------------------------------

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

    private async Task InviteMemberAsync(Guid vaultId, Guid callerId, Guid tenantId, Guid userId, VaultPermission permission)
    {
        using var ctx = CreateContext(Tenant(tenantId, callerId));
        await new VaultMembershipService(ctx).InviteAsync(vaultId, callerId, tenantId,
            new CreateMembershipRequest(userId, permission, WrappedKey(), EphemeralKey()));
    }

    private async Task<Guid> CreateItemAsync(Guid vaultId, Guid callerId)
    {
        using var ctx = CreateContext(await TenantContextForAsync(vaultId, callerId));
        var dto = await new VaultItemService(ctx)
            .CreateAsync(vaultId, callerId, new CreateVaultItemRequest(VaultItemType.Password, Payload));
        return dto.Id;
    }

    private async Task<ITenantContext> TenantContextForAsync(Guid vaultId, Guid callerId)
    {
        using var ctx = CreateContext(SuperAdmin());
        var vault = await ctx.Vaults.IgnoreQueryFilters().SingleAsync(v => v.Id == vaultId);
        return Tenant(vault.TenantId, callerId);
    }

    private async Task ShareItemAsync(
        Guid vaultId, Guid itemId, Guid ownerId, Guid tenantId, Guid recipientId,
        ItemSharePermission recipientPermission = ItemSharePermission.Viewer, byte[]? ownerWrappedItemKey = null)
    {
        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        await new ItemMembershipService(ctx).ShareAsync(vaultId, itemId, ownerId, tenantId,
            new ShareItemRequest(await EmailOfAsync(recipientId), recipientPermission,
                RandomBytes(32), ownerWrappedItemKey ?? WrappedKey(), EphemeralKey(), WrappedKey(), EphemeralKey()));
    }

    private async Task AddMemberAsync(Guid itemId, Guid ownerId, Guid tenantId, Guid recipientId, ItemSharePermission permission)
    {
        using var ctx = CreateContext(Tenant(tenantId, ownerId));
        await new ItemMembershipService(ctx).AddMemberAsync(itemId, ownerId, tenantId,
            new AddItemMemberRequest(await EmailOfAsync(recipientId), permission, WrappedKey(), EphemeralKey()));
    }

    private async Task<string> EmailOfAsync(Guid userId)
    {
        using var ctx = CreateContext(SuperAdmin());
        return (await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId)).Email;
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

    private static byte[] WrappedKey() => RandomBytes(48);

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
