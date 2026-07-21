using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Crypto;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using CffVaultManager.Infrastructure.VaultCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// End-to-end coverage of the vault-core services (vaults, folders, tags, items, trash) against an
/// in-memory SQLite database. Provisioning/registration are exercised through the real services so
/// the auto-created personal vault is genuine, and ownership isolation is asserted as
/// <see cref="KeyNotFoundException"/> (never <see cref="UnauthorizedAccessException"/>).
/// </summary>
public sealed class VaultCoreTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;

    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);

    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    private static readonly byte[] Payload = { 9, 8, 7, 6 };

    public VaultCoreTests()
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

    // ---- Provisioning / registration create personal vaults ---------------------------------

    [Fact]
    public async Task Provisioning_creates_a_personal_vault_owned_by_the_new_admin()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var verify = CreateContext(SuperAdmin());
        var vault = await verify.Vaults.IgnoreQueryFilters().SingleAsync(v => v.Id == vaultId);
        Assert.Equal(tenantId, vault.TenantId);
        Assert.Equal(adminId, vault.OwnerUserId);
        Assert.False(vault.IsOrganizationVault);
        Assert.Equal("Personale", vault.Name);
    }

    [Fact]
    public async Task Registering_a_user_creates_a_personal_vault_owned_by_them()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var userId = await RegisterUserAsync(tenantId, adminId, "operator@x.com");

        using var verify = CreateContext(SuperAdmin());
        var vault = await verify.Vaults.IgnoreQueryFilters().SingleAsync(v => v.OwnerUserId == userId);
        Assert.Equal(tenantId, vault.TenantId);
        Assert.False(vault.IsOrganizationVault);
        Assert.Equal("Personale", vault.Name);
    }

    [Fact]
    public async Task ListOwnedVaultsAsync_returns_only_the_callers_own_personal_vault()
    {
        var (tenantId, adminId, adminVaultId) = await ProvisionAsync();
        var userId = await RegisterUserAsync(tenantId, adminId, "operator@x.com");

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new VaultService(ctx);
        var vaults = await service.ListOwnedVaultsAsync(adminId);

        Assert.Single(vaults);
        Assert.Equal(adminVaultId, vaults[0].Id);
        Assert.DoesNotContain(vaults, v => v.Id != adminVaultId);
        _ = userId;
    }

    // ---- Folders -----------------------------------------------------------------------------

    [Fact]
    public async Task Folder_create_then_list_then_rename_works()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new FolderService(ctx);

        var created = await service.CreateAsync(vaultId, adminId, new CreateFolderRequest("Work"));
        Assert.Equal("Work", created.Name);

        var list = await service.ListAsync(vaultId, adminId);
        Assert.Single(list);
        Assert.Equal(created.Id, list[0].Id);

        var renamed = await service.RenameAsync(vaultId, created.Id, adminId, new RenameFolderRequest("Personal"));
        Assert.Equal("Personal", renamed.Name);
    }

    [Fact]
    public async Task Folder_create_with_duplicate_name_in_same_vault_throws_InvalidOperationException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new FolderService(ctx);

        await service.CreateAsync(vaultId, adminId, new CreateFolderRequest("Work"));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.CreateAsync(vaultId, adminId, new CreateFolderRequest("Work")));
    }

    [Fact]
    public async Task Folder_delete_sets_FolderId_null_on_its_items_instead_of_deleting_them()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        Guid folderId;
        Guid itemId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var folders = new FolderService(ctx);
            folderId = (await folders.CreateAsync(vaultId, adminId, new CreateFolderRequest("Work"))).Id;

            var items = new VaultItemService(ctx);
            itemId = (await items.CreateAsync(vaultId, adminId,
                new CreateVaultItemRequest(VaultItemType.Password, Payload, folderId))).Id;

            await folders.DeleteAsync(vaultId, folderId, adminId);
        }

        using var verify = CreateContext(Tenant(tenantId, adminId));
        Assert.False(await verify.Folders.AnyAsync(f => f.Id == folderId));
        var item = await verify.VaultItems.SingleAsync(i => i.Id == itemId);
        Assert.Null(item.FolderId);
    }

    // ---- Tags --------------------------------------------------------------------------------

    [Fact]
    public async Task Tag_create_then_list_then_rename_works()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new TagService(ctx);

        var created = await service.CreateAsync(vaultId, adminId, new CreateTagRequest("email"));
        var list = await service.ListAsync(vaultId, adminId);
        Assert.Single(list);

        var renamed = await service.RenameAsync(vaultId, created.Id, adminId, new RenameTagRequest("mail"));
        Assert.Equal("mail", renamed.Name);
    }

    [Fact]
    public async Task Tag_create_with_duplicate_name_in_same_vault_throws_InvalidOperationException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new TagService(ctx);

        await service.CreateAsync(vaultId, adminId, new CreateTagRequest("email"));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.CreateAsync(vaultId, adminId, new CreateTagRequest("email")));
    }

    [Fact]
    public async Task Tag_assign_to_item_then_remove_works_and_is_idempotent()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var tags = new TagService(ctx);
        var items = new VaultItemService(ctx);

        var tagId = (await tags.CreateAsync(vaultId, adminId, new CreateTagRequest("email"))).Id;
        var itemId = (await items.CreateAsync(vaultId, adminId,
            new CreateVaultItemRequest(VaultItemType.Password, Payload))).Id;

        await items.AssignTagAsync(vaultId, itemId, tagId, adminId);
        // Idempotent: assigning again is a no-op, not a duplicate-key failure.
        await items.AssignTagAsync(vaultId, itemId, tagId, adminId);
        Assert.Equal(1, await ctx.VaultItemTags.CountAsync(t => t.VaultItemId == itemId && t.TagId == tagId));

        var fetched = await items.GetAsync(vaultId, itemId, adminId);
        Assert.Contains(tagId, fetched.TagIds);

        await items.RemoveTagAsync(vaultId, itemId, tagId, adminId);
        // Idempotent: removing again is a no-op.
        await items.RemoveTagAsync(vaultId, itemId, tagId, adminId);
        Assert.Equal(0, await ctx.VaultItemTags.CountAsync(t => t.VaultItemId == itemId && t.TagId == tagId));
    }

    // ---- Vault items -------------------------------------------------------------------------

    [Fact]
    public async Task VaultItem_create_then_appears_in_default_list_with_default_sort()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var items = new VaultItemService(ctx);

        var first = await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload));
        var second = await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.SecureNote, Payload));

        var list = await items.ListAsync(vaultId, adminId, new VaultItemListQuery());
        Assert.Equal(2, list.Count);
        // Default sort is UpdatedAt descending: the most recently created comes first.
        Assert.Equal(second.Id, list[0].Id);
        Assert.Equal(first.Id, list[1].Id);
    }

    [Fact]
    public async Task VaultItem_list_filters_by_folder_tag_type_and_favorite()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var folders = new FolderService(ctx);
        var tags = new TagService(ctx);
        var items = new VaultItemService(ctx);

        var folderId = (await folders.CreateAsync(vaultId, adminId, new CreateFolderRequest("Work"))).Id;
        var tagId = (await tags.CreateAsync(vaultId, adminId, new CreateTagRequest("email"))).Id;

        var inFolder = (await items.CreateAsync(vaultId, adminId,
            new CreateVaultItemRequest(VaultItemType.Password, Payload, folderId))).Id;
        var favoriteNote = (await items.CreateAsync(vaultId, adminId,
            new CreateVaultItemRequest(VaultItemType.SecureNote, Payload, FolderId: null, IsFavorite: true))).Id;
        var plainCard = (await items.CreateAsync(vaultId, adminId,
            new CreateVaultItemRequest(VaultItemType.CreditCard, Payload))).Id;
        await items.AssignTagAsync(vaultId, inFolder, tagId, adminId);

        var byFolder = await items.ListAsync(vaultId, adminId, new VaultItemListQuery(FolderId: folderId));
        Assert.Equal(new[] { inFolder }, byFolder.Select(i => i.Id).ToArray());

        var byTag = await items.ListAsync(vaultId, adminId, new VaultItemListQuery(TagId: tagId));
        Assert.Equal(new[] { inFolder }, byTag.Select(i => i.Id).ToArray());

        var byType = await items.ListAsync(vaultId, adminId, new VaultItemListQuery(Type: VaultItemType.CreditCard));
        Assert.Equal(new[] { plainCard }, byType.Select(i => i.Id).ToArray());

        var byFavorite = await items.ListAsync(vaultId, adminId, new VaultItemListQuery(Favorite: true));
        Assert.Equal(new[] { favoriteNote }, byFavorite.Select(i => i.Id).ToArray());
    }

    [Fact]
    public async Task VaultItem_SoftDeleteAsync_hides_item_from_default_list()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var items = new VaultItemService(ctx);

        var itemId = (await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload))).Id;
        await items.SoftDeleteAsync(vaultId, itemId, adminId);

        var list = await items.ListAsync(vaultId, adminId, new VaultItemListQuery());
        Assert.Empty(list);
    }

    [Fact]
    public async Task VaultItem_SoftDeleteAsync_makes_item_appear_in_ListTrashAsync()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var items = new VaultItemService(ctx);

        var itemId = (await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload))).Id;
        await items.SoftDeleteAsync(vaultId, itemId, adminId);

        var trash = await items.ListTrashAsync(vaultId, adminId);
        Assert.Single(trash);
        Assert.Equal(itemId, trash[0].Id);
        Assert.True(trash[0].IsDeleted);
        Assert.NotNull(trash[0].DeletedAt);
    }

    [Fact]
    public async Task VaultItem_SoftDeleteAsync_twice_throws_InvalidOperationException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var items = new VaultItemService(ctx);

        var itemId = (await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload))).Id;
        await items.SoftDeleteAsync(vaultId, itemId, adminId);

        await Assert.ThrowsAsync<InvalidOperationException>(() => items.SoftDeleteAsync(vaultId, itemId, adminId));
    }

    [Fact]
    public async Task VaultItem_RestoreAsync_brings_item_back_to_default_list()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var items = new VaultItemService(ctx);

        var itemId = (await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload))).Id;
        await items.SoftDeleteAsync(vaultId, itemId, adminId);
        await items.RestoreAsync(vaultId, itemId, adminId);

        var list = await items.ListAsync(vaultId, adminId, new VaultItemListQuery());
        Assert.Single(list);
        Assert.Equal(itemId, list[0].Id);
        Assert.Empty(await items.ListTrashAsync(vaultId, adminId));
    }

    [Fact]
    public async Task VaultItem_RestoreAsync_without_prior_delete_throws_InvalidOperationException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var items = new VaultItemService(ctx);

        var itemId = (await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload))).Id;
        await Assert.ThrowsAsync<InvalidOperationException>(() => items.RestoreAsync(vaultId, itemId, adminId));
    }

    [Fact]
    public async Task VaultItem_UpdateAsync_on_a_deleted_item_throws_InvalidOperationException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var items = new VaultItemService(ctx);

        var itemId = (await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload))).Id;
        await items.SoftDeleteAsync(vaultId, itemId, adminId);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            items.UpdateAsync(vaultId, itemId, adminId,
                new UpdateVaultItemRequest(VaultItemType.Password, Payload, FolderId: null, IsFavorite: true)));
    }

    [Fact]
    public async Task VaultItem_PermanentlyDeleteAsync_removes_the_row_from_the_database()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        Guid itemId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var items = new VaultItemService(ctx);
            itemId = (await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload))).Id;
            await items.SoftDeleteAsync(vaultId, itemId, adminId);
            await items.PermanentlyDeleteAsync(vaultId, itemId, adminId);
        }

        using var verify = CreateContext(SuperAdmin());
        Assert.False(await verify.VaultItems.IgnoreQueryFilters().AnyAsync(i => i.Id == itemId));
    }

    [Fact]
    public async Task VaultItem_PermanentlyDeleteAsync_without_prior_soft_delete_throws_InvalidOperationException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var items = new VaultItemService(ctx);

        var itemId = (await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload))).Id;
        await Assert.ThrowsAsync<InvalidOperationException>(() => items.PermanentlyDeleteAsync(vaultId, itemId, adminId));
    }

    [Fact]
    public async Task VaultItem_GetAsync_updates_LastAccessedAt()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var items = new VaultItemService(ctx);

        var created = await items.CreateAsync(vaultId, adminId, new CreateVaultItemRequest(VaultItemType.Password, Payload));
        Assert.Null(created.LastAccessedAt);

        var fetched = await items.GetAsync(vaultId, created.Id, adminId);
        Assert.NotNull(fetched.LastAccessedAt);
    }

    // ---- Ownership / scope isolation ---------------------------------------------------------

    [Fact]
    public async Task User_cannot_access_another_users_vault_folders_tags_or_items()
    {
        var (tenantId, adminId, adminVaultId) = await ProvisionAsync();
        var otherId = await RegisterUserAsync(tenantId, adminId, "operator@x.com");

        // The other user is a legitimate member of the same tenant, but not the owner of adminVaultId.
        using var ctx = CreateContext(Tenant(tenantId, otherId));
        var folders = new FolderService(ctx);
        var tags = new TagService(ctx);
        var items = new VaultItemService(ctx);

        await Assert.ThrowsAsync<KeyNotFoundException>(() => folders.ListAsync(adminVaultId, otherId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => tags.ListAsync(adminVaultId, otherId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            items.ListAsync(adminVaultId, otherId, new VaultItemListQuery()));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            folders.CreateAsync(adminVaultId, otherId, new CreateFolderRequest("X")));
    }

    [Fact]
    public async Task Operations_on_an_organization_vault_are_rejected_as_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();

        var orgVaultId = Guid.NewGuid();
        using (var seed = CreateContext(SuperAdmin()))
        {
            seed.Vaults.Add(new Vault(orgVaultId, tenantId, "Org", isOrganizationVault: true, ownerUserId: null));
            await seed.SaveChangesAsync();
        }

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var folders = new FolderService(ctx);
        var items = new VaultItemService(ctx);

        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            VaultAccessGuard.GetOwnedPersonalVaultAsync(ctx, orgVaultId, adminId, default));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => folders.ListAsync(orgVaultId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            items.ListAsync(orgVaultId, adminId, new VaultItemListQuery()));
    }

    // ---- Helpers -----------------------------------------------------------------------------

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

    private static byte[] RandomAuthHash() => System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

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
