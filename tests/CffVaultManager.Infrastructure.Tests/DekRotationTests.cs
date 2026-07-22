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
/// Coverage for <see cref="DekRotationService"/> (see docs/features/encryption-key-management.md
/// "Rotazione DEK"): re-encrypts every current personal-vault item under a fresh DEK without
/// touching the master password, excluding soft-deleted items, already-shared items (their own
/// dedicated key, see ItemMembership), and other users'/org vaults' items entirely.
/// </summary>
public sealed class DekRotationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;

    private static readonly X25519KeyExchangeService KeyExchange = new(new AesGcmCipherService());
    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);

    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    private static readonly byte[] Payload = { 9, 8, 7, 6 };

    public DekRotationTests()
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

    [Fact]
    public async Task RotateDekAsync_reencrypts_every_current_item_and_updates_EncryptedDek()
    {
        var (tenantId, userId, vaultId) = await ProvisionAsync();
        var item1 = await CreateItemAsync(vaultId, userId);
        var item2 = await CreateItemAsync(vaultId, userId);

        byte[] newEncryptedDek = RandomBytes(48);
        byte[] newPayload1 = RandomBytes(32);
        byte[] newPayload2 = RandomBytes(40);

        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await new DekRotationService(ctx).RotateDekAsync(userId, new RotateDekRequest(newEncryptedDek,
                new[]
                {
                    new ReencryptedItem(item1, newPayload1),
                    new ReencryptedItem(item2, newPayload2),
                }));
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        Assert.Equal(newEncryptedDek, user.EncryptedDek);

        var i1 = await verify.VaultItems.IgnoreQueryFilters().SingleAsync(i => i.Id == item1);
        var i2 = await verify.VaultItems.IgnoreQueryFilters().SingleAsync(i => i.Id == item2);
        Assert.Equal(newPayload1, i1.EncryptedPayload);
        Assert.Equal(newPayload2, i2.EncryptedPayload);

        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.TenantId == tenantId && a.UserId == userId && a.Action == AuditAction.DekRotated));
    }

    [Fact]
    public async Task RotateDekAsync_excludes_soft_deleted_items_from_the_required_set()
    {
        var (tenantId, userId, vaultId) = await ProvisionAsync();
        var liveItem = await CreateItemAsync(vaultId, userId);
        var deletedItem = await CreateItemAsync(vaultId, userId);

        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await new VaultItemService(ctx).SoftDeleteAsync(vaultId, deletedItem, userId);
        }

        // Only the live item needs re-encryption; omitting the soft-deleted one must succeed.
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await new DekRotationService(ctx).RotateDekAsync(userId, new RotateDekRequest(RandomBytes(48),
                new[] { new ReencryptedItem(liveItem, RandomBytes(32)) }));
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.UserId == userId && a.Action == AuditAction.DekRotated));
    }

    [Fact]
    public async Task RotateDekAsync_excludes_an_already_shared_item_from_the_required_set()
    {
        var (tenantId, userId, vaultId) = await ProvisionAsync();
        var plainItem = await CreateItemAsync(vaultId, userId);
        var sharedItem = await CreateItemAsync(vaultId, userId);

        var recipientId = await RegisterUserAsync(tenantId, userId, UniqueEmail());
        using (var ctx = CreateContext(SuperAdmin()))
        {
            var recipient = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == recipientId);
            recipient.PublicKey = RandomBytes(CryptoConstants.X25519KeyLengthBytes);
            await ctx.SaveChangesAsync();
        }

        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await new ItemMembershipService(ctx).ShareAsync(vaultId, sharedItem, userId, tenantId,
                new ShareItemRequest(await EmailOfAsync(recipientId), ItemSharePermission.Viewer,
                    RandomBytes(32), RandomBytes(48), RandomBytes(CryptoConstants.X25519KeyLengthBytes),
                    RandomBytes(48), RandomBytes(CryptoConstants.X25519KeyLengthBytes)));
        }

        // Only the still-plain item is in scope for personal-DEK rotation; the shared one uses its
        // own dedicated key now and must be omitted.
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await new DekRotationService(ctx).RotateDekAsync(userId, new RotateDekRequest(RandomBytes(48),
                new[] { new ReencryptedItem(plainItem, RandomBytes(32)) }));
        }

        using var verify = CreateContext(SuperAdmin());
        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.UserId == userId && a.Action == AuditAction.DekRotated));
    }

    [Fact]
    public async Task RotateDekAsync_with_a_missing_item_throws_InvalidOperationException()
    {
        var (tenantId, userId, vaultId) = await ProvisionAsync();
        await CreateItemAsync(vaultId, userId);
        await CreateItemAsync(vaultId, userId);

        using var ctx = CreateContext(Tenant(tenantId, userId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new DekRotationService(ctx).RotateDekAsync(userId, new RotateDekRequest(RandomBytes(48),
                Array.Empty<ReencryptedItem>())));
    }

    [Fact]
    public async Task RotateDekAsync_with_an_extra_unrelated_item_throws_InvalidOperationException()
    {
        var (tenantId, userId, vaultId) = await ProvisionAsync();
        var item = await CreateItemAsync(vaultId, userId);

        using var ctx = CreateContext(Tenant(tenantId, userId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new DekRotationService(ctx).RotateDekAsync(userId, new RotateDekRequest(RandomBytes(48),
                new[]
                {
                    new ReencryptedItem(item, RandomBytes(32)),
                    new ReencryptedItem(Guid.NewGuid(), RandomBytes(32)),
                })));
    }

    [Fact]
    public async Task RotateDekAsync_does_not_touch_another_users_items()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var otherUserId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var otherVaultId = await OwnedVaultIdAsync(otherUserId);
        var otherItem = await CreateItemAsync(otherVaultId, otherUserId);

        // Admin has no items of their own; rotating should require an empty set, and must never
        // touch the other user's item regardless.
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new DekRotationService(ctx).RotateDekAsync(adminId, new RotateDekRequest(RandomBytes(48), []));
        }

        using var verify = CreateContext(SuperAdmin());
        var otherItemAfter = await verify.VaultItems.IgnoreQueryFilters().SingleAsync(i => i.Id == otherItem);
        Assert.Equal(Payload, otherItemAfter.EncryptedPayload);
    }

    [Fact]
    public async Task RotateDekAsync_does_not_require_org_vault_items()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (wrapped, ephemeral) = RealWrappedDek();

        Guid orgVaultId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var dto = await new VaultService(ctx).CreateOrganizationVaultAsync(
                adminId, tenantId, new CreateOrganizationVaultRequest("Team", wrapped, ephemeral));
            orgVaultId = dto.Id;
        }

        await CreateItemAsync(orgVaultId, adminId);

        // Admin's own personal vault has no items; the org-vault item must not be required here.
        using var ctx2 = CreateContext(Tenant(tenantId, adminId));
        await new DekRotationService(ctx2).RotateDekAsync(adminId, new RotateDekRequest(RandomBytes(48), []));
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

    private async Task<Guid> OwnedVaultIdAsync(Guid userId)
    {
        using var ctx = CreateContext(SuperAdmin());
        return (await ctx.Vaults.IgnoreQueryFilters().SingleAsync(v => v.OwnerUserId == userId)).Id;
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

    private async Task<string> EmailOfAsync(Guid userId)
    {
        using var ctx = CreateContext(SuperAdmin());
        return (await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId)).Email;
    }

    private static (byte[] Wrapped, byte[] Ephemeral) RealWrappedDek()
    {
        var (publicKey, _) = KeyExchange.GenerateKeyPair();
        var dek = RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);
        var (ephemeral, wrapped) = KeyExchange.WrapKey(publicKey, dek);
        return (wrapped.ToBytes(), ephemeral);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

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
