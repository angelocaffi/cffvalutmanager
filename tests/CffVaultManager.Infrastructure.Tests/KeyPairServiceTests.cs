using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Crypto;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Coverage for <see cref="KeyPairService"/> — the prerequisite for any X25519-based sharing (see
/// docs/features/sharing-access-control.md): set-once semantics, since a second keypair would orphan
/// anything already wrapped for the first public key.
/// </summary>
public sealed class KeyPairServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;

    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);
    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    public KeyPairServiceTests()
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
    public async Task SetKeyPairAsync_stores_the_public_and_encrypted_private_key()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        byte[] publicKey = RandomBytes(32);
        byte[] encryptedPrivateKey = RandomBytes(64);

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new KeyPairService(ctx).SetKeyPairAsync(adminId, publicKey, encryptedPrivateKey);
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == adminId);
        Assert.Equal(publicKey, user.PublicKey);
        Assert.Equal(encryptedPrivateKey, user.EncryptedPrivateKey);
    }

    [Fact]
    public async Task GetOwnKeyPairAsync_before_any_keypair_is_set_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => new KeyPairService(ctx).GetOwnKeyPairAsync(adminId));
    }

    [Fact]
    public async Task GetOwnKeyPairAsync_returns_what_was_set()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        byte[] publicKey = RandomBytes(32);
        byte[] encryptedPrivateKey = RandomBytes(64);

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new KeyPairService(ctx).SetKeyPairAsync(adminId, publicKey, encryptedPrivateKey);
        }

        using var ctx2 = CreateContext(Tenant(tenantId, adminId));
        var dto = await new KeyPairService(ctx2).GetOwnKeyPairAsync(adminId);
        Assert.Equal(publicKey, dto.PublicKey);
        Assert.Equal(encryptedPrivateKey, dto.EncryptedPrivateKey);
    }

    [Fact]
    public async Task SetKeyPairAsync_a_second_time_throws_InvalidOperationException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new KeyPairService(ctx).SetKeyPairAsync(adminId, RandomBytes(32), RandomBytes(64));
        }

        using var ctx2 = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new KeyPairService(ctx2).SetKeyPairAsync(adminId, RandomBytes(32), RandomBytes(64)));
    }

    [Fact]
    public async Task GetOwnProfileAsync_reports_HasKeyPair_correctly_before_and_after_setting()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var before = await new UserProfileService(ctx).GetOwnProfileAsync(adminId);
            Assert.False(before.HasKeyPair);
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new KeyPairService(ctx).SetKeyPairAsync(adminId, RandomBytes(32), RandomBytes(64));
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var after = await new UserProfileService(ctx).GetOwnProfileAsync(adminId);
            Assert.True(after.HasKeyPair);
        }
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

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

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
