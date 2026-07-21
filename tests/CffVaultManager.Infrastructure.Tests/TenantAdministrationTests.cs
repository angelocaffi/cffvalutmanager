using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Crypto;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Administration;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Coverage for <see cref="TenantAdministrationService"/>'s suspend/reactivate operations against
/// an in-memory SQLite database. Login/refresh enforcement of a suspended tenant is covered in
/// <see cref="AuthenticationTests"/> (that's where <see cref="IAuthenticationService"/> lives).
/// </summary>
public sealed class TenantAdministrationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;

    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);

    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    public TenantAdministrationTests()
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
    public async Task SuspendTenantAsync_sets_status_and_writes_audit()
    {
        var (tenantId, _) = await ProvisionAsync();
        var superAdminId = await SeedSuperAdminAsync();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            var service = new TenantAdministrationService(ctx);
            await service.SuspendTenantAsync(tenantId, superAdminId);
        }

        using var verify = CreateContext(SuperAdmin());
        var tenant = await verify.Tenants.IgnoreQueryFilters().SingleAsync(t => t.Id == tenantId);
        Assert.Equal(TenantStatus.Suspended, tenant.Status);

        var audit = await verify.AuditLogEntries.IgnoreQueryFilters()
            .SingleAsync(a => a.TenantId == tenantId && a.Action == AuditAction.TenantSuspended);
        Assert.Equal(superAdminId, audit.UserId);
    }

    [Fact]
    public async Task SuspendTenantAsync_for_nonexistent_tenant_throws_KeyNotFoundException()
    {
        using var ctx = CreateContext(SuperAdmin());
        var service = new TenantAdministrationService(ctx);

        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            service.SuspendTenantAsync(Guid.NewGuid(), Guid.NewGuid()));
    }

    [Fact]
    public async Task ReactivateTenantAsync_sets_status_back_to_active_and_writes_audit()
    {
        var (tenantId, _) = await ProvisionAsync();
        var superAdminId = await SeedSuperAdminAsync();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            var service = new TenantAdministrationService(ctx);
            await service.SuspendTenantAsync(tenantId, superAdminId);
            await service.ReactivateTenantAsync(tenantId, superAdminId);
        }

        using var verify = CreateContext(SuperAdmin());
        var tenant = await verify.Tenants.IgnoreQueryFilters().SingleAsync(t => t.Id == tenantId);
        Assert.Equal(TenantStatus.Active, tenant.Status);

        var audit = await verify.AuditLogEntries.IgnoreQueryFilters()
            .SingleAsync(a => a.TenantId == tenantId && a.Action == AuditAction.TenantReactivated);
        Assert.Equal(superAdminId, audit.UserId);
    }

    [Fact]
    public async Task ReactivateTenantAsync_for_nonexistent_tenant_throws_KeyNotFoundException()
    {
        using var ctx = CreateContext(SuperAdmin());
        var service = new TenantAdministrationService(ctx);

        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            service.ReactivateTenantAsync(Guid.NewGuid(), Guid.NewGuid()));
    }

    [Fact]
    public async Task GetAllTenantsAsync_reflects_suspended_status()
    {
        var (tenantId, _) = await ProvisionAsync();
        var superAdminId = await SeedSuperAdminAsync();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            await new TenantAdministrationService(ctx).SuspendTenantAsync(tenantId, superAdminId);
        }

        using var readCtx = CreateContext(SuperAdmin());
        var tenants = await new TenantAdministrationService(readCtx).GetAllTenantsAsync();

        var summary = Assert.Single(tenants, t => t.Id == tenantId);
        Assert.Equal(TenantStatus.Suspended, summary.Status);
    }

    // ---- Helpers -----------------------------------------------------------------------------

    private CffVaultManagerDbContext CreateContext(ITenantContext tenantContext)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlite(_connection)
            .Options;
        return new CffVaultManagerDbContext(options, tenantContext);
    }

    private async Task<(Guid TenantId, Guid AdminId)> ProvisionAsync()
    {
        using var ctx = CreateContext(Unresolved());
        var service = new ProvisionTenantService(ctx, _authHashHasher);
        var result = await service.ProvisionAsync(NewProvisionRequest());
        return (result.TenantId, result.AdminUserId);
    }

    // AuditLogEntry.UserId has a real FK to Users, so the caller performing an admin action must
    // exist as an actual User row — a bare Guid.NewGuid() would violate that constraint.
    private async Task<Guid> SeedSuperAdminAsync()
    {
        using var ctx = CreateContext(SuperAdmin());
        var user = User.CreateSuperAdmin(Guid.NewGuid(), $"superadmin-{Guid.NewGuid()}@platform.test", encryptedDek: Dek);
        ctx.Users.Add(user);
        await ctx.SaveChangesAsync();
        return user.Id;
    }

    private static ProvisionTenantRequest NewProvisionRequest() => new(
        TenantName: "Acme",
        TenantSlug: "acme",
        AdminEmail: "admin@x.com",
        AuthHash: RandomAuthHash(),
        EncryptedDek: Dek,
        MasterPasswordSalt: Salt,
        KdfMemoryKb: 65536,
        KdfIterations: 3,
        KdfVersion: 1);

    private static byte[] RandomAuthHash() => System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

    private static ITenantContext Unresolved() => new TenantContext();

    private static ITenantContext SuperAdmin()
    {
        var c = new TenantContext();
        c.SetSuperAdmin(Guid.NewGuid());
        return c;
    }
}
