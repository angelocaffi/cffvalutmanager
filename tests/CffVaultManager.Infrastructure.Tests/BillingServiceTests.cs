using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Crypto;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Billing;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Coverage of <see cref="BillingService"/> against an in-memory SQLite database — status,
/// checkout, capture (with idempotency), and tenant isolation on <see cref="PaymentTransaction"/>
/// (see docs/features/billing.md).
/// </summary>
public sealed class BillingServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;
    private static readonly IConfiguration EmptyConfig = new ConfigurationBuilder().Build();

    public BillingServiceTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            ctx.Database.EnsureCreated();
        }

        _authHashHasher = new ServerAuthHashHasher(new Argon2KeyDerivationService(), new Argon2Parameters(memoryKb: 1024, iterations: 1));
    }

    public void Dispose() => _connection.Dispose();

    [Fact]
    public async Task GetStatusAsync_returns_trial_state_for_a_freshly_provisioned_tenant()
    {
        var (tenantId, adminId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var status = await new BillingService(ctx, EmptyConfig).GetStatusAsync(tenantId);

        Assert.False(status.IsReadOnly);
        Assert.Null(status.PlanExpiresAt);
    }

    [Fact]
    public async Task GetStatusAsync_returns_read_only_once_the_trial_has_passed_with_no_payment()
    {
        var (tenantId, adminId) = await SeedExpiredTrialTenantAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var status = await new BillingService(ctx, EmptyConfig).GetStatusAsync(tenantId);

        Assert.True(status.IsReadOnly);
    }

    [Fact]
    public async Task CreateCheckoutAsync_persists_a_CreatedPaymentTransaction_and_returns_the_order_id()
    {
        var (tenantId, adminId) = await ProvisionAsync();
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-42" };

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var result = await new BillingService(ctx, EmptyConfig, payPal).CreateCheckoutAsync(tenantId, adminId);
            Assert.Equal("ORDER-42", result.OrderId);
        }

        using var verify = CreateContext(Tenant(tenantId, adminId));
        var transaction = await verify.PaymentTransactions.SingleAsync();
        Assert.Equal(PaymentTransactionStatus.Created, transaction.Status);
        Assert.Equal("ORDER-42", transaction.PayPalOrderId);
    }

    [Fact]
    public async Task CreateCheckoutAsync_withoutAConfiguredPayPalClient_throwsPayPalNotConfiguredException()
    {
        var (tenantId, adminId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<PayPalNotConfiguredException>(() =>
            new BillingService(ctx, EmptyConfig).CreateCheckoutAsync(tenantId, adminId));
    }

    [Fact]
    public async Task CaptureCheckoutAsync_onCompletedStatus_extendsThePlanAndMarksTheTransactionCaptured()
    {
        var (tenantId, adminId) = await SeedExpiredTrialTenantAsync();
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-1", NextCaptureStatus = "COMPLETED" };

        string orderId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            orderId = (await new BillingService(ctx, EmptyConfig, payPal).CreateCheckoutAsync(tenantId, adminId)).OrderId;
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var result = await new BillingService(ctx, EmptyConfig, payPal).CaptureCheckoutAsync(tenantId, adminId, orderId);
            Assert.True(result.Success);
            Assert.NotNull(result.PlanExpiresAt);
        }

        using var verify = CreateContext(Tenant(tenantId, adminId));
        var tenant = await verify.Tenants.SingleAsync(t => t.Id == tenantId);
        Assert.NotNull(tenant.PlanExpiresAt);
        Assert.False(tenant.IsReadOnly(DateTimeOffset.UtcNow));

        var transaction = await verify.PaymentTransactions.SingleAsync();
        Assert.Equal(PaymentTransactionStatus.Captured, transaction.Status);
        Assert.NotNull(transaction.CapturedAt);

        Assert.Single(verify.AuditLogEntries.Where(a => a.Action == AuditAction.PaymentCaptured));
    }

    [Fact]
    public async Task CaptureCheckoutAsync_calledTwice_isIdempotent_doesNotCallPayPalOrExtendThePlanTwice()
    {
        var (tenantId, adminId) = await SeedExpiredTrialTenantAsync();
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-1", NextCaptureStatus = "COMPLETED" };

        string orderId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            orderId = (await new BillingService(ctx, EmptyConfig, payPal).CreateCheckoutAsync(tenantId, adminId)).OrderId;
        }

        DateTimeOffset? firstExpiry;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            firstExpiry = (await new BillingService(ctx, EmptyConfig, payPal).CaptureCheckoutAsync(tenantId, adminId, orderId)).PlanExpiresAt;
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var second = await new BillingService(ctx, EmptyConfig, payPal).CaptureCheckoutAsync(tenantId, adminId, orderId);
            Assert.True(second.Success);
            Assert.Equal(firstExpiry, second.PlanExpiresAt);
        }

        Assert.Equal(1, payPal.CaptureOrderCallCount);
    }

    [Fact]
    public async Task CaptureCheckoutAsync_whenPayPalReportsANonCompletedStatus_marksFailed_andDoesNotExtendThePlan()
    {
        var (tenantId, adminId) = await SeedExpiredTrialTenantAsync();
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-1", NextCaptureStatus = "DECLINED" };

        string orderId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            orderId = (await new BillingService(ctx, EmptyConfig, payPal).CreateCheckoutAsync(tenantId, adminId)).OrderId;
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var result = await new BillingService(ctx, EmptyConfig, payPal).CaptureCheckoutAsync(tenantId, adminId, orderId);
            Assert.False(result.Success);
        }

        using var verify = CreateContext(Tenant(tenantId, adminId));
        Assert.Null((await verify.Tenants.SingleAsync(t => t.Id == tenantId)).PlanExpiresAt);
        Assert.Equal(PaymentTransactionStatus.Failed, (await verify.PaymentTransactions.SingleAsync()).Status);
    }

    [Fact]
    public async Task CaptureCheckoutAsync_forAnUnknownOrderId_throwsKeyNotFoundException()
    {
        var (tenantId, adminId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new BillingService(ctx, EmptyConfig, new FakePayPalClient()).CaptureCheckoutAsync(tenantId, adminId, "no-such-order"));
    }

    [Fact]
    public async Task CaptureCheckoutAsync_neverResolvesAnotherTenantsPaymentTransaction()
    {
        var (tenantA, adminA) = await ProvisionAsync();
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-A" };

        string orderId;
        using (var ctx = CreateContext(Tenant(tenantA, adminA)))
        {
            orderId = (await new BillingService(ctx, EmptyConfig, payPal).CreateCheckoutAsync(tenantA, adminA)).OrderId;
        }

        var (tenantB, adminB) = await ProvisionAsync("other", "admin@other.com");

        // Resolved as tenant B's own context, but the tenantId argument itself points at tenant A
        // — an IDOR attempt. The global query filter (tenant B) combined with the explicit
        // TenantId == tenantA predicate must together resolve to nothing.
        using var ctxB = CreateContext(Tenant(tenantB, adminB));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new BillingService(ctxB, EmptyConfig, payPal).CaptureCheckoutAsync(tenantA, adminB, orderId));
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private CffVaultManagerDbContext CreateContext(ITenantContext tenantContext)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlite(_connection)
            .Options;
        return new CffVaultManagerDbContext(options, tenantContext);
    }

    private async Task<(Guid TenantId, Guid AdminId)> ProvisionAsync(string slug = "acme", string email = "admin@x.com")
    {
        using var ctx = CreateContext(Unresolved());
        var service = new ProvisionTenantService(ctx, _authHashHasher);
        var result = await service.ProvisionAsync(new ProvisionTenantRequest(
            TenantName: slug,
            TenantSlug: slug,
            AdminEmail: email,
            AuthHash: RandomBytes(32),
            EncryptedDek: RandomBytes(4),
            MasterPasswordSalt: RandomBytes(16),
            KdfMemoryKb: 65536,
            KdfIterations: 3,
            KdfVersion: 1));
        return (result.TenantId, result.AdminUserId);
    }

    /// <summary>A tenant whose trial ended 1 day ago and which has never paid — i.e. currently read-only.</summary>
    private async Task<(Guid TenantId, Guid AdminId)> SeedExpiredTrialTenantAsync()
    {
        var (tenantId, adminId) = await ProvisionAsync($"expired-{Guid.NewGuid():N}", $"admin-{Guid.NewGuid():N}@x.com");

        using var ctx = CreateContext(Unresolved());
        var expired = DateTimeOffset.UtcNow.AddDays(-1);
        await ctx.Database.ExecuteSqlInterpolatedAsync($"UPDATE Tenants SET TrialEndsAt = {expired} WHERE Id = {tenantId}");
        return (tenantId, adminId);
    }

    private static byte[] RandomBytes(int length) => System.Security.Cryptography.RandomNumberGenerator.GetBytes(length);

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
