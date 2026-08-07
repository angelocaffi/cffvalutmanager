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
        var status = await new BillingService(ctx, EmptyConfig).GetStatusAsync(tenantId, adminId);

        Assert.False(status.IsReadOnly);
        Assert.Null(status.PlanExpiresAt);
    }

    [Fact]
    public async Task GetStatusAsync_returns_read_only_once_the_trial_has_passed_with_no_payment()
    {
        var (tenantId, adminId) = await SeedExpiredTrialTenantAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var status = await new BillingService(ctx, EmptyConfig).GetStatusAsync(tenantId, adminId);

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
    public async Task CreateCheckoutAsync_forTheConfiguredVipEmail_usesTheVipPriceInstead()
    {
        var (tenantId, adminId) = await ProvisionAsync("vip", "vip@x.com");
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-VIP" };
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Billing:VipEmail"] = "vip@x.com",
                ["Billing:VipAnnualPrice"] = "1.00",
            })
            .Build();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await new BillingService(ctx, config, payPal).CreateCheckoutAsync(tenantId, adminId);

        Assert.Equal(1.00m, (await ctx.PaymentTransactions.SingleAsync()).Amount);
        Assert.Equal(1.00m, payPal.LastCreateOrderAmount);
    }

    [Fact]
    public async Task CreateCheckoutAsync_forAnyOtherEmail_stillUsesTheDefaultPrice_evenWithVipConfigured()
    {
        var (tenantId, adminId) = await ProvisionAsync("notvip", "notvip@x.com");
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-DEFAULT" };
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Billing:AnnualPrice"] = "49.00",
                ["Billing:VipEmail"] = "vip@x.com",
                ["Billing:VipAnnualPrice"] = "1.00",
            })
            .Build();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await new BillingService(ctx, config, payPal).CreateCheckoutAsync(tenantId, adminId);

        Assert.Equal(49.00m, (await ctx.PaymentTransactions.SingleAsync()).Amount);
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

    [Fact]
    public async Task CreateCheckoutAsync_whenSuperAdminHasSetAStandardPrice_usesItInsteadOfTheConfigDefault()
    {
        var (tenantId, adminId) = await ProvisionAsync("standard-override", "std@x.com");
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-STD" };

        using (var ctx = CreateContext(Unresolved()))
        {
            ctx.Set<BillingPricing>().Add(new BillingPricing(59.00m, null, null, null, adminId));
            await ctx.SaveChangesAsync();
        }

        using var checkout = CreateContext(Tenant(tenantId, adminId));
        await new BillingService(checkout, EmptyConfig, payPal).CreateCheckoutAsync(tenantId, adminId);

        Assert.Equal(59.00m, (await checkout.PaymentTransactions.SingleAsync()).Amount);
    }

    [Fact]
    public async Task CreateCheckoutAsync_whenADiscountIsActive_usesTheDiscountedPrice()
    {
        var (tenantId, adminId) = await ProvisionAsync("discount-active", "disc@x.com");
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-DISC" };

        using (var ctx = CreateContext(Unresolved()))
        {
            ctx.Set<BillingPricing>().Add(new BillingPricing(59.00m, 29.00m, DateTimeOffset.UtcNow.AddDays(7), "Promo", adminId));
            await ctx.SaveChangesAsync();
        }

        using var checkout = CreateContext(Tenant(tenantId, adminId));
        await new BillingService(checkout, EmptyConfig, payPal).CreateCheckoutAsync(tenantId, adminId);

        Assert.Equal(29.00m, (await checkout.PaymentTransactions.SingleAsync()).Amount);
    }

    [Fact]
    public async Task CreateCheckoutAsync_whenTheDiscountHasExpired_fallsBackToTheStandardPrice()
    {
        var (tenantId, adminId) = await ProvisionAsync("discount-expired", "exp@x.com");
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-EXPIRED" };

        using (var ctx = CreateContext(Unresolved()))
        {
            ctx.Set<BillingPricing>().Add(new BillingPricing(59.00m, 29.00m, DateTimeOffset.UtcNow.AddDays(-1), "Promo scaduta", adminId, DateTimeOffset.UtcNow.AddDays(-8)));
            await ctx.SaveChangesAsync();
        }

        using var checkout = CreateContext(Tenant(tenantId, adminId));
        await new BillingService(checkout, EmptyConfig, payPal).CreateCheckoutAsync(tenantId, adminId);

        Assert.Equal(59.00m, (await checkout.PaymentTransactions.SingleAsync()).Amount);
    }

    [Fact]
    public async Task CreateCheckoutAsync_vipOverride_takesPrecedenceOverAnActiveDiscount()
    {
        var (tenantId, adminId) = await ProvisionAsync("vip-over-discount", "vip2@x.com");
        var payPal = new FakePayPalClient { NextOrderId = "ORDER-VIP2" };
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Billing:VipEmail"] = "vip2@x.com",
                ["Billing:VipAnnualPrice"] = "1.00",
            })
            .Build();

        using (var ctx = CreateContext(Unresolved()))
        {
            ctx.Set<BillingPricing>().Add(new BillingPricing(59.00m, 29.00m, DateTimeOffset.UtcNow.AddDays(7), null, adminId));
            await ctx.SaveChangesAsync();
        }

        using var checkout = CreateContext(Tenant(tenantId, adminId));
        await new BillingService(checkout, config, payPal).CreateCheckoutAsync(tenantId, adminId);

        Assert.Equal(1.00m, (await checkout.PaymentTransactions.SingleAsync()).Amount);
    }

    [Fact]
    public async Task GetStatusAsync_whenADiscountIsActive_exposesTheEffectivePriceAndPromoMessage()
    {
        var (tenantId, adminId) = await ProvisionAsync("status-promo", "promo@x.com");
        var expiry = DateTimeOffset.UtcNow.AddDays(7);

        using (var ctx = CreateContext(Unresolved()))
        {
            ctx.Set<BillingPricing>().Add(new BillingPricing(59.00m, 29.00m, expiry, "Sconto lancio", adminId));
            await ctx.SaveChangesAsync();
        }

        using var read = CreateContext(Tenant(tenantId, adminId));
        var status = await new BillingService(read, EmptyConfig).GetStatusAsync(tenantId, adminId);

        Assert.Equal(59.00m, status.StandardAnnualPrice);
        Assert.Equal(29.00m, status.EffectivePrice);
        Assert.Equal("Sconto lancio", status.PromoMessage);
        Assert.Equal(expiry, status.PromoExpiresAt);
    }

    [Fact]
    public async Task GetStatusAsync_whenNoDiscountIsActive_promoFieldsAreNull()
    {
        var (tenantId, adminId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var status = await new BillingService(ctx, EmptyConfig).GetStatusAsync(tenantId, adminId);

        Assert.Null(status.PromoMessage);
        Assert.Null(status.PromoExpiresAt);
        Assert.Equal(status.StandardAnnualPrice, status.EffectivePrice);
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
