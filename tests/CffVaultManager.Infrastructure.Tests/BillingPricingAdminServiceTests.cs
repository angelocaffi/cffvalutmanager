using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Billing;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>Coverage of <see cref="BillingPricingAdminService"/> against an in-memory SQLite database (see docs/features/billing.md "Prezzo modificabile da SuperAdmin").</summary>
public sealed class BillingPricingAdminServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private static readonly IConfiguration EmptyConfig = new ConfigurationBuilder().Build();

    public BillingPricingAdminServiceTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using var ctx = CreateContext();
        ctx.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    [Fact]
    public async Task GetAsync_whenNoRowExists_returnsServerConfiguredDefault_withNoDiscount()
    {
        using var ctx = CreateContext();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Billing:AnnualPrice"] = "49.00", ["Billing:Currency"] = "EUR" })
            .Build();

        var pricing = await new BillingPricingAdminService(ctx, config).GetAsync();

        Assert.Equal(49.00m, pricing.StandardAnnualPrice);
        Assert.Null(pricing.DiscountedAnnualPrice);
        Assert.False(pricing.IsDiscountActive);
        Assert.Null(pricing.UpdatedAt);
        Assert.Equal("EUR", pricing.Currency);
    }

    [Fact]
    public async Task UpdateAsync_firstCall_createsTheRow_andReturnsIt()
    {
        using var ctx = CreateContext();
        var adminId = await SeedSuperAdminAsync(ctx);

        var result = await new BillingPricingAdminService(ctx, EmptyConfig)
            .UpdateAsync(59.00m, 39.00m, DateTimeOffset.UtcNow.AddDays(7), "Promo", adminId);

        Assert.Equal(59.00m, result.StandardAnnualPrice);
        Assert.Equal(39.00m, result.DiscountedAnnualPrice);
        Assert.True(result.IsDiscountActive);
        Assert.NotNull(result.UpdatedAt);

        Assert.Equal(1, await ctx.Set<BillingPricing>().CountAsync());
    }

    [Fact]
    public async Task UpdateAsync_secondCall_updatesTheSameRow_doesNotDuplicate()
    {
        using var ctx = CreateContext();
        var adminId = await SeedSuperAdminAsync(ctx);
        var service = new BillingPricingAdminService(ctx, EmptyConfig);

        await service.UpdateAsync(59.00m, null, null, null, adminId);
        var second = await service.UpdateAsync(69.00m, null, null, null, adminId);

        Assert.Equal(69.00m, second.StandardAnnualPrice);
        Assert.Equal(1, await ctx.Set<BillingPricing>().CountAsync());
    }

    [Fact]
    public async Task UpdateAsync_writesAnAuditLogEntry_withNoTenantId()
    {
        using var ctx = CreateContext();
        var adminId = await SeedSuperAdminAsync(ctx);

        await new BillingPricingAdminService(ctx, EmptyConfig).UpdateAsync(59.00m, null, null, null, adminId);

        var entry = await ctx.AuditLogEntries.SingleAsync(a => a.Action == AuditAction.BillingPricingUpdated);
        Assert.Null(entry.TenantId);
        Assert.Equal(adminId, entry.UserId);
    }

    [Fact]
    public async Task UpdateAsync_invalidInput_propagatesTheEntitysArgumentException()
    {
        using var ctx = CreateContext();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new BillingPricingAdminService(ctx, EmptyConfig).UpdateAsync(0m, null, null, null, Guid.NewGuid()));
    }

    /// <summary>BillingPricing.UpdatedByUserId is a real FK to Users — seed a row so SaveChangesAsync doesn't fail on SQLite.</summary>
    private static async Task<Guid> SeedSuperAdminAsync(CffVaultManagerDbContext ctx)
    {
        var user = User.CreateSuperAdmin(Guid.NewGuid(), $"admin-{Guid.NewGuid():N}@x.com", encryptedDek: [1, 2, 3]);
        ctx.Users.Add(user);
        await ctx.SaveChangesAsync();
        return user.Id;
    }

    private CffVaultManagerDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>().UseSqlite(_connection).Options;
        var tenantContext = new TenantContext();
        tenantContext.SetSuperAdmin(Guid.NewGuid());
        return new CffVaultManagerDbContext(options, tenantContext);
    }
}
