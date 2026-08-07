using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Billing;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace CffVaultManager.Infrastructure.Billing;

/// <summary>SuperAdmin-only pricing administration — see <see cref="IBillingPricingAdminService"/> and docs/features/billing.md.</summary>
internal sealed class BillingPricingAdminService : IBillingPricingAdminService
{
    private readonly CffVaultManagerDbContext _db;
    private readonly decimal _defaultAnnualPrice;
    private readonly string _currency;

    public BillingPricingAdminService(CffVaultManagerDbContext db, IConfiguration configuration)
    {
        _db = db;
        _defaultAnnualPrice = configuration.GetValue<decimal?>("Billing:AnnualPrice") ?? 49.00m;
        _currency = configuration["Billing:Currency"] ?? "EUR";
    }

    public async Task<BillingPricingDto> GetAsync(CancellationToken ct = default)
    {
        var pricing = await _db.BillingPricing.FirstOrDefaultAsync(p => p.Id == BillingPricing.SingletonId, ct);
        return ToDto(pricing);
    }

    public async Task<BillingPricingDto> UpdateAsync(
        decimal standardAnnualPrice,
        decimal? discountedAnnualPrice,
        DateTimeOffset? discountExpiresAt,
        string? promoMessage,
        Guid updatedByUserId,
        CancellationToken ct = default)
    {
        var pricing = await _db.BillingPricing.FirstOrDefaultAsync(p => p.Id == BillingPricing.SingletonId, ct);
        if (pricing is null)
        {
            pricing = new BillingPricing(standardAnnualPrice, discountedAnnualPrice, discountExpiresAt, promoMessage, updatedByUserId);
            _db.BillingPricing.Add(pricing);
        }
        else
        {
            pricing.Update(standardAnnualPrice, discountedAnnualPrice, discountExpiresAt, promoMessage, updatedByUserId);
        }

        // Platform-wide event, not tied to any one tenant — TenantId is null by design for
        // SuperAdmin actions that aren't about a specific tenant, see AuditLogEntry.
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), null, updatedByUserId, AuditAction.BillingPricingUpdated));

        await _db.SaveChangesAsync(ct);
        return ToDto(pricing);
    }

    private BillingPricingDto ToDto(BillingPricing? pricing)
    {
        var now = DateTimeOffset.UtcNow;
        if (pricing is null)
        {
            return new BillingPricingDto(_defaultAnnualPrice, null, null, null, _currency, false, null);
        }

        return new BillingPricingDto(
            pricing.StandardAnnualPrice,
            pricing.DiscountedAnnualPrice,
            pricing.DiscountExpiresAt,
            pricing.PromoMessage,
            _currency,
            pricing.IsDiscountActive(now),
            pricing.UpdatedAt);
    }
}
