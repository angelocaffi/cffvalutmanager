using CffVaultManager.Application.Dtos.Billing;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// SuperAdmin-only platform pricing administration (see docs/features/billing.md "Prezzo
/// modificabile da SuperAdmin") — separate from <see cref="IBillingService"/>, which is the
/// tenant-facing checkout surface. Pricing is platform config, not tenant data, same trust class
/// as <see cref="ITenantAdministrationService"/>'s metadata-only surface.
/// </summary>
public interface IBillingPricingAdminService
{
    /// <summary>
    /// Current pricing. If a SuperAdmin has never set anything, returns the server-configured
    /// default (<c>Billing:AnnualPrice</c>) with no discount and <c>UpdatedAt = null</c> — same
    /// value <see cref="IBillingService"/> would charge a non-VIP caller today.
    /// </summary>
    Task<BillingPricingDto> GetAsync(CancellationToken ct = default);

    /// <summary>
    /// Creates or updates the single platform pricing row. Throws <see cref="ArgumentException"/>
    /// on invalid input (non-positive price, discount/expiry not set as a pair, discount not lower
    /// than standard, expiry in the past, promo message too long — see <c>BillingPricing.Update</c>).
    /// </summary>
    Task<BillingPricingDto> UpdateAsync(
        decimal standardAnnualPrice,
        decimal? discountedAnnualPrice,
        DateTimeOffset? discountExpiresAt,
        string? promoMessage,
        Guid updatedByUserId,
        CancellationToken ct = default);
}
