namespace CffVaultManager.Domain.Entities;

/// <summary>
/// Platform-wide, SuperAdmin-editable override of the annual subscription price (see
/// docs/features/billing.md "Prezzo modificabile da SuperAdmin"). Exactly one row ever exists,
/// identified by <see cref="SingletonId"/> — pricing is a platform concern, not a per-tenant one,
/// same reasoning as <c>TenantProvisioningRequest</c> being outside the tenant query filter.
/// When no row exists yet (fresh install, SuperAdmin never touched pricing), <c>BillingService</c>
/// falls back to the <c>Billing:AnnualPrice</c> configuration value exactly as before this feature
/// existed — nothing breaks for an install that never opts in.
/// </summary>
public class BillingPricing
{
    public static readonly Guid SingletonId = new("00000000-0000-0000-0000-0000000000b1");

    private BillingPricing()
    {
        // Parameterless constructor for EF Core / serialization.
    }

    public BillingPricing(
        decimal standardAnnualPrice,
        decimal? discountedAnnualPrice,
        DateTimeOffset? discountExpiresAt,
        string? promoMessage,
        Guid updatedByUserId,
        DateTimeOffset? now = null)
    {
        Id = SingletonId;
        Apply(standardAnnualPrice, discountedAnnualPrice, discountExpiresAt, promoMessage, updatedByUserId, now);
    }

    public Guid Id { get; private set; }

    public decimal StandardAnnualPrice { get; private set; }

    public decimal? DiscountedAnnualPrice { get; private set; }

    public DateTimeOffset? DiscountExpiresAt { get; private set; }

    public string? PromoMessage { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }

    public Guid UpdatedByUserId { get; private set; }

    /// <summary>True while a discount is configured and its expiry is still in the future.</summary>
    public bool IsDiscountActive(DateTimeOffset now) =>
        DiscountedAnnualPrice is not null && DiscountExpiresAt is not null && DiscountExpiresAt > now;

    /// <summary>The price a caller not otherwise overridden (e.g. by the VIP price, see <c>BillingService</c>) actually pays right now.</summary>
    public decimal EffectivePrice(DateTimeOffset now) => IsDiscountActive(now) ? DiscountedAnnualPrice!.Value : StandardAnnualPrice;

    public void Update(
        decimal standardAnnualPrice,
        decimal? discountedAnnualPrice,
        DateTimeOffset? discountExpiresAt,
        string? promoMessage,
        Guid updatedByUserId,
        DateTimeOffset? now = null) =>
        Apply(standardAnnualPrice, discountedAnnualPrice, discountExpiresAt, promoMessage, updatedByUserId, now);

    private void Apply(
        decimal standardAnnualPrice,
        decimal? discountedAnnualPrice,
        DateTimeOffset? discountExpiresAt,
        string? promoMessage,
        Guid updatedByUserId,
        DateTimeOffset? now)
    {
        if (standardAnnualPrice <= 0)
        {
            throw new ArgumentException("Standard price must be greater than zero.", nameof(standardAnnualPrice));
        }

        var effectiveNow = now ?? DateTimeOffset.UtcNow;

        // A discounted price and its expiry are a package deal: a promotion without an end date
        // isn't a promotion, and an expiry with no discounted price is meaningless — see
        // docs/features/billing.md.
        if (discountedAnnualPrice is not null || discountExpiresAt is not null)
        {
            if (discountedAnnualPrice is null || discountExpiresAt is null)
            {
                throw new ArgumentException("A discounted price and its expiry date must be set together, or not at all.");
            }

            if (discountedAnnualPrice.Value <= 0)
            {
                throw new ArgumentException("Discounted price must be greater than zero.", nameof(discountedAnnualPrice));
            }

            if (discountedAnnualPrice.Value >= standardAnnualPrice)
            {
                throw new ArgumentException("Discounted price must be lower than the standard price.", nameof(discountedAnnualPrice));
            }

            if (discountExpiresAt.Value <= effectiveNow)
            {
                throw new ArgumentException("Discount expiry must be in the future.", nameof(discountExpiresAt));
            }
        }

        if (promoMessage is { Length: > 280 })
        {
            throw new ArgumentException("Promo message must be 280 characters or fewer.", nameof(promoMessage));
        }

        StandardAnnualPrice = standardAnnualPrice;
        DiscountedAnnualPrice = discountedAnnualPrice;
        DiscountExpiresAt = discountExpiresAt;
        PromoMessage = string.IsNullOrWhiteSpace(promoMessage) ? null : promoMessage.Trim();
        UpdatedByUserId = Guard.AgainstEmptyGuid(updatedByUserId);
        UpdatedAt = effectiveNow;
    }
}
