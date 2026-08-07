namespace CffVaultManager.Application.Dtos.Billing;

/// <summary>Current platform-wide pricing (see docs/features/billing.md "Prezzo modificabile da SuperAdmin"), for the SuperAdmin admin page.</summary>
public sealed record BillingPricingDto(
    decimal StandardAnnualPrice,
    decimal? DiscountedAnnualPrice,
    DateTimeOffset? DiscountExpiresAt,
    string? PromoMessage,
    string Currency,
    bool IsDiscountActive,
    DateTimeOffset? UpdatedAt);
