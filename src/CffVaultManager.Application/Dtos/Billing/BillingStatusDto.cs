namespace CffVaultManager.Application.Dtos.Billing;

/// <summary>
/// The caller's tenant billing state, for the <c>/billing</c> page banner (see
/// docs/features/billing.md). <see cref="EffectivePrice"/> is what this specific caller would pay
/// right now (VIP override, if any, already applied) — <see cref="StandardAnnualPrice"/> and
/// <see cref="PromoMessage"/> are shown alongside it only to render a "was X, now Y" promo banner,
/// never used by the client to decide what to charge (see BillingService "Sicurezza").
/// </summary>
public sealed record BillingStatusDto(
    string? PlanName,
    DateTimeOffset TrialEndsAt,
    DateTimeOffset? PlanExpiresAt,
    bool IsReadOnly,
    decimal StandardAnnualPrice,
    decimal EffectivePrice,
    string Currency,
    string? PromoMessage,
    DateTimeOffset? PromoExpiresAt);
