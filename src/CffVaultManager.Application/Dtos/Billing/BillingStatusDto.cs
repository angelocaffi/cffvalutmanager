namespace CffVaultManager.Application.Dtos.Billing;

/// <summary>The caller's tenant billing state, for the <c>/billing</c> page banner (see docs/features/billing.md).</summary>
public sealed record BillingStatusDto(
    string? PlanName,
    DateTimeOffset TrialEndsAt,
    DateTimeOffset? PlanExpiresAt,
    bool IsReadOnly);
