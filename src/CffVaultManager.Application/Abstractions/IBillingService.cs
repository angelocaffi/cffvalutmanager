using CffVaultManager.Application.Dtos.Billing;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Drives the trial/paid-plan lifecycle and PayPal checkout (see docs/features/billing.md).
/// </summary>
public interface IBillingService
{
    /// <summary><paramref name="callerId"/> resolves the VIP price override (if any) for <see cref="BillingStatusDto.EffectivePrice"/> — see BillingService.ResolvePriceAsync.</summary>
    Task<BillingStatusDto> GetStatusAsync(Guid tenantId, Guid callerId, CancellationToken ct = default);

    /// <summary>
    /// Creates a PayPal order for the fixed, server-configured annual price and persists a
    /// <c>Created</c> <c>PaymentTransaction</c>. Throws <see cref="CffVaultManager.Domain.PayPalNotConfiguredException"/>
    /// if PayPal credentials are not configured.
    /// </summary>
    Task<CreateCheckoutResult> CreateCheckoutAsync(Guid tenantId, Guid createdByUserId, CancellationToken ct = default);

    /// <summary>
    /// Captures the order with PayPal and extends <c>Tenant.PlanExpiresAt</c>. Idempotent: if
    /// <paramref name="orderId"/> is already <c>Captured</c> locally, returns the same result
    /// without calling PayPal again or extending the plan a second time.
    /// </summary>
    Task<CaptureCheckoutResult> CaptureCheckoutAsync(Guid tenantId, Guid userId, string orderId, CancellationToken ct = default);
}
