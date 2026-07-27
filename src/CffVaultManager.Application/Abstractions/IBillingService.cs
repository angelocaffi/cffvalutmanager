using CffVaultManager.Application.Dtos.Billing;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Drives the trial/paid-plan lifecycle and PayPal checkout (see docs/features/billing.md).
/// </summary>
public interface IBillingService
{
    Task<BillingStatusDto> GetStatusAsync(Guid tenantId, CancellationToken ct = default);

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
