using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// Tracks a single PayPal checkout attempt for a tenant — audit trail and idempotency guard for
/// <c>POST /api/billing/checkout</c>/<c>capture</c> (see docs/features/billing.md). Not a secret:
/// same trust class as <see cref="TenantBillingProfile"/>, see docs/security-model.md.
/// </summary>
public class PaymentTransaction
{
    private PaymentTransaction()
    {
        // Parameterless constructor for EF Core / serialization.
        PayPalOrderId = null!;
        Currency = null!;
    }

    public PaymentTransaction(
        Guid id,
        Guid tenantId,
        Guid createdByUserId,
        string payPalOrderId,
        decimal amount,
        string currency,
        DateTimeOffset? createdAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
        CreatedByUserId = Guard.AgainstEmptyGuid(createdByUserId);
        PayPalOrderId = Guard.AgainstNullOrWhiteSpace(payPalOrderId);
        Amount = amount;
        Currency = Guard.AgainstNullOrWhiteSpace(currency);
        Status = PaymentTransactionStatus.Created;
        CreatedAt = createdAt ?? DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Guid CreatedByUserId { get; private set; }

    public string PayPalOrderId { get; private set; }

    public decimal Amount { get; private set; }

    public string Currency { get; private set; }

    public PaymentTransactionStatus Status { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? CapturedAt { get; private set; }

    /// <summary>Snapshot of <c>Tenant.PlanExpiresAt</c> right after this capture — immutable even if the plan changes later.</summary>
    public DateTimeOffset? PlanExpiresAtAfterCapture { get; private set; }

    public void MarkCaptured(DateTimeOffset capturedAt, DateTimeOffset planExpiresAtAfterCapture)
    {
        Status = PaymentTransactionStatus.Captured;
        CapturedAt = capturedAt;
        PlanExpiresAtAfterCapture = planExpiresAtAfterCapture;
    }

    public void MarkFailed() => Status = PaymentTransactionStatus.Failed;
}
