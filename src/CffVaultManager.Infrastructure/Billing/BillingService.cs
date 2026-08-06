using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Billing;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace CffVaultManager.Infrastructure.Billing;

/// <summary>
/// Drives the trial/paid-plan lifecycle and PayPal checkout (see docs/features/billing.md). The
/// price/currency/plan name are always read from server configuration, never from the caller —
/// see "Sicurezza" in that doc for why.
/// </summary>
internal sealed class BillingService : IBillingService
{
    private static readonly TimeSpan PlanDuration = TimeSpan.FromDays(365);

    private readonly CffVaultManagerDbContext _db;
    private readonly IPayPalClient? _payPal;
    private readonly decimal _annualPrice;
    private readonly string _currency;
    private readonly string _planName;
    private readonly string? _vipEmail;
    private readonly decimal? _vipAnnualPrice;

    // payPal is optional so DI resolves it to the real client only when PayPal:ClientId/Secret
    // are configured — there is no safe no-op fallback for payments (see
    // PayPalNotConfiguredException). Mirrors the IEmailVerificationService? pattern already used
    // by ProvisionTenantService for a similarly-optional external dependency.
    public BillingService(CffVaultManagerDbContext db, IConfiguration configuration, IPayPalClient? payPal = null)
    {
        _db = db;
        _payPal = payPal;
        _annualPrice = configuration.GetValue<decimal?>("Billing:AnnualPrice") ?? 49.00m;
        _currency = configuration["Billing:Currency"] ?? "EUR";
        _planName = configuration["Billing:PlanName"] ?? "Pro";
        _vipEmail = configuration["Billing:VipEmail"];
        _vipAnnualPrice = configuration.GetValue<decimal?>("Billing:VipAnnualPrice");
    }

    public async Task<BillingStatusDto> GetStatusAsync(Guid tenantId, CancellationToken ct = default)
    {
        var tenant = await _db.Tenants.FirstOrDefaultAsync(t => t.Id == tenantId, ct)
            ?? throw new KeyNotFoundException("Tenant not found.");

        var now = DateTimeOffset.UtcNow;
        return new BillingStatusDto(tenant.PlanName, tenant.TrialEndsAt, tenant.PlanExpiresAt, tenant.IsReadOnly(now));
    }

    public async Task<CreateCheckoutResult> CreateCheckoutAsync(Guid tenantId, Guid createdByUserId, CancellationToken ct = default)
    {
        if (_payPal is null)
        {
            throw new PayPalNotConfiguredException();
        }

        decimal price = await ResolvePriceAsync(createdByUserId, ct);
        string orderId = await _payPal.CreateOrderAsync(price, _currency, ct);

        _db.PaymentTransactions.Add(new PaymentTransaction(Guid.NewGuid(), tenantId, createdByUserId, orderId, price, _currency));
        await _db.SaveChangesAsync(ct);

        return new CreateCheckoutResult(orderId);
    }

    /// <summary>
    /// Almost always <see cref="_annualPrice"/>. If <c>Billing:VipEmail</c>/<c>VipAnnualPrice</c>
    /// are configured (see docs/features/billing.md "Prezzo VIP opzionale") and the caller's own
    /// account email matches, the configured override price is used instead — resolved
    /// server-side from the authenticated user id, never from client input, so the "amount is
    /// never a client input" invariant this service otherwise enforces still holds.
    /// </summary>
    private async Task<decimal> ResolvePriceAsync(Guid userId, CancellationToken ct)
    {
        if (_vipEmail is null || _vipAnnualPrice is null)
        {
            return _annualPrice;
        }

        string? email = await _db.Users.Where(u => u.Id == userId).Select(u => u.Email).FirstOrDefaultAsync(ct);
        return string.Equals(email, _vipEmail, StringComparison.OrdinalIgnoreCase) ? _vipAnnualPrice.Value : _annualPrice;
    }

    public async Task<CaptureCheckoutResult> CaptureCheckoutAsync(Guid tenantId, Guid userId, string orderId, CancellationToken ct = default)
    {
        var transaction = await _db.PaymentTransactions
            .FirstOrDefaultAsync(t => t.TenantId == tenantId && t.PayPalOrderId == orderId, ct)
            ?? throw new KeyNotFoundException("Payment order not found.");

        // Idempotent: a double click on "Paga" or a retried request must not extend the plan twice.
        if (transaction.Status == PaymentTransactionStatus.Captured)
        {
            return new CaptureCheckoutResult(true, transaction.PlanExpiresAtAfterCapture);
        }

        if (_payPal is null)
        {
            throw new PayPalNotConfiguredException();
        }

        var capture = await _payPal.CaptureOrderAsync(orderId, ct);
        var now = DateTimeOffset.UtcNow;

        if (capture.Status != "COMPLETED")
        {
            transaction.MarkFailed();
            await _db.SaveChangesAsync(ct);
            return new CaptureCheckoutResult(false, null);
        }

        var tenant = await _db.Tenants.FirstOrDefaultAsync(t => t.Id == tenantId, ct)
            ?? throw new KeyNotFoundException("Tenant not found.");

        tenant.ExtendPlan(now, PlanDuration);
        tenant.PlanName ??= _planName;
        transaction.MarkCaptured(now, tenant.PlanExpiresAt!.Value);
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), tenantId, userId, AuditAction.PaymentCaptured));

        await _db.SaveChangesAsync(ct);

        return new CaptureCheckoutResult(true, tenant.PlanExpiresAt);
    }
}
