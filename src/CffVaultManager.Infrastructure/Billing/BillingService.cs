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

    public async Task<BillingStatusDto> GetStatusAsync(Guid tenantId, Guid callerId, CancellationToken ct = default)
    {
        var tenant = await _db.Tenants.FirstOrDefaultAsync(t => t.Id == tenantId, ct)
            ?? throw new KeyNotFoundException("Tenant not found.");

        var now = DateTimeOffset.UtcNow;
        var pricing = await _db.Set<BillingPricing>().FirstOrDefaultAsync(p => p.Id == BillingPricing.SingletonId, ct);
        decimal standardPrice = pricing?.StandardAnnualPrice ?? _annualPrice;
        decimal effectivePrice = await ResolvePriceAsync(callerId, pricing, ct);
        bool promoActive = pricing?.IsDiscountActive(now) ?? false;

        return new BillingStatusDto(
            tenant.PlanName,
            tenant.TrialEndsAt,
            tenant.PlanExpiresAt,
            tenant.IsReadOnly(now),
            standardPrice,
            effectivePrice,
            _currency,
            promoActive ? pricing!.PromoMessage : null,
            promoActive ? pricing!.DiscountExpiresAt : null);
    }

    public async Task<CreateCheckoutResult> CreateCheckoutAsync(Guid tenantId, Guid createdByUserId, CancellationToken ct = default)
    {
        if (_payPal is null)
        {
            throw new PayPalNotConfiguredException();
        }

        var pricing = await _db.Set<BillingPricing>().FirstOrDefaultAsync(p => p.Id == BillingPricing.SingletonId, ct);
        decimal price = await ResolvePriceAsync(createdByUserId, pricing, ct);
        string orderId = await _payPal.CreateOrderAsync(price, _currency, ct);

        _db.PaymentTransactions.Add(new PaymentTransaction(Guid.NewGuid(), tenantId, createdByUserId, orderId, price, _currency));
        await _db.SaveChangesAsync(ct);

        return new CreateCheckoutResult(orderId);
    }

    /// <summary>
    /// Precedence: (1) the VIP override if <c>Billing:VipEmail</c>/<c>VipAnnualPrice</c> are
    /// configured (see docs/features/billing.md "Prezzo VIP opzionale") and the caller's own
    /// account email matches — resolved server-side from the authenticated user id, never from
    /// client input, so the "amount is never a client input" invariant this service otherwise
    /// enforces still holds; (2) the SuperAdmin-configured <see cref="BillingPricing"/> row's
    /// effective price (discount if currently active, else its standard price) if one exists; (3)
    /// <see cref="_annualPrice"/>, the server-configured default, for an install where no
    /// SuperAdmin has ever touched pricing.
    /// </summary>
    private async Task<decimal> ResolvePriceAsync(Guid userId, BillingPricing? pricing, CancellationToken ct)
    {
        if (_vipEmail is not null && _vipAnnualPrice is not null)
        {
            string? email = await _db.Users.Where(u => u.Id == userId).Select(u => u.Email).FirstOrDefaultAsync(ct);
            if (string.Equals(email, _vipEmail, StringComparison.OrdinalIgnoreCase))
            {
                return _vipAnnualPrice.Value;
            }
        }

        return pricing?.EffectivePrice(DateTimeOffset.UtcNow) ?? _annualPrice;
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
