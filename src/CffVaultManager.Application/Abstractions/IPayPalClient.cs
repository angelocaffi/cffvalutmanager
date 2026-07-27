using CffVaultManager.Application.Dtos.Billing;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Server-to-server PayPal Orders API v2 client (see docs/features/billing.md). Registered only
/// when <c>PayPal:ClientId</c>/<c>PayPal:ClientSecret</c> are configured — there is no safe no-op
/// implementation for payments, so callers that need it when it's absent must handle a null
/// resolution themselves (mirrors the optional <c>IEmailVerificationService?</c> pattern in
/// ProvisionTenantService).
/// </summary>
public interface IPayPalClient
{
    /// <summary>Creates a PayPal order (intent CAPTURE) for the given amount and returns its order id.</summary>
    Task<string> CreateOrderAsync(decimal amount, string currency, CancellationToken ct = default);

    /// <summary>Captures a previously created order.</summary>
    Task<PayPalOrderCapture> CaptureOrderAsync(string orderId, CancellationToken ct = default);
}
