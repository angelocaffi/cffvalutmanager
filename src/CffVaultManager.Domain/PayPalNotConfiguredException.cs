namespace CffVaultManager.Domain;

/// <summary>
/// Thrown when a checkout is attempted but <c>PayPal:ClientId</c>/<c>PayPal:ClientSecret</c> are not
/// configured. There is no safe no-op fallback for payments (unlike e.g. LoggingEmailSender) — this
/// maps to 503 Service Unavailable, see docs/features/billing.md.
/// </summary>
public sealed class PayPalNotConfiguredException : Exception
{
    public PayPalNotConfiguredException()
        : base("PayPal is not configured on this server.")
    {
    }
}
