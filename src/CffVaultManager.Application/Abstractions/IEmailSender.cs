namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Sends a plain-text email. Delivery mechanism is fully pluggable — see the registered
/// implementation for what actually happens (no real SMTP/transactional-email provider is wired
/// up yet; see docs/features/authentication.md).
/// </summary>
public interface IEmailSender
{
    Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default);
}
