using CffVaultManager.Application.Abstractions;
using Microsoft.Extensions.Logging;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Placeholder <see cref="IEmailSender"/>: logs that an email would be sent but never actually
/// delivers it — no real SMTP/transactional-email provider is wired up yet (this project is still
/// in its initial scaffolding phase, see the root CLAUDE.md). Never logs the body: it may contain
/// a one-time code, and this project's logging discipline treats those the same as any other
/// secret. Must be replaced with a real provider before any production deployment.
/// </summary>
internal sealed class LoggingEmailSender : IEmailSender
{
    private readonly ILogger<LoggingEmailSender> _logger;

    public LoggingEmailSender(ILogger<LoggingEmailSender> logger) => _logger = logger;

    public Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        _logger.LogInformation(
            "Email not actually sent (no email provider configured yet): to={ToEmail}, subject={Subject}",
            toEmail, subject);
        return Task.CompletedTask;
    }
}
