using CffVaultManager.Application.Abstractions;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// The handful of MailKit <see cref="SmtpClient"/> operations <see cref="SmtpEmailSender"/> needs,
/// kept as its own tiny seam rather than depending on MailKit's own <c>ISmtpClient</c> directly:
/// that interface has dozens of members (capabilities, SASL mechanisms, TLS/certificate knobs,
/// etc.) unrelated to sending a single plain-text message, which would make a hand-written test
/// fake mostly boilerplate (this project references no mocking library).
/// </summary>
internal interface ISmtpTransport : IDisposable
{
    Task ConnectAsync(string host, int port, SecureSocketOptions options, CancellationToken ct);

    Task AuthenticateAsync(string userName, string password, CancellationToken ct);

    Task SendAsync(MimeMessage message, CancellationToken ct);

    Task DisconnectAsync(bool quit, CancellationToken ct);
}

/// <summary>Thin adapter over the real MailKit <see cref="SmtpClient"/>.</summary>
internal sealed class MailKitSmtpTransport : ISmtpTransport
{
    private readonly SmtpClient _client = new();

    public Task ConnectAsync(string host, int port, SecureSocketOptions options, CancellationToken ct) =>
        _client.ConnectAsync(host, port, options, ct);

    public Task AuthenticateAsync(string userName, string password, CancellationToken ct) =>
        _client.AuthenticateAsync(userName, password, ct);

    public async Task SendAsync(MimeMessage message, CancellationToken ct) => await _client.SendAsync(message, ct);

    public Task DisconnectAsync(bool quit, CancellationToken ct) => _client.DisconnectAsync(quit, ct);

    public void Dispose() => _client.Dispose();
}

/// <summary>
/// Real <see cref="IEmailSender"/> implementation: delivers via SMTP (MailKit), not a specific
/// vendor API — this project is self-hosted, and virtually every transactional email service also
/// exposes an SMTP endpoint (SendGrid, Mailgun, Amazon SES, Postmark, Brevo, a personal
/// Gmail/Office365 account, or a self-hosted relay), so one SMTP implementation covers all of them
/// via configuration alone (see docs/features/notifications.md). Never logs the body: it may
/// contain a one-time code, same discipline as <see cref="LoggingEmailSender"/>. No retry/queueing:
/// out of scope for a single self-hosted relay (see docs/roadmap.md).
/// </summary>
internal sealed class SmtpEmailSender : IEmailSender
{
    private readonly string _host;
    private readonly int _port;
    private readonly string? _username;
    private readonly string? _password;
    private readonly bool _useStartTls;
    private readonly string _fromAddress;
    private readonly string _fromDisplayName;
    private readonly Func<ISmtpTransport> _transportFactory;
    private readonly ILogger<SmtpEmailSender> _logger;

    public SmtpEmailSender(
        string host,
        int port,
        string? username,
        string? password,
        bool useStartTls,
        string fromAddress,
        string fromDisplayName,
        ILogger<SmtpEmailSender> logger,
        Func<ISmtpTransport>? transportFactory = null)
    {
        _host = host;
        _port = port;
        _username = username;
        _password = password;
        _useStartTls = useStartTls;
        _fromAddress = fromAddress;
        _fromDisplayName = fromDisplayName;
        _logger = logger;
        _transportFactory = transportFactory ?? (() => new MailKitSmtpTransport());
    }

    public async Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(_fromDisplayName, _fromAddress));
        message.To.Add(MailboxAddress.Parse(toEmail));
        message.Subject = subject;
        message.Body = new TextPart("plain") { Text = body };

        using var transport = _transportFactory();
        try
        {
            await transport.ConnectAsync(_host, _port, _useStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.Auto, ct);

            // Anonymous relay support for self-hosted setups that don't require auth.
            if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
            {
                await transport.AuthenticateAsync(_username, _password, ct);
            }

            await transport.SendAsync(message, ct);
            _logger.LogInformation("Email sent: to={ToEmail}, subject={Subject}", toEmail, subject);
        }
        finally
        {
            await transport.DisconnectAsync(true, ct);
        }
    }
}
