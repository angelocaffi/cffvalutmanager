using CffVaultManager.Application.Abstractions;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// Test double for <see cref="IEmailSender"/>, registered in place of the real (logging-only)
/// implementation so tests can read back what would have been sent — in particular, the one-time
/// code embedded in the body, which is otherwise only ever stored hashed.
/// </summary>
public sealed class FakeEmailSender : IEmailSender
{
    public string? LastToEmail { get; private set; }

    public string? LastBody { get; private set; }

    public Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        LastToEmail = toEmail;
        LastBody = body;
        return Task.CompletedTask;
    }
}
