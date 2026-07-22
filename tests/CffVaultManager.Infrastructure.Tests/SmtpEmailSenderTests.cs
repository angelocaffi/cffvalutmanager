using CffVaultManager.Infrastructure.Authentication;
using MailKit.Security;
using Microsoft.Extensions.Logging.Abstractions;
using MimeKit;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Unit coverage of <see cref="SmtpEmailSender"/> against a hand-written fake <see cref="ISmtpTransport"/>
/// (no mocking library is referenced anywhere in this solution) — proves the MimeMessage is built
/// correctly, that authentication is skipped for an anonymous relay, and that a send failure
/// propagates rather than being swallowed. No real network I/O happens in these tests.
/// </summary>
public sealed class SmtpEmailSenderTests
{
    [Fact]
    public async Task SendAsync_builds_the_expected_message_and_connects_authenticates_sends_disconnects()
    {
        var fake = new FakeSmtpTransport();
        var sender = new SmtpEmailSender(
            "smtp.example.com", 587, "user@example.com", "hunter2", useStartTls: true,
            fromAddress: "no-reply@cffvaultmanager.test", fromDisplayName: "CffVaultManager",
            NullLogger<SmtpEmailSender>.Instance, () => fake);

        await sender.SendAsync("recipient@example.com", "Subject line", "Body text", default);

        Assert.Equal("smtp.example.com", fake.ConnectedHost);
        Assert.Equal(587, fake.ConnectedPort);
        Assert.Equal(SecureSocketOptions.StartTls, fake.ConnectedOptions);
        Assert.Equal("user@example.com", fake.AuthenticatedUser);
        Assert.Equal("hunter2", fake.AuthenticatedPassword);

        Assert.NotNull(fake.SentMessage);
        Assert.Equal("no-reply@cffvaultmanager.test", ((MailboxAddress)fake.SentMessage!.From[0]).Address);
        Assert.Equal("CffVaultManager", ((MailboxAddress)fake.SentMessage!.From[0]).Name);
        Assert.Equal("recipient@example.com", ((MailboxAddress)fake.SentMessage!.To[0]).Address);
        Assert.Equal("Subject line", fake.SentMessage!.Subject);
        Assert.Equal("Body text", fake.SentMessage!.TextBody);

        Assert.True(fake.Disconnected);
    }

    [Fact]
    public async Task SendAsync_skips_authentication_when_username_or_password_is_empty()
    {
        var fake = new FakeSmtpTransport();
        var sender = new SmtpEmailSender(
            "relay.internal", 25, username: null, password: null, useStartTls: false,
            fromAddress: "no-reply@cffvaultmanager.test", fromDisplayName: "CffVaultManager",
            NullLogger<SmtpEmailSender>.Instance, () => fake);

        await sender.SendAsync("recipient@example.com", "Subject", "Body", default);

        Assert.False(fake.AuthenticateCalled);
        Assert.NotNull(fake.SentMessage);
        Assert.True(fake.Disconnected);
    }

    [Fact]
    public async Task SendAsync_propagates_a_send_failure_and_still_disconnects()
    {
        var fake = new FakeSmtpTransport { ThrowOnSend = new InvalidOperationException("relay refused the message") };
        var sender = new SmtpEmailSender(
            "smtp.example.com", 587, "user@example.com", "hunter2", useStartTls: true,
            fromAddress: "no-reply@cffvaultmanager.test", fromDisplayName: "CffVaultManager",
            NullLogger<SmtpEmailSender>.Instance, () => fake);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            sender.SendAsync("recipient@example.com", "Subject", "Body", default));

        Assert.True(fake.Disconnected);
    }

    private sealed class FakeSmtpTransport : ISmtpTransport
    {
        public string? ConnectedHost { get; private set; }
        public int ConnectedPort { get; private set; }
        public SecureSocketOptions ConnectedOptions { get; private set; }
        public bool AuthenticateCalled { get; private set; }
        public string? AuthenticatedUser { get; private set; }
        public string? AuthenticatedPassword { get; private set; }
        public MimeMessage? SentMessage { get; private set; }
        public bool Disconnected { get; private set; }
        public Exception? ThrowOnSend { get; set; }

        public Task ConnectAsync(string host, int port, SecureSocketOptions options, CancellationToken ct)
        {
            ConnectedHost = host;
            ConnectedPort = port;
            ConnectedOptions = options;
            return Task.CompletedTask;
        }

        public Task AuthenticateAsync(string userName, string password, CancellationToken ct)
        {
            AuthenticateCalled = true;
            AuthenticatedUser = userName;
            AuthenticatedPassword = password;
            return Task.CompletedTask;
        }

        public Task SendAsync(MimeMessage message, CancellationToken ct)
        {
            if (ThrowOnSend is not null)
            {
                throw ThrowOnSend;
            }

            SentMessage = message;
            return Task.CompletedTask;
        }

        public Task DisconnectAsync(bool quit, CancellationToken ct)
        {
            Disconnected = true;
            return Task.CompletedTask;
        }

        public void Dispose()
        {
        }
    }
}
