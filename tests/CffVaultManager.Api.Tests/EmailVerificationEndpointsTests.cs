using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of "verifica email in registrazione" over real HTTP: a code is sent
/// automatically at the end of tenant provisioning; these tests confirm the resend/confirm
/// endpoints wired to it, including their anti-enumeration behavior.
/// </summary>
public sealed class EmailVerificationEndpointsTests : IAsyncLifetime
{
    private ApiTestFactory _factory = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _factory = new ApiTestFactory();
        await _factory.EnsureDatabaseCreatedAsync();
        _client = _factory.CreateClient();
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Provisioning_sends_a_code_and_confirming_it_with_the_right_code_succeeds()
    {
        await ProvisionAsync("admin@acme.test");

        Assert.Equal("admin@acme.test", _factory.EmailSender.LastToEmail);
        string code = ExtractCode(_factory.EmailSender.LastBody!);

        var response = await _client.PostAsJsonAsync("/api/auth/email-verification/confirm", new { Email = "admin@acme.test", Code = code });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Confirming_with_the_wrong_code_returns_401()
    {
        await ProvisionAsync("admin@acme.test");

        string realCode = ExtractCode(_factory.EmailSender.LastBody!);
        string wrongCode = realCode == "000000" ? "111111" : "000000";

        var response = await _client.PostAsJsonAsync("/api/auth/email-verification/confirm", new { Email = "admin@acme.test", Code = wrongCode });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Confirming_for_an_unknown_email_returns_401_same_as_a_wrong_code()
    {
        // Anti-enumeration: an email that was never registered must look identical to a real
        // email with a wrong code — both a plain 401, no distinguishing detail.
        var response = await _client.PostAsJsonAsync(
            "/api/auth/email-verification/confirm", new { Email = "nobody@nowhere.test", Code = "123456" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Resend_for_an_unknown_email_returns_202_without_sending_anything()
    {
        // Anti-enumeration: the resend endpoint must not reveal whether the email exists.
        var response = await _client.PostAsJsonAsync("/api/auth/email-verification/resend", new { Email = "nobody@nowhere.test" });
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Null(_factory.EmailSender.LastToEmail);
    }

    [Fact]
    public async Task Resend_immediately_after_provisioning_is_within_cooldown_and_sends_nothing_new()
    {
        await ProvisionAsync("admin@acme.test");
        string firstBody = _factory.EmailSender.LastBody!;

        var response = await _client.PostAsJsonAsync("/api/auth/email-verification/resend", new { Email = "admin@acme.test" });

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(firstBody, _factory.EmailSender.LastBody);
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task ProvisionAsync(string adminEmail)
    {
        var response = await _client.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = "acme",
            TenantSlug = "acme",
            AdminEmail = adminEmail,
            AuthHash = RandomNumberGenerator.GetBytes(32),
            EncryptedDek = RandomNumberGenerator.GetBytes(4),
            MasterPasswordSalt = RandomNumberGenerator.GetBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private static string ExtractCode(string body) => Regex.Match(body, @"\d{6}").Value;
}
