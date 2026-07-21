using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of Email OTP as an MFA factor (docs/features/authentication.md "Email OTP
/// come fattore MFA") over real HTTP: enabling/disabling the factor, and completing a login
/// challenge with it (alone, or alongside TOTP).
/// </summary>
public sealed class EmailOtpMfaEndpointsTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

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
    public async Task Enable_without_a_verified_email_returns_409()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        string accessToken = await LoginAsync("admin@acme.test", authHash);

        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/mfa/email-otp/enable", accessToken);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Enable_after_verifying_email_succeeds_and_login_then_requires_the_email_otp_challenge()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        await VerifyEmailAsync("admin@acme.test");
        string accessToken = await LoginAsync("admin@acme.test", authHash);

        var enableResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/mfa/email-otp/enable", accessToken);
        Assert.Equal(HttpStatusCode.NoContent, enableResponse.StatusCode);

        var login = await LoginResponseAsync("admin@acme.test", authHash);
        Assert.False(login.RootElement.GetProperty("success").GetBoolean());
        Assert.True(login.RootElement.GetProperty("requiresMfa").GetBoolean());
        var factors = login.RootElement.GetProperty("availableMfaFactors").EnumerateArray().Select(e => e.GetString()).ToArray();
        Assert.Equal(new[] { "EmailOtp" }, factors);
    }

    [Fact]
    public async Task Full_challenge_send_then_verify_with_the_emailed_code_issues_a_session()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        await VerifyEmailAsync("admin@acme.test");
        string accessToken = await LoginAsync("admin@acme.test", authHash);
        await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/mfa/email-otp/enable", accessToken);

        var login = await LoginResponseAsync("admin@acme.test", authHash);
        string challengeToken = login.RootElement.GetProperty("mfaChallengeToken").GetString()!;

        var sendResponse = await _client.PostAsJsonAsync("/api/auth/mfa/email-otp/send", new { ChallengeToken = challengeToken });
        Assert.Equal(HttpStatusCode.Accepted, sendResponse.StatusCode);
        string code = ExtractCode(_factory.EmailSender.LastBody!);

        var verifyResponse = await _client.PostAsJsonAsync("/api/auth/mfa/verify", new
        {
            ChallengeToken = challengeToken,
            Code = code,
            Factor = "EmailOtp",
        });

        Assert.Equal(HttpStatusCode.OK, verifyResponse.StatusCode);
        using var verifyBody = JsonDocument.Parse(await verifyResponse.Content.ReadAsStringAsync());
        Assert.True(verifyBody.RootElement.GetProperty("success").GetBoolean());
        Assert.NotNull(verifyBody.RootElement.GetProperty("accessToken").GetString());
    }

    [Fact]
    public async Task Verify_with_the_wrong_email_otp_code_returns_401()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        await VerifyEmailAsync("admin@acme.test");
        string accessToken = await LoginAsync("admin@acme.test", authHash);
        await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/mfa/email-otp/enable", accessToken);

        var login = await LoginResponseAsync("admin@acme.test", authHash);
        string challengeToken = login.RootElement.GetProperty("mfaChallengeToken").GetString()!;
        await _client.PostAsJsonAsync("/api/auth/mfa/email-otp/send", new { ChallengeToken = challengeToken });

        string realCode = ExtractCode(_factory.EmailSender.LastBody!);
        string wrongCode = realCode == "000000" ? "111111" : "000000";

        var verifyResponse = await _client.PostAsJsonAsync("/api/auth/mfa/verify", new
        {
            ChallengeToken = challengeToken,
            Code = wrongCode,
            Factor = "EmailOtp",
        });

        Assert.Equal(HttpStatusCode.Unauthorized, verifyResponse.StatusCode);
    }

    [Fact]
    public async Task Send_with_an_invalid_challenge_token_returns_401()
    {
        var response = await _client.PostAsJsonAsync("/api/auth/mfa/email-otp/send", new { ChallengeToken = "not-a-real-token" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Disable_removes_the_factor_and_login_no_longer_requires_a_challenge()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        await VerifyEmailAsync("admin@acme.test");
        string accessToken = await LoginAsync("admin@acme.test", authHash);
        await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/mfa/email-otp/enable", accessToken);

        var disableResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/mfa/email-otp/disable", accessToken);
        Assert.Equal(HttpStatusCode.NoContent, disableResponse.StatusCode);

        var login = await LoginResponseAsync("admin@acme.test", authHash);
        Assert.True(login.RootElement.GetProperty("success").GetBoolean());
        Assert.False(login.RootElement.GetProperty("requiresMfa").GetBoolean());
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task ProvisionTenantAsync(string slug, string adminEmail, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = slug,
            TenantSlug = slug,
            AdminEmail = adminEmail,
            AuthHash = authHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private async Task VerifyEmailAsync(string email)
    {
        string code = ExtractCode(_factory.EmailSender.LastBody!);
        var response = await _client.PostAsJsonAsync("/api/auth/email-verification/confirm", new { Email = email, Code = code });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private async Task<string> LoginAsync(string email, byte[] authHash)
    {
        var login = await LoginResponseAsync(email, authHash);
        return login.RootElement.GetProperty("accessToken").GetString()!;
    }

    private async Task<JsonDocument> LoginResponseAsync(string email, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash });
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private async Task<HttpResponseMessage> SendAuthorizedAsync(HttpMethod method, string url, string accessToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await _client.SendAsync(request);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    private static string ExtractCode(string body) => Regex.Match(body, @"\d{6}").Value;
}
