using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using OtpNet;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the Api host's JWT bearer authentication, tenant-resolution middleware,
/// and role-based authorization, exercised over real HTTP against the real DI wiring in
/// Program.cs (in-memory SQLite standing in for PostgreSQL — see <see cref="ApiTestFactory"/>).
/// Business-rule coverage (tenant isolation at the query-filter level, login/MFA/refresh
/// semantics) already lives in CffVaultManager.Infrastructure.Tests; these tests only prove the
/// HTTP plumbing wires that logic up correctly.
/// </summary>
public sealed class AuthAndRolesTests : IAsyncLifetime
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
    public async Task Prelogin_for_a_provisioned_email_returns_its_real_salt_and_kdf_params()
    {
        var authHash = RandomBytes(32);
        byte[] salt = RandomBytes(16);
        var response = await _client.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = "acme",
            TenantSlug = "acme",
            AdminEmail = "admin@acme.test",
            AuthHash = authHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = salt,
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var prelogin = await _client.PostAsJsonAsync("/api/auth/prelogin", new { Email = "admin@acme.test" });
        Assert.Equal(HttpStatusCode.OK, prelogin.StatusCode);
        using var body = JsonDocument.Parse(await prelogin.Content.ReadAsStringAsync());
        Assert.Equal(salt, body.RootElement.GetProperty("masterPasswordSalt").GetBytesFromBase64());
        Assert.Equal(65536, body.RootElement.GetProperty("kdfMemoryKb").GetInt32());
    }

    [Fact]
    public async Task Prelogin_for_an_unknown_email_still_returns_200_with_a_plausible_salt()
    {
        // Anti-enumeration: no 404, no distinguishing error — same shape as a real user.
        var response = await _client.PostAsJsonAsync("/api/auth/prelogin", new { Email = "nobody@nowhere.test" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(16, body.RootElement.GetProperty("masterPasswordSalt").GetBytesFromBase64().Length);
    }

    [Fact]
    public async Task Provision_then_login_succeeds_and_returns_a_usable_access_token()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);

        var login = await LoginAsync("admin@acme.test", authHash);

        Assert.True(login.RootElement.GetProperty("success").GetBoolean());
        Assert.False(login.RootElement.GetProperty("requiresMfa").GetBoolean());
        string accessToken = login.RootElement.GetProperty("accessToken").GetString()!;
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        // A valid access token for any authenticated role can reach an [Authorize]-only endpoint.
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/mfa/setup");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Login_with_wrong_authhash_returns_401()
    {
        await ProvisionTenantAsync("acme", "admin@acme.test", RandomBytes(32));

        var response = await _client.PostAsJsonAsync("/api/auth/login", new
        {
            Email = "admin@acme.test",
            AuthHash = RandomBytes(32),
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SuperAdmin_endpoint_without_token_returns_401()
    {
        var response = await _client.GetAsync("/api/admin/tenants");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SuperAdmin_endpoint_with_tenant_admin_token_returns_403()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        var login = await LoginAsync("admin@acme.test", authHash);
        string accessToken = login.RootElement.GetProperty("accessToken").GetString()!;

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/tenants");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await _client.SendAsync(request);

        // A tenant Admin is a real, authenticated role — just not SuperAdmin.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Admin_can_register_operator_but_operator_cannot_register_anyone()
    {
        var adminAuthHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", adminAuthHash);
        var adminLogin = await LoginAsync("admin@acme.test", adminAuthHash);
        string adminToken = adminLogin.RootElement.GetProperty("accessToken").GetString()!;

        var operatorAuthHash = RandomBytes(32);
        var registerResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/users", adminToken, new
        {
            Email = "operator@acme.test",
            Role = "Operator",
            AuthHash = operatorAuthHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, registerResponse.StatusCode);

        var operatorLogin = await LoginAsync("operator@acme.test", operatorAuthHash);
        string operatorToken = operatorLogin.RootElement.GetProperty("accessToken").GetString()!;

        var forbidden = await SendAuthorizedAsync(HttpMethod.Post, "/api/users", operatorToken, new
        {
            Email = "someone-else@acme.test",
            Role = "Operator",
            AuthHash = RandomBytes(32),
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
    }

    [Fact]
    public async Task Refresh_rotates_the_token_and_the_old_one_cannot_be_reused()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        var login = await LoginAsync("admin@acme.test", authHash);
        string originalRefreshToken = login.RootElement.GetProperty("refreshToken").GetString()!;

        var refreshResponse = await _client.PostAsJsonAsync("/api/auth/refresh", new { RefreshToken = originalRefreshToken });
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        using var refreshed = JsonDocument.Parse(await refreshResponse.Content.ReadAsStringAsync());
        string newAccessToken = refreshed.RootElement.GetProperty("accessToken").GetString()!;
        string newRefreshToken = refreshed.RootElement.GetProperty("refreshToken").GetString()!;
        Assert.NotEqual(originalRefreshToken, newRefreshToken);

        // The new access token must actually work.
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/mfa/setup");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newAccessToken);
        Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync(request)).StatusCode);

        // Reusing the original (already-rotated) refresh token must now fail.
        var reuseResponse = await _client.PostAsJsonAsync("/api/auth/refresh", new { RefreshToken = originalRefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, reuseResponse.StatusCode);
    }

    [Fact]
    public async Task Mfa_setup_then_login_requires_challenge_then_verify_succeeds()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        var login = await LoginAsync("admin@acme.test", authHash);
        string accessToken = login.RootElement.GetProperty("accessToken").GetString()!;

        using var setupRequest = new HttpRequestMessage(HttpMethod.Post, "/api/auth/mfa/setup");
        setupRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var setupResponse = await _client.SendAsync(setupRequest);
        using var setupBody = JsonDocument.Parse(await setupResponse.Content.ReadAsStringAsync());
        string provisioningUri = setupBody.RootElement.GetProperty("provisioningUri").GetString()!;
        byte[] secret = ExtractTotpSecret(provisioningUri);

        var confirmResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/mfa/confirm", accessToken,
            new { Code = new Totp(secret).ComputeTotp() });
        Assert.Equal(HttpStatusCode.OK, confirmResponse.StatusCode);

        var loginAfterMfa = await LoginAsync("admin@acme.test", authHash);
        Assert.False(loginAfterMfa.RootElement.GetProperty("success").GetBoolean());
        Assert.True(loginAfterMfa.RootElement.GetProperty("requiresMfa").GetBoolean());
        string challengeToken = loginAfterMfa.RootElement.GetProperty("mfaChallengeToken").GetString()!;

        var verifyResponse = await _client.PostAsJsonAsync("/api/auth/mfa/verify", new
        {
            ChallengeToken = challengeToken,
            Code = new Totp(secret).ComputeTotp(),
        });
        Assert.Equal(HttpStatusCode.OK, verifyResponse.StatusCode);
        using var verifyBody = JsonDocument.Parse(await verifyResponse.Content.ReadAsStringAsync());
        Assert.True(verifyBody.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Me_reflects_the_callers_own_email_and_default_mfa_state()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        var login = await LoginAsync("admin@acme.test", authHash);
        string accessToken = login.RootElement.GetProperty("accessToken").GetString()!;

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("admin@acme.test", body.RootElement.GetProperty("email").GetString());
        Assert.False(body.RootElement.GetProperty("emailVerified").GetBoolean());
        Assert.False(body.RootElement.GetProperty("mfaEnabled").GetBoolean());
        Assert.False(body.RootElement.GetProperty("mfaEmailOtpEnabled").GetBoolean());
    }

    [Fact]
    public async Task Me_without_a_token_returns_401()
    {
        var response = await _client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
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

    private async Task<JsonDocument> LoginAsync(string email, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash });
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private async Task<HttpResponseMessage> SendAuthorizedAsync(HttpMethod method, string url, string accessToken, object body)
    {
        using var request = new HttpRequestMessage(method, url) { Content = JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await _client.SendAsync(request);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    private static byte[] ExtractTotpSecret(string provisioningUri)
    {
        // otpauth://totp/...?secret=BASE32SECRET&issuer=...
        var uri = new Uri(provisioningUri);
        var query = QueryHelpers.ParseQuery(uri.Query);
        string base32Secret = query["secret"]!;
        return Base32Encoding.ToBytes(base32Secret);
    }
}
