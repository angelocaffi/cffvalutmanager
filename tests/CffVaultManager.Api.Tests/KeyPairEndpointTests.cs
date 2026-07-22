using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of <c>POST /api/auth/keypair</c> and the <c>hasKeyPair</c> flag on
/// <c>GET /api/auth/me</c> — the prerequisite for any X25519-based sharing (see
/// docs/features/sharing-access-control.md).
/// </summary>
public sealed class KeyPairEndpointTests : IAsyncLifetime
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
    public async Task GET_me_reports_HasKeyPair_false_before_any_keypair_is_set()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");

        var response = await GetAuthorizedAsync("/api/auth/me", token);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(body.RootElement.GetProperty("hasKeyPair").GetBoolean());
    }

    [Fact]
    public async Task POST_keypair_returns_204_and_GET_me_then_reports_HasKeyPair_true()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");

        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/keypair", token, new
        {
            PublicKey = RandomBytes(32),
            EncryptedPrivateKey = RandomBytes(64),
        });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var me = await GetAuthorizedAsync("/api/auth/me", token);
        using var body = JsonDocument.Parse(await me.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.GetProperty("hasKeyPair").GetBoolean());
    }

    [Fact]
    public async Task GET_keypair_before_any_is_set_returns_404()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");

        var response = await GetAuthorizedAsync("/api/auth/keypair", token);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GET_keypair_after_it_is_set_returns_what_was_uploaded()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        byte[] publicKey = RandomBytes(32);
        byte[] encryptedPrivateKey = RandomBytes(64);

        Assert.Equal(HttpStatusCode.NoContent, (await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/keypair", token, new
        {
            PublicKey = publicKey,
            EncryptedPrivateKey = encryptedPrivateKey,
        })).StatusCode);

        var response = await GetAuthorizedAsync("/api/auth/keypair", token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Convert.ToBase64String(publicKey), body.RootElement.GetProperty("publicKey").GetString());
        Assert.Equal(Convert.ToBase64String(encryptedPrivateKey), body.RootElement.GetProperty("encryptedPrivateKey").GetString());
    }

    [Fact]
    public async Task POST_keypair_a_second_time_returns_409()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");

        var first = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/keypair", token, new
        {
            PublicKey = RandomBytes(32),
            EncryptedPrivateKey = RandomBytes(64),
        });
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);

        var second = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/keypair", token, new
        {
            PublicKey = RandomBytes(32),
            EncryptedPrivateKey = RandomBytes(64),
        });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task<string> ProvisionAndLoginAsync(string slug, string adminEmail)
    {
        var authHash = RandomBytes(32);
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

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new { Email = adminEmail, AuthHash = authHash });
        using var body = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("accessToken").GetString()!;
    }

    private Task<HttpResponseMessage> GetAuthorizedAsync(string url, string accessToken) =>
        SendAuthorizedAsync(HttpMethod.Get, url, accessToken, null);

    private async Task<HttpResponseMessage> SendAuthorizedAsync(HttpMethod method, string url, string accessToken, object? body)
    {
        using var request = new HttpRequestMessage(method, url);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await _client.SendAsync(request);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);
}
