using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of "logout remoto" (docs/features/authentication.md): listing and
/// revoking the caller's own refresh-token sessions.
/// </summary>
public sealed class SessionEndpointsTests : IAsyncLifetime
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
    public async Task GET_sessions_without_token_returns_401()
    {
        var response = await _client.GetAsync("/api/auth/sessions");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GET_sessions_lists_the_active_session_from_login()
    {
        var authHash = RandomBytes(32);
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test", authHash);

        var response = await GetAuthorizedAsync("/api/auth/sessions", token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var sessions = body.RootElement.EnumerateArray().ToList();
        Assert.Single(sessions);
    }

    [Fact]
    public async Task Revoke_a_session_removes_it_from_the_active_list_and_blocks_refresh()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);

        using var login = await LoginAsync("admin@acme.test", authHash);
        string token = login.RootElement.GetProperty("accessToken").GetString()!;
        string refreshToken = login.RootElement.GetProperty("refreshToken").GetString()!;

        var listResponse = await GetAuthorizedAsync("/api/auth/sessions", token);
        using var listBody = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        Guid sessionId = listBody.RootElement.EnumerateArray().Single().GetProperty("id").GetGuid();

        var revokeResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/auth/sessions/{sessionId}/revoke", token, null);
        Assert.Equal(HttpStatusCode.NoContent, revokeResponse.StatusCode);

        var listAfterRevoke = await GetAuthorizedAsync("/api/auth/sessions", token);
        using var afterBody = JsonDocument.Parse(await listAfterRevoke.Content.ReadAsStringAsync());
        Assert.Empty(afterBody.RootElement.EnumerateArray());

        var refreshResponse = await _client.PostAsJsonAsync("/api/auth/refresh", new { RefreshToken = refreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refreshResponse.StatusCode);
    }

    [Fact]
    public async Task Revoke_a_nonexistent_session_returns_404()
    {
        var authHash = RandomBytes(32);
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test", authHash);

        var response = await SendAuthorizedAsync(HttpMethod.Post, $"/api/auth/sessions/{Guid.NewGuid()}/revoke", token, null);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Revoke_all_sessions_clears_the_active_list_and_blocks_every_refresh_token()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);

        using var login1 = await LoginAsync("admin@acme.test", authHash);
        string token1 = login1.RootElement.GetProperty("accessToken").GetString()!;
        string refresh1 = login1.RootElement.GetProperty("refreshToken").GetString()!;

        using var login2 = await LoginAsync("admin@acme.test", authHash);
        string refresh2 = login2.RootElement.GetProperty("refreshToken").GetString()!;

        var revokeAllResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/sessions/revoke-all", token1, null);
        Assert.Equal(HttpStatusCode.NoContent, revokeAllResponse.StatusCode);

        var listResponse = await GetAuthorizedAsync("/api/auth/sessions", token1);
        using var body = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        Assert.Empty(body.RootElement.EnumerateArray());

        var refreshResponse1 = await _client.PostAsJsonAsync("/api/auth/refresh", new { RefreshToken = refresh1 });
        Assert.Equal(HttpStatusCode.Unauthorized, refreshResponse1.StatusCode);

        var refreshResponse2 = await _client.PostAsJsonAsync("/api/auth/refresh", new { RefreshToken = refresh2 });
        Assert.Equal(HttpStatusCode.Unauthorized, refreshResponse2.StatusCode);
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

    private async Task<string> ProvisionAndLoginAsync(string slug, string adminEmail, byte[] authHash)
    {
        await ProvisionTenantAsync(slug, adminEmail, authHash);
        using var login = await LoginAsync(adminEmail, authHash);
        return login.RootElement.GetProperty("accessToken").GetString()!;
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
