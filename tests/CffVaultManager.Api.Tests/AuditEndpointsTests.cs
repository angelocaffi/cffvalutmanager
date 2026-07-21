using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the audit-trail HTTP surface: role-based visibility (Admin sees the
/// whole tenant, Operator sees only their own actions) and the client-triggered reveal event.
/// </summary>
public sealed class AuditEndpointsTests : IAsyncLifetime
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
    public async Task GET_audit_without_token_returns_401()
    {
        var response = await _client.GetAsync("/api/audit");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Admin_sees_both_their_own_and_the_operators_login_entries()
    {
        var adminAuthHash = RandomBytes(32);
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test", adminAuthHash);

        var operatorAuthHash = RandomBytes(32);
        await RegisterOperatorAsync(adminToken, "operator@acme.test", operatorAuthHash);
        await LoginAsync("operator@acme.test", operatorAuthHash);

        var response = await GetAuthorizedAsync("/api/audit?action=LoginSuccess", adminToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var entries = body.RootElement.EnumerateArray().ToList();

        // Both the admin's own login (from provisioning) and the operator's login are visible.
        Assert.Equal(2, entries.Count);
    }

    [Fact]
    public async Task Operator_sees_only_their_own_login_entries()
    {
        var adminAuthHash = RandomBytes(32);
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test", adminAuthHash);

        var operatorAuthHash = RandomBytes(32);
        await RegisterOperatorAsync(adminToken, "operator@acme.test", operatorAuthHash);
        string operatorToken = await LoginAsync("operator@acme.test", operatorAuthHash);

        var response = await GetAuthorizedAsync("/api/audit?action=LoginSuccess", operatorToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var entries = body.RootElement.EnumerateArray().ToList();

        Assert.Single(entries);
    }

    [Fact]
    public async Task Reveal_endpoint_records_an_entry_visible_via_GET_audit()
    {
        var authHash = RandomBytes(32);
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test", authHash);
        Guid vaultId = await GetOwnedVaultIdAsync(token);

        using var created = JsonDocument.Parse(await (await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", token, new
        {
            Type = "Password",
            EncryptedPayload = RandomBytes(16),
            FolderId = (Guid?)null,
            IsFavorite = false,
        })).Content.ReadAsStringAsync());
        Guid itemId = created.RootElement.GetProperty("id").GetGuid();

        var revealResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items/{itemId}/reveal", token, null);
        Assert.Equal(HttpStatusCode.NoContent, revealResponse.StatusCode);

        var response = await GetAuthorizedAsync("/api/audit?action=Revealed", token);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var entries = body.RootElement.EnumerateArray().ToList();

        Assert.Single(entries);
        Assert.Equal(itemId, entries[0].GetProperty("vaultItemId").GetGuid());
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task<string> ProvisionAndLoginAsync(string slug, string adminEmail, byte[] authHash)
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

        return await LoginAsync(adminEmail, authHash);
    }

    private async Task RegisterOperatorAsync(string adminToken, string email, byte[] authHash)
    {
        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/users", adminToken, new
        {
            Email = email,
            Role = "Operator",
            AuthHash = authHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private async Task<string> LoginAsync(string email, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash });
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("accessToken").GetString()!;
    }

    private async Task<Guid> GetOwnedVaultIdAsync(string token)
    {
        var response = await GetAuthorizedAsync("/api/vaults", token);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.EnumerateArray().First().GetProperty("id").GetGuid();
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
