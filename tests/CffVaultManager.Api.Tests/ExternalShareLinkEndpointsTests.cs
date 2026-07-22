using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the external share-link HTTP surface (see
/// docs/features/sharing-access-control.md "Link di condivisione esterna"): creation, the public
/// anonymous read (no Authorization header at all), revocation, and listing. Business-rule coverage
/// lives in CffVaultManager.Infrastructure.Tests; these tests prove routes, status codes, and that the
/// read endpoint truly requires no authentication.
/// </summary>
public sealed class ExternalShareLinkEndpointsTests : IAsyncLifetime
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
    public async Task POST_share_link_as_owner_returns_201_with_a_token()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(token);
        Guid itemId = await CreateItemAsync(token, vaultId);

        var response = await CreateShareLinkAsync(token, vaultId, itemId, RandomBytes(32), 60);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("token").GetString()));
    }

    [Fact]
    public async Task GET_public_share_link_with_no_authorization_header_returns_the_content()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);
        byte[] payload = RandomBytes(32);

        var created = await CreateShareLinkAsync(ownerToken, vaultId, itemId, payload, 60);
        using var createdBody = JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        string shareToken = createdBody.RootElement.GetProperty("token").GetString()!;

        // No Authorization header at all — this must be a genuinely anonymous request.
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/share-links/{shareToken}");
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Convert.ToBase64String(payload), body.RootElement.GetProperty("encryptedPayload").GetString());
    }

    [Fact]
    public async Task GET_public_share_link_with_an_unknown_token_returns_404()
    {
        var response = await _client.GetAsync("/api/share-links/this-token-does-not-exist");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GET_public_share_link_after_revoke_returns_404()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);

        var created = await CreateShareLinkAsync(ownerToken, vaultId, itemId, RandomBytes(32), 60);
        using var createdBody = JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        string shareToken = createdBody.RootElement.GetProperty("token").GetString()!;
        Guid linkId = createdBody.RootElement.GetProperty("id").GetGuid();

        var revoke = await SendAuthorizedAsync(HttpMethod.Post,
            $"/api/vaults/{vaultId}/items/{itemId}/share-links/{linkId}/revoke", ownerToken, null);
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        var response = await _client.GetAsync($"/api/share-links/{shareToken}");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task POST_share_link_by_a_non_owner_returns_404()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);

        var strangerAuthHash = RandomBytes(32);
        await RegisterOperatorAsync(ownerToken, "stranger@acme.test", strangerAuthHash);
        string strangerToken = await LoginAsync("stranger@acme.test", strangerAuthHash);

        var response = await CreateShareLinkAsync(strangerToken, vaultId, itemId, RandomBytes(32), 60);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GET_share_links_for_item_lists_only_active_links()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);

        var active = await CreateShareLinkAsync(ownerToken, vaultId, itemId, RandomBytes(32), 60);
        using var activeBody = JsonDocument.Parse(await active.Content.ReadAsStringAsync());
        Guid activeId = activeBody.RootElement.GetProperty("id").GetGuid();

        var toRevoke = await CreateShareLinkAsync(ownerToken, vaultId, itemId, RandomBytes(32), 60);
        using var toRevokeBody = JsonDocument.Parse(await toRevoke.Content.ReadAsStringAsync());
        Guid revokedId = toRevokeBody.RootElement.GetProperty("id").GetGuid();
        await SendAuthorizedAsync(HttpMethod.Post,
            $"/api/vaults/{vaultId}/items/{itemId}/share-links/{revokedId}/revoke", ownerToken, null);

        var response = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items/{itemId}/share-links", ownerToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var ids = body.RootElement.EnumerateArray().Select(e => e.GetProperty("id").GetGuid()).ToList();

        Assert.Single(ids);
        Assert.Contains(activeId, ids);
        Assert.DoesNotContain(revokedId, ids);
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private Task<HttpResponseMessage> CreateShareLinkAsync(string token, Guid vaultId, Guid itemId, byte[] payload, int expiresInMinutes) =>
        SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items/{itemId}/share-links", token, new
        {
            EncryptedPayload = payload,
            ExpiresInMinutes = expiresInMinutes,
        });

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

        return await LoginAsync(adminEmail, authHash);
    }

    private async Task<string> LoginAsync(string email, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash });
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("accessToken").GetString()!;
    }

    private async Task<Guid> RegisterOperatorAsync(string adminToken, string email, byte[] authHash)
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
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("id").GetGuid();
    }

    private async Task<Guid> GetOwnedVaultIdAsync(string token)
    {
        var response = await GetAuthorizedAsync("/api/vaults", token);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.EnumerateArray().First().GetProperty("id").GetGuid();
    }

    private async Task<Guid> CreateItemAsync(string token, Guid vaultId)
    {
        var response = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", token, new
        {
            Type = "Password",
            EncryptedPayload = RandomBytes(32),
            FolderId = (Guid?)null,
            IsFavorite = false,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("id").GetGuid();
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
