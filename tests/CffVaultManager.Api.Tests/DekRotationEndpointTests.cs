using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of <c>POST /api/auth/rotate-dek</c> (see
/// docs/features/encryption-key-management.md "Rotazione DEK"): rotates the caller's personal DEK
/// without touching the master password.
/// </summary>
public sealed class DekRotationEndpointTests : IAsyncLifetime
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
    public async Task POST_rotate_dek_with_matching_set_returns_204_and_updates_the_item()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(token);
        Guid itemId = await CreateItemAsync(token, vaultId);

        byte[] newPayload = RandomBytes(32);
        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/rotate-dek", token, new
        {
            NewEncryptedDek = RandomBytes(48),
            ReencryptedItems = new[] { new { ItemId = itemId, EncryptedPayload = newPayload } },
        });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var getResponse = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items/{itemId}", token);
        using var body = JsonDocument.Parse(await getResponse.Content.ReadAsStringAsync());
        Assert.Equal(Convert.ToBase64String(newPayload), body.RootElement.GetProperty("encryptedPayload").GetString());
    }

    [Fact]
    public async Task POST_rotate_dek_with_a_missing_item_returns_409()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(token);
        await CreateItemAsync(token, vaultId);

        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/rotate-dek", token, new
        {
            NewEncryptedDek = RandomBytes(48),
            ReencryptedItems = Array.Empty<object>(),
        });
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task POST_rotate_dek_without_a_token_returns_401()
    {
        var response = await _client.PostAsJsonAsync("/api/auth/rotate-dek", new
        {
            NewEncryptedDek = RandomBytes(48),
            ReencryptedItems = Array.Empty<object>(),
        });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
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
