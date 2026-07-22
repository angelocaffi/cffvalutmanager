using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the live per-item sharing HTTP surface (see
/// docs/features/sharing-access-control.md "Condivisione live di singola voce"): first share
/// (promotion), adding/revoking members, listing, the "shared with me" feed, and the by-email
/// public-key lookup. Business-rule coverage lives in CffVaultManager.Infrastructure.Tests; these
/// tests prove routes, status codes, and auth wiring over real HTTP.
/// </summary>
public sealed class ItemMembershipEndpointsTests : IAsyncLifetime
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
    public async Task POST_share_promotes_the_item_and_returns_201()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "owner@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);
        Guid recipientId = await RegisterOperatorAsync(ownerToken, "recipient@acme.test", RandomBytes(32));
        await SetPublicKeyAsync(recipientId, RandomBytes(32));

        var response = await ShareAsync(ownerToken, vaultId, itemId, "recipient@acme.test");
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(recipientId, body.RootElement.GetProperty("userId").GetGuid());
        Assert.Equal("Viewer", body.RootElement.GetProperty("permission").GetString());
    }

    [Fact]
    public async Task POST_share_with_a_recipient_with_no_key_pair_returns_409()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "owner@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);
        await RegisterOperatorAsync(ownerToken, "recipient@acme.test", RandomBytes(32));

        var response = await ShareAsync(ownerToken, vaultId, itemId, "recipient@acme.test");
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task GET_shared_items_shows_the_item_for_the_recipient_but_not_the_owner()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "owner@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);
        var recipientAuthHash = RandomBytes(32);
        Guid recipientId = await RegisterOperatorAsync(ownerToken, "recipient@acme.test", recipientAuthHash);
        await SetPublicKeyAsync(recipientId, RandomBytes(32));
        Assert.Equal(HttpStatusCode.Created, (await ShareAsync(ownerToken, vaultId, itemId, "recipient@acme.test")).StatusCode);

        string recipientToken = await LoginAsync("recipient@acme.test", recipientAuthHash);
        var recipientFeed = await GetAuthorizedAsync("/api/shared-items", recipientToken);
        using var recipientBody = JsonDocument.Parse(await recipientFeed.Content.ReadAsStringAsync());
        var recipientIds = recipientBody.RootElement.EnumerateArray().Select(e => e.GetProperty("id").GetGuid()).ToList();
        Assert.Contains(itemId, recipientIds);

        var ownerFeed = await GetAuthorizedAsync("/api/shared-items", ownerToken);
        using var ownerBody = JsonDocument.Parse(await ownerFeed.Content.ReadAsStringAsync());
        Assert.Empty(ownerBody.RootElement.EnumerateArray());
    }

    [Fact]
    public async Task GET_shared_item_by_a_non_member_returns_404()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "owner@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);
        var strangerAuthHash = RandomBytes(32);
        await RegisterOperatorAsync(ownerToken, "stranger@acme.test", strangerAuthHash);
        string strangerToken = await LoginAsync("stranger@acme.test", strangerAuthHash);

        var response = await GetAuthorizedAsync($"/api/shared-items/{itemId}", strangerToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task PUT_shared_item_by_a_Viewer_returns_403_while_Editor_succeeds()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "owner@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);

        var viewerAuthHash = RandomBytes(32);
        Guid viewerId = await RegisterOperatorAsync(ownerToken, "viewer@acme.test", viewerAuthHash);
        await SetPublicKeyAsync(viewerId, RandomBytes(32));
        Assert.Equal(HttpStatusCode.Created, (await ShareAsync(ownerToken, vaultId, itemId, "viewer@acme.test")).StatusCode);
        string viewerToken = await LoginAsync("viewer@acme.test", viewerAuthHash);

        var viewerUpdate = await SendAuthorizedAsync(HttpMethod.Put, $"/api/shared-items/{itemId}", viewerToken, new
        {
            EncryptedPayload = RandomBytes(32),
        });
        Assert.Equal(HttpStatusCode.Forbidden, viewerUpdate.StatusCode);

        var editorAuthHash = RandomBytes(32);
        Guid editorId = await RegisterOperatorAsync(ownerToken, "editor@acme.test", editorAuthHash);
        await SetPublicKeyAsync(editorId, RandomBytes(32));
        var addEditor = await SendAuthorizedAsync(HttpMethod.Post, $"/api/items/{itemId}/memberships", ownerToken, new
        {
            RecipientEmail = "editor@acme.test",
            Permission = "Editor",
            WrappedItemKey = RandomBytes(48),
            EphemeralPublicKey = RandomBytes(32),
        });
        Assert.Equal(HttpStatusCode.Created, addEditor.StatusCode);
        string editorToken = await LoginAsync("editor@acme.test", editorAuthHash);

        var editorUpdate = await SendAuthorizedAsync(HttpMethod.Put, $"/api/shared-items/{itemId}", editorToken, new
        {
            EncryptedPayload = RandomBytes(32),
        });
        Assert.Equal(HttpStatusCode.NoContent, editorUpdate.StatusCode);
    }

    [Fact]
    public async Task POST_revoke_by_the_owner_with_matching_set_returns_204_and_removes_access()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "owner@acme.test");
        Guid ownerId = await GetUserIdByEmailAsync("owner@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(ownerToken);
        Guid itemId = await CreateItemAsync(ownerToken, vaultId);

        var viewerAuthHash = RandomBytes(32);
        Guid viewerId = await RegisterOperatorAsync(ownerToken, "viewer@acme.test", viewerAuthHash);
        await SetPublicKeyAsync(viewerId, RandomBytes(32));
        Assert.Equal(HttpStatusCode.Created, (await ShareAsync(ownerToken, vaultId, itemId, "viewer@acme.test")).StatusCode);

        var revoke = await SendAuthorizedAsync(HttpMethod.Post, $"/api/items/{itemId}/memberships/{viewerId}/revoke", ownerToken, new
        {
            RevokedUserId = viewerId,
            ReencryptedPayload = RandomBytes(32),
            NewMemberships = new[]
            {
                new { UserId = ownerId, WrappedItemKey = RandomBytes(48), EphemeralPublicKey = RandomBytes(32) },
            },
        });
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        string viewerToken = await LoginAsync("viewer@acme.test", viewerAuthHash);
        var afterRevoke = await GetAuthorizedAsync($"/api/shared-items/{itemId}", viewerToken);
        Assert.Equal(HttpStatusCode.NotFound, afterRevoke.StatusCode);
    }

    [Fact]
    public async Task GET_public_key_by_email_for_a_user_without_a_keypair_returns_422()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "owner@acme.test");
        await RegisterOperatorAsync(ownerToken, "recipient@acme.test", RandomBytes(32));

        var response = await GetAuthorizedAsync("/api/tenant/users/by-email/recipient@acme.test/public-key", ownerToken);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
    }

    [Fact]
    public async Task GET_public_key_by_email_after_key_is_set_returns_200()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "owner@acme.test");
        Guid recipientId = await RegisterOperatorAsync(ownerToken, "recipient@acme.test", RandomBytes(32));
        var publicKey = RandomBytes(32);
        await SetPublicKeyAsync(recipientId, publicKey);

        var response = await GetAuthorizedAsync("/api/tenant/users/by-email/recipient@acme.test/public-key", ownerToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Convert.ToBase64String(publicKey), body.RootElement.GetProperty("publicKey").GetString());
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private Task<HttpResponseMessage> ShareAsync(string ownerToken, Guid vaultId, Guid itemId, string recipientEmail) =>
        SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items/{itemId}/share", ownerToken, new
        {
            RecipientEmail = recipientEmail,
            RecipientPermission = "Viewer",
            ReencryptedPayload = RandomBytes(32),
            OwnerWrappedItemKey = RandomBytes(48),
            OwnerEphemeralPublicKey = RandomBytes(32),
            RecipientWrappedItemKey = RandomBytes(48),
            RecipientEphemeralPublicKey = RandomBytes(32),
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

    private async Task<Guid> GetUserIdByEmailAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CffVaultManagerDbContext>();
        var user = await db.Users.IgnoreQueryFilters().SingleAsync(u => u.Email == email);
        return user.Id;
    }

    private async Task SetPublicKeyAsync(Guid userId, byte[] publicKey)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CffVaultManagerDbContext>();
        var user = await db.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        user.PublicKey = publicKey;
        await db.SaveChangesAsync();
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
