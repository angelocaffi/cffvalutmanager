using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the vault-core HTTP surface (vaults/folders/tags/items) over real HTTP
/// against the real DI wiring in Program.cs. Business-rule coverage (ownership enforcement, sort
/// semantics, soft-delete lifecycle) already lives in CffVaultManager.Infrastructure.Tests; these
/// tests only prove the routes, status codes, and auth wiring are correct.
/// </summary>
public sealed class VaultCoreEndpointsTests : IAsyncLifetime
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
    public async Task Provisioning_creates_a_personal_vault_visible_via_GET_vaults()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");

        var response = await GetAuthorizedAsync("/api/vaults", token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var vaults = body.RootElement.EnumerateArray().ToList();
        Assert.Single(vaults);
        Assert.Equal("Personale", vaults[0].GetProperty("name").GetString());
        Assert.False(vaults[0].GetProperty("isOrganizationVault").GetBoolean());
    }

    [Fact]
    public async Task GET_vaults_without_token_returns_401()
    {
        var response = await _client.GetAsync("/api/vaults");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Folder_create_list_rename_delete_round_trips()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(token);

        var createResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/folders", token,
            new { Name = "Lavoro" });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        using var created = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        Guid folderId = created.RootElement.GetProperty("id").GetGuid();

        var listResponse = await GetAuthorizedAsync($"/api/vaults/{vaultId}/folders", token);
        using var listBody = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        Assert.Single(listBody.RootElement.EnumerateArray());

        var renameResponse = await SendAuthorizedAsync(HttpMethod.Put, $"/api/vaults/{vaultId}/folders/{folderId}", token,
            new { Name = "Personale" });
        Assert.Equal(HttpStatusCode.OK, renameResponse.StatusCode);
        using var renamed = JsonDocument.Parse(await renameResponse.Content.ReadAsStringAsync());
        Assert.Equal("Personale", renamed.RootElement.GetProperty("name").GetString());

        var deleteResponse = await SendAuthorizedAsync(HttpMethod.Delete, $"/api/vaults/{vaultId}/folders/{folderId}", token, null);
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

        var listAfterDelete = await GetAuthorizedAsync($"/api/vaults/{vaultId}/folders", token);
        using var afterDeleteBody = JsonDocument.Parse(await listAfterDelete.Content.ReadAsStringAsync());
        Assert.Empty(afterDeleteBody.RootElement.EnumerateArray());
    }

    [Fact]
    public async Task Folder_create_with_duplicate_name_returns_409()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(token);

        Assert.Equal(HttpStatusCode.Created,
            (await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/folders", token, new { Name = "Lavoro" })).StatusCode);

        var duplicate = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/folders", token, new { Name = "Lavoro" });
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
    }

    [Fact]
    public async Task Tag_create_list_rename_delete_round_trips()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(token);

        var createResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/tags", token,
            new { Name = "importante" });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        using var created = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        Guid tagId = created.RootElement.GetProperty("id").GetGuid();

        var renameResponse = await SendAuthorizedAsync(HttpMethod.Put, $"/api/vaults/{vaultId}/tags/{tagId}", token,
            new { Name = "urgente" });
        Assert.Equal(HttpStatusCode.OK, renameResponse.StatusCode);

        var deleteResponse = await SendAuthorizedAsync(HttpMethod.Delete, $"/api/vaults/{vaultId}/tags/{tagId}", token, null);
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

        var listAfterDelete = await GetAuthorizedAsync($"/api/vaults/{vaultId}/tags", token);
        using var afterDeleteBody = JsonDocument.Parse(await listAfterDelete.Content.ReadAsStringAsync());
        Assert.Empty(afterDeleteBody.RootElement.EnumerateArray());
    }

    [Fact]
    public async Task VaultItem_create_get_update_and_tag_assignment_round_trip()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(token);

        using var tagResponse = JsonDocument.Parse(await (await SendAuthorizedAsync(
            HttpMethod.Post, $"/api/vaults/{vaultId}/tags", token, new { Name = "importante" })).Content.ReadAsStringAsync());
        Guid tagId = tagResponse.RootElement.GetProperty("id").GetGuid();

        var createResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", token, new
        {
            Type = "Password",
            EncryptedPayload = RandomBytes(32),
            FolderId = (Guid?)null,
            IsFavorite = false,
        });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        using var created = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        Guid itemId = created.RootElement.GetProperty("id").GetGuid();

        var assignTagResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items/{itemId}/tags/{tagId}", token, null);
        Assert.Equal(HttpStatusCode.NoContent, assignTagResponse.StatusCode);

        var getResponse = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items/{itemId}", token);
        using var getBody = JsonDocument.Parse(await getResponse.Content.ReadAsStringAsync());
        var tagIds = getBody.RootElement.GetProperty("tagIds").EnumerateArray().Select(e => e.GetGuid()).ToList();
        Assert.Contains(tagId, tagIds);

        var updateResponse = await SendAuthorizedAsync(HttpMethod.Put, $"/api/vaults/{vaultId}/items/{itemId}", token, new
        {
            Type = "Password",
            EncryptedPayload = RandomBytes(32),
            FolderId = (Guid?)null,
            IsFavorite = true,
        });
        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
        using var updated = JsonDocument.Parse(await updateResponse.Content.ReadAsStringAsync());
        Assert.True(updated.RootElement.GetProperty("isFavorite").GetBoolean());

        var removeTagResponse = await SendAuthorizedAsync(HttpMethod.Delete, $"/api/vaults/{vaultId}/items/{itemId}/tags/{tagId}", token, null);
        Assert.Equal(HttpStatusCode.NoContent, removeTagResponse.StatusCode);
    }

    [Fact]
    public async Task VaultItem_list_can_be_filtered_by_favorite()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(token);

        await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", token, new
        {
            Type = "Password",
            EncryptedPayload = RandomBytes(16),
            FolderId = (Guid?)null,
            IsFavorite = true,
        });
        await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", token, new
        {
            Type = "Password",
            EncryptedPayload = RandomBytes(16),
            FolderId = (Guid?)null,
            IsFavorite = false,
        });

        var response = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items?favorite=true", token);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var items = body.RootElement.EnumerateArray().ToList();
        Assert.Single(items);
        Assert.True(items[0].GetProperty("isFavorite").GetBoolean());
    }

    [Fact]
    public async Task VaultItem_soft_delete_restore_and_permanent_delete_lifecycle()
    {
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await GetOwnedVaultIdAsync(token);

        using var created = JsonDocument.Parse(await (await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", token, new
        {
            Type = "SecureNote",
            EncryptedPayload = RandomBytes(16),
            FolderId = (Guid?)null,
            IsFavorite = false,
        })).Content.ReadAsStringAsync());
        Guid itemId = created.RootElement.GetProperty("id").GetGuid();

        var deleteResponse = await SendAuthorizedAsync(HttpMethod.Delete, $"/api/vaults/{vaultId}/items/{itemId}", token, null);
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

        var listResponse = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items", token);
        using var listBody = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        Assert.Empty(listBody.RootElement.EnumerateArray());

        var trashResponse = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items/trash", token);
        using var trashBody = JsonDocument.Parse(await trashResponse.Content.ReadAsStringAsync());
        Assert.Single(trashBody.RootElement.EnumerateArray());

        var restoreResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items/{itemId}/restore", token, null);
        Assert.Equal(HttpStatusCode.NoContent, restoreResponse.StatusCode);

        var listAfterRestore = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items", token);
        using var listAfterRestoreBody = JsonDocument.Parse(await listAfterRestore.Content.ReadAsStringAsync());
        Assert.Single(listAfterRestoreBody.RootElement.EnumerateArray());

        // Permanent delete is only valid on an already-trashed item.
        var invalidPermanentDelete = await SendAuthorizedAsync(HttpMethod.Delete, $"/api/vaults/{vaultId}/items/{itemId}/permanent", token, null);
        Assert.Equal(HttpStatusCode.Conflict, invalidPermanentDelete.StatusCode);

        await SendAuthorizedAsync(HttpMethod.Delete, $"/api/vaults/{vaultId}/items/{itemId}", token, null);
        var permanentDelete = await SendAuthorizedAsync(HttpMethod.Delete, $"/api/vaults/{vaultId}/items/{itemId}/permanent", token, null);
        Assert.Equal(HttpStatusCode.NoContent, permanentDelete.StatusCode);

        var getAfterPermanentDelete = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items/{itemId}", token);
        Assert.Equal(HttpStatusCode.NotFound, getAfterPermanentDelete.StatusCode);
    }

    [Fact]
    public async Task Another_users_vault_is_invisible_and_returns_404_not_403()
    {
        string ownerToken = await ProvisionAndLoginAsync("acme", "owner@acme.test");
        Guid ownerVaultId = await GetOwnedVaultIdAsync(ownerToken);

        var intruderAuthHash = RandomBytes(32);
        var registerResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/users", ownerToken, new
        {
            Email = "intruder@acme.test",
            Role = "Operator",
            AuthHash = intruderAuthHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, registerResponse.StatusCode);
        string intruderToken = await LoginAsync("intruder@acme.test", intruderAuthHash);

        // The owner's vault is a different personal vault: even a same-tenant Operator must not
        // be able to read/write it (personal-vault ownership, not tenant membership, is the gate).
        var listFolders = await GetAuthorizedAsync($"/api/vaults/{ownerVaultId}/folders", intruderToken);
        Assert.Equal(HttpStatusCode.NotFound, listFolders.StatusCode);

        var createFolder = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{ownerVaultId}/folders", intruderToken, new { Name = "Hack" });
        Assert.Equal(HttpStatusCode.NotFound, createFolder.StatusCode);
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

        return await LoginAsync(adminEmail, authHash);
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
