using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for vault-core reads/writes: vaults,
/// folders, tags, and items (including the soft-delete trash lifecycle and the reveal-audit call).
/// <see cref="VaultItemResponse.EncryptedPayload"/> is always opaque ciphertext here — encryption/
/// decryption with the unlocked DEK happens in the calling page, never in this client.
/// </summary>
public sealed class VaultApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;

    public VaultApiClient(HttpClient http) => _http = http;

    public async Task<IReadOnlyList<VaultResponse>> ListVaultsAsync(CancellationToken ct = default)
    {
        var personal = _http.GetFromJsonAsync<IReadOnlyList<VaultResponse>>("/api/vaults", JsonOptions, ct);
        var organization = _http.GetFromJsonAsync<IReadOnlyList<VaultResponse>>("/api/vaults/organization", JsonOptions, ct);
        await Task.WhenAll(personal, organization);
        return [.. (await personal ?? []), .. (await organization ?? [])];
    }

    // ---- Folders ------------------------------------------------------------------------------

    public async Task<IReadOnlyList<FolderResponse>> ListFoldersAsync(Guid vaultId, CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<FolderResponse>>($"/api/vaults/{vaultId}/folders", JsonOptions, ct) ?? [];

    public async Task<FolderResponse> CreateFolderAsync(Guid vaultId, string name, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync($"/api/vaults/{vaultId}/folders", new { Name = name }, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<FolderResponse>(JsonOptions, ct))!;
    }

    // ---- Tags -----------------------------------------------------------------------------

    public async Task<IReadOnlyList<TagResponse>> ListTagsAsync(Guid vaultId, CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<TagResponse>>($"/api/vaults/{vaultId}/tags", JsonOptions, ct) ?? [];

    public async Task<TagResponse> CreateTagAsync(Guid vaultId, string name, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync($"/api/vaults/{vaultId}/tags", new { Name = name }, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TagResponse>(JsonOptions, ct))!;
    }

    public Task<HttpResponseMessage> AssignTagAsync(Guid vaultId, Guid itemId, Guid tagId, CancellationToken ct = default) =>
        _http.PostAsync($"/api/vaults/{vaultId}/items/{itemId}/tags/{tagId}", content: null, ct);

    // ---- Items ----------------------------------------------------------------------------

    public async Task<IReadOnlyList<VaultItemResponse>> ListItemsAsync(Guid vaultId, CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<VaultItemResponse>>($"/api/vaults/{vaultId}/items", JsonOptions, ct) ?? [];

    public async Task<IReadOnlyList<VaultItemResponse>> ListTrashAsync(Guid vaultId, CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<VaultItemResponse>>($"/api/vaults/{vaultId}/items/trash", JsonOptions, ct) ?? [];

    public async Task<VaultItemResponse> GetItemAsync(Guid vaultId, Guid itemId, CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<VaultItemResponse>($"/api/vaults/{vaultId}/items/{itemId}", JsonOptions, ct))!;

    public async Task<(bool Success, VaultItemResponse? Item, string? Error)> CreateItemAsync(
        Guid vaultId, string type, byte[] encryptedPayload, Guid? folderId, bool isFavorite, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            $"/api/vaults/{vaultId}/items",
            new { Type = type, EncryptedPayload = encryptedPayload, FolderId = folderId, IsFavorite = isFavorite },
            ct);

        if (!response.IsSuccessStatusCode)
        {
            var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
            return (false, null, problem?.Error ?? "Impossibile creare la voce.");
        }

        return (true, await response.Content.ReadFromJsonAsync<VaultItemResponse>(JsonOptions, ct), null);
    }

    public async Task<(bool Success, VaultItemResponse? Item, string? Error)> UpdateItemAsync(
        Guid vaultId, Guid itemId, string type, byte[] encryptedPayload, Guid? folderId, bool isFavorite, CancellationToken ct = default)
    {
        var response = await _http.PutAsJsonAsync(
            $"/api/vaults/{vaultId}/items/{itemId}",
            new { Type = type, EncryptedPayload = encryptedPayload, FolderId = folderId, IsFavorite = isFavorite },
            ct);

        if (!response.IsSuccessStatusCode)
        {
            var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
            return (false, null, problem?.Error ?? "Impossibile salvare la voce.");
        }

        return (true, await response.Content.ReadFromJsonAsync<VaultItemResponse>(JsonOptions, ct), null);
    }

    public async Task<bool> DeleteItemAsync(Guid vaultId, Guid itemId, CancellationToken ct = default) =>
        (await _http.DeleteAsync($"/api/vaults/{vaultId}/items/{itemId}", ct)).IsSuccessStatusCode;

    public async Task<bool> RestoreItemAsync(Guid vaultId, Guid itemId, CancellationToken ct = default) =>
        (await _http.PostAsync($"/api/vaults/{vaultId}/items/{itemId}/restore", content: null, ct)).IsSuccessStatusCode;

    public async Task<bool> PermanentlyDeleteItemAsync(Guid vaultId, Guid itemId, CancellationToken ct = default) =>
        (await _http.DeleteAsync($"/api/vaults/{vaultId}/items/{itemId}/permanent", ct)).IsSuccessStatusCode;

    /// <summary>Records that a sensitive field on this item was revealed to the user (audit trail only — the server never sees the plaintext).</summary>
    public Task RecordRevealAsync(Guid vaultId, Guid itemId, CancellationToken ct = default) =>
        _http.PostAsync($"/api/vaults/{vaultId}/items/{itemId}/reveal", content: null, ct);
}

public sealed record VaultResponse(Guid Id, string Name, bool IsOrganizationVault);

public sealed record FolderResponse(Guid Id, string Name);

public sealed record TagResponse(Guid Id, string Name);

public sealed record VaultItemResponse(
    Guid Id,
    string Type,
    byte[] EncryptedPayload,
    Guid? FolderId,
    bool IsFavorite,
    IReadOnlyList<Guid> TagIds,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? LastAccessedAt,
    bool IsDeleted,
    DateTimeOffset? DeletedAt);

/// <summary>Vault item type discriminator — kept as a plain string (not a shared enum type) since Web.Client cannot reference CffVaultManager.Domain.</summary>
public static class VaultItemTypes
{
    public const string Password = "Password";
    public const string CreditCard = "CreditCard";
    public const string SecureNote = "SecureNote";
    public const string GenericSecret = "GenericSecret";
    public const string CryptoWallet = "CryptoWallet";
}
