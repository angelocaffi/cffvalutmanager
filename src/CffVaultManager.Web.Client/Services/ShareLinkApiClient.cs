using System.Net.Http.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Time-limited anonymous links to a single vault item (see docs/features/sharing-access-control.md
/// "Link di condivisione esterna"). Local record types because <c>Web.Client</c> cannot reference
/// <c>CffVaultManager.Application</c>.
/// </summary>
public sealed class ShareLinkApiClient
{
    private readonly HttpClient _http;

    public ShareLinkApiClient(HttpClient http) => _http = http;

    /// <summary>Null on failure (network/non-2xx/unparseable body) — callers must check for null instead of assuming success.</summary>
    public async Task<ShareLinkResponse?> CreateAsync(
        Guid vaultId, Guid itemId, byte[] encryptedPayload, int expiresInMinutes, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            $"/api/vaults/{vaultId}/items/{itemId}/share-links",
            new { EncryptedPayload = encryptedPayload, ExpiresInMinutes = expiresInMinutes },
            ct);
        return await response.ReadJsonOrDefaultAsync<ShareLinkResponse>(ct);
    }

    public async Task<IReadOnlyList<ShareLinkResponse>> ListForItemAsync(Guid vaultId, Guid itemId, CancellationToken ct = default) =>
        await _http.GetJsonListOrEmptyAsync<ShareLinkResponse>($"/api/vaults/{vaultId}/items/{itemId}/share-links", ct);

    public Task<HttpResponseMessage> RevokeAsync(Guid vaultId, Guid itemId, Guid linkId, CancellationToken ct = default) =>
        _http.PostAsync($"/api/vaults/{vaultId}/items/{itemId}/share-links/{linkId}/revoke", content: null, ct);

    /// <summary>Anonymous read — no authentication, works even for a visitor who has never logged in. Null for an unknown/expired/revoked token.</summary>
    public async Task<ShareLinkContentResponse?> GetByTokenAsync(string token, CancellationToken ct = default) =>
        await _http.GetJsonOrDefaultAsync<ShareLinkContentResponse>($"/api/share-links/{Uri.EscapeDataString(token)}", ct);
}

public sealed record ShareLinkResponse(Guid Id, Guid VaultItemId, string Token, DateTimeOffset ExpiresAt, DateTimeOffset CreatedAt);

public sealed record ShareLinkContentResponse(byte[] EncryptedPayload, DateTimeOffset ExpiresAt);
