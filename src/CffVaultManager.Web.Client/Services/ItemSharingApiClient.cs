using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Live sharing of a single vault item with another user in the same tenant (see
/// docs/features/sharing-access-control.md "Condivisione live di singola voce"), independent of
/// which vault the item lives in. Local record types because <c>Web.Client</c> cannot reference
/// <c>CffVaultManager.Application</c>.
/// </summary>
public sealed class ItemSharingApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;

    public ItemSharingApiClient(HttpClient http) => _http = http;

    /// <summary>First share of an item: promotes it from vault-DEK encryption to a dedicated per-item key.</summary>
    public async Task<(bool Success, ItemMembershipResponse? Membership, string? Error)> ShareAsync(
        Guid vaultId, Guid itemId, string recipientEmail, string recipientPermission, byte[] reencryptedPayload,
        byte[] ownerWrappedItemKey, byte[] ownerEphemeralPublicKey, byte[] recipientWrappedItemKey, byte[] recipientEphemeralPublicKey,
        CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync($"/api/vaults/{vaultId}/items/{itemId}/share", new
        {
            RecipientEmail = recipientEmail,
            RecipientPermission = recipientPermission,
            ReencryptedPayload = reencryptedPayload,
            OwnerWrappedItemKey = ownerWrappedItemKey,
            OwnerEphemeralPublicKey = ownerEphemeralPublicKey,
            RecipientWrappedItemKey = recipientWrappedItemKey,
            RecipientEphemeralPublicKey = recipientEphemeralPublicKey,
        }, ct);

        if (!response.IsSuccessStatusCode)
        {
            var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
            return (false, null, problem?.Error ?? "Impossibile condividere la voce.");
        }

        return (true, await response.Content.ReadFromJsonAsync<ItemMembershipResponse>(JsonOptions, ct), null);
    }

    /// <summary>Adds another member to an already-shared item — the item key itself doesn't change. Owner-only.</summary>
    public async Task<(bool Success, ItemMembershipResponse? Membership, string? Error)> AddMemberAsync(
        Guid itemId, string recipientEmail, string permission, byte[] wrappedItemKey, byte[] ephemeralPublicKey, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync($"/api/items/{itemId}/memberships", new
        {
            RecipientEmail = recipientEmail,
            Permission = permission,
            WrappedItemKey = wrappedItemKey,
            EphemeralPublicKey = ephemeralPublicKey,
        }, ct);

        if (!response.IsSuccessStatusCode)
        {
            var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
            return (false, null, problem?.Error ?? "Impossibile aggiungere il destinatario.");
        }

        return (true, await response.Content.ReadFromJsonAsync<ItemMembershipResponse>(JsonOptions, ct), null);
    }

    /// <summary>Revokes a member and rotates the item key atomically. Owner-only.</summary>
    public async Task<(bool Success, string? Error)> RevokeAsync(
        Guid itemId, Guid revokedUserId, byte[] reencryptedPayload, IReadOnlyList<NewItemMembershipRequest> newMemberships, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync($"/api/items/{itemId}/memberships/{revokedUserId}/revoke", new
        {
            RevokedUserId = revokedUserId,
            ReencryptedPayload = reencryptedPayload,
            NewMemberships = newMemberships,
        }, ct);

        if (response.IsSuccessStatusCode)
        {
            return (true, null);
        }

        var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
        return (false, problem?.Error ?? "Impossibile revocare l'accesso.");
    }

    public async Task<IReadOnlyList<ItemMembershipResponse>> ListMembersAsync(Guid itemId, CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<ItemMembershipResponse>>($"/api/items/{itemId}/memberships", JsonOptions, ct) ?? [];

    /// <summary>Items shared with the caller by someone else (excludes items the caller owns — those already appear in their own vault).</summary>
    public async Task<IReadOnlyList<SharedItemResponse>> GetSharedWithMeAsync(CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<SharedItemResponse>>("/api/shared-items", JsonOptions, ct) ?? [];

    public async Task<SharedItemResponse?> GetSharedItemAsync(Guid itemId, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/api/shared-items/{itemId}", ct);
        return response.IsSuccessStatusCode
            ? await response.Content.ReadFromJsonAsync<SharedItemResponse>(JsonOptions, ct)
            : null;
    }

    /// <summary>Updates a shared item's ciphertext in place — same key, no rotation. Editor or Owner only.</summary>
    public Task<HttpResponseMessage> UpdateSharedItemAsync(Guid itemId, byte[] encryptedPayload, CancellationToken ct = default) =>
        _http.PutAsJsonAsync($"/api/shared-items/{itemId}", new { EncryptedPayload = encryptedPayload }, ct);

    /// <summary>Looks up a same-tenant user's public key by email, to wrap an item key for them.</summary>
    public async Task<byte[]?> GetPublicKeyByEmailAsync(string email, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/api/tenant/users/by-email/{Uri.EscapeDataString(email)}/public-key", ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var dto = await response.Content.ReadFromJsonAsync<PublicKeyResponse>(JsonOptions, ct);
        return dto?.PublicKey;
    }

    /// <summary>Looks up a same-tenant user's public key by id — used when rewrapping for remaining members on revoke.</summary>
    public async Task<byte[]?> GetPublicKeyByUserIdAsync(Guid userId, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/api/tenant/users/{userId}/public-key", ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var dto = await response.Content.ReadFromJsonAsync<PublicKeyResponse>(JsonOptions, ct);
        return dto?.PublicKey;
    }
}

public sealed record ItemMembershipResponse(Guid Id, Guid VaultItemId, Guid UserId, string Permission, DateTimeOffset CreatedAt);

public sealed record SharedItemResponse(
    Guid Id, string Type, byte[] EncryptedPayload, string MyPermission, byte[] MyWrappedItemKey, byte[] MyEphemeralPublicKey,
    Guid SharedByUserId, DateTimeOffset CreatedAt);

public sealed record NewItemMembershipRequest(Guid UserId, byte[] WrappedItemKey, byte[] EphemeralPublicKey);

public sealed record PublicKeyResponse(byte[] PublicKey);
