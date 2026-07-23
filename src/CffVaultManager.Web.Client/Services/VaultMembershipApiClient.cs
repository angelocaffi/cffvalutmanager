using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Organization-vault membership management (see docs/features/sharing-access-control.md): who has
/// access to a shared vault, inviting/revoking members, and looking up a same-tenant user's public
/// key to wrap the vault's DEK for them. Mirrors <see cref="ItemSharingApiClient"/> one level up
/// (vault DEK instead of a per-item key). Local record types because <c>Web.Client</c> cannot
/// reference <c>CffVaultManager.Application</c>.
/// </summary>
public sealed class VaultMembershipApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;

    public VaultMembershipApiClient(HttpClient http) => _http = http;

    /// <summary>The caller's own membership row for this vault, including their wrapped DEK. Null if the vault is personal, doesn't exist, or the caller isn't an active member.</summary>
    public async Task<MyVaultMembershipResponse?> GetMyMembershipAsync(Guid vaultId, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/api/vaults/{vaultId}/memberships/me", ct);
        return response.IsSuccessStatusCode
            ? await response.Content.ReadFromJsonAsync<MyVaultMembershipResponse>(JsonOptions, ct)
            : null;
    }

    public async Task<IReadOnlyList<VaultMembershipResponse>> ListMembersAsync(Guid vaultId, CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<VaultMembershipResponse>>($"/api/vaults/{vaultId}/memberships", JsonOptions, ct) ?? [];

    /// <summary>Invites a user to an organization vault. Owner-of-vault only (enforced server-side).</summary>
    public async Task<(bool Success, VaultMembershipResponse? Membership, string? Error)> InviteAsync(
        Guid vaultId, Guid userId, string permission, byte[] wrappedVaultDek, byte[] ephemeralPublicKey, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync($"/api/vaults/{vaultId}/memberships", new
        {
            UserId = userId,
            Permission = permission,
            WrappedVaultDek = wrappedVaultDek,
            EphemeralPublicKey = ephemeralPublicKey,
        }, ct);

        if (!response.IsSuccessStatusCode)
        {
            var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
            return (false, null, problem?.Error ?? "Impossibile invitare l'utente.");
        }

        return (true, await response.Content.ReadFromJsonAsync<VaultMembershipResponse>(JsonOptions, ct), null);
    }

    /// <summary>Revokes a member and rotates the vault DEK atomically. Owner-of-vault only.</summary>
    public async Task<(bool Success, string? Error)> RevokeAsync(
        Guid vaultId, Guid revokedUserId, IReadOnlyList<ReencryptedItemRequest> reencryptedItems,
        IReadOnlyList<NewVaultMembershipRequest> newMemberships, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync($"/api/vaults/{vaultId}/memberships/{revokedUserId}/revoke", new
        {
            RevokedUserId = revokedUserId,
            ReencryptedItems = reencryptedItems,
            NewMemberships = newMemberships,
        }, ct);

        if (response.IsSuccessStatusCode)
        {
            return (true, null);
        }

        var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
        return (false, problem?.Error ?? "Impossibile revocare l'accesso.");
    }

    /// <summary>Looks up a same-tenant user's public key (and id) by email, to invite them by address.</summary>
    public async Task<PublicKeyWithUserIdResponse?> GetPublicKeyByEmailAsync(string email, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/api/tenant/users/by-email/{Uri.EscapeDataString(email)}/public-key", ct);
        return response.IsSuccessStatusCode
            ? await response.Content.ReadFromJsonAsync<PublicKeyWithUserIdResponse>(JsonOptions, ct)
            : null;
    }

    /// <summary>Looks up a same-tenant user's public key by id — used when rewrapping the vault DEK for remaining members on revoke.</summary>
    public async Task<byte[]?> GetPublicKeyByUserIdAsync(Guid userId, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/api/tenant/users/{userId}/public-key", ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var dto = await response.Content.ReadFromJsonAsync<PublicKeyWithUserIdResponse>(JsonOptions, ct);
        return dto?.PublicKey;
    }
}

public sealed record VaultMembershipResponse(Guid Id, Guid VaultId, Guid UserId, string Permission, DateTimeOffset CreatedAt);

/// <summary>The caller's own membership row, including the wrapped vault DEK — never returned for another member's row.</summary>
public sealed record MyVaultMembershipResponse(Guid Id, Guid VaultId, string Permission, byte[] WrappedVaultDek, byte[] EphemeralPublicKey, DateTimeOffset CreatedAt);

public sealed record ReencryptedItemRequest(Guid ItemId, byte[] EncryptedPayload);

public sealed record NewVaultMembershipRequest(Guid UserId, byte[] WrappedVaultDek, byte[] EphemeralPublicKey);

public sealed record PublicKeyWithUserIdResponse(byte[] PublicKey, Guid UserId);
