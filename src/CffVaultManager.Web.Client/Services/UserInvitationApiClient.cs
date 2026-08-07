using System.Net.Http.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for <c>/api/tenant/users/*</c> (see
/// docs/features/roles-permissions.md "Invito di nuovi utenti"): tenant-Admin user management and
/// the public accept-invitation flow.
/// </summary>
public sealed class UserInvitationApiClient
{
    private readonly HttpClient _http;

    public UserInvitationApiClient(HttpClient http) => _http = http;

    public async Task<IReadOnlyList<TenantUserResponse>> ListUsersAsync(CancellationToken ct = default) =>
        await _http.GetJsonListOrEmptyAsync<TenantUserResponse>("/api/tenant/users", ct);

    public async Task<IReadOnlyList<PendingInvitationResponse>> ListPendingInvitationsAsync(CancellationToken ct = default) =>
        await _http.GetJsonListOrEmptyAsync<PendingInvitationResponse>("/api/tenant/users/invitations", ct);

    public async Task<(bool Success, string? Error)> InviteAsync(string email, string role, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/tenant/users/invitations", new { Email = email, Role = role }, ct);
        if (response.IsSuccessStatusCode)
        {
            return (true, null);
        }

        return (false, await response.ReadErrorOrAsync("Impossibile inviare l'invito.", ct));
    }

    public async Task<bool> RevokeInvitationAsync(Guid invitationId, CancellationToken ct = default) =>
        (await _http.PostAsync($"/api/tenant/users/invitations/{invitationId}/revoke", content: null, ct)).IsSuccessStatusCode;

    public async Task<InvitationPreviewResponse?> GetInvitationPreviewAsync(string token, CancellationToken ct = default) =>
        await _http.GetJsonOrDefaultAsync<InvitationPreviewResponse>($"/api/tenant/users/invitations/{token}", ct);

    public async Task<(bool Success, string? Error)> CompleteInvitationAsync(
        string token, byte[] authHash, byte[] encryptedDek, byte[] masterPasswordSalt,
        int kdfMemoryKb, int kdfIterations, int kdfVersion, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            $"/api/tenant/users/invitations/{token}/complete",
            new { AuthHash = authHash, EncryptedDek = encryptedDek, MasterPasswordSalt = masterPasswordSalt, KdfMemoryKb = kdfMemoryKb, KdfIterations = kdfIterations, KdfVersion = kdfVersion },
            ct);

        return response.IsSuccessStatusCode
            ? (true, null)
            : (false, "Invito non valido, scaduto o già utilizzato.");
    }
}

public sealed record TenantUserResponse(Guid Id, string Email, string Role, DateTimeOffset CreatedAt);

public sealed record PendingInvitationResponse(Guid Id, string Email, string Role, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);

public sealed record InvitationPreviewResponse(string TenantName, string Role, string InvitedByEmail);
