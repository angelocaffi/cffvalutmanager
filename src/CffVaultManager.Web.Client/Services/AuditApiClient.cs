namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for reading the caller's audit trail
/// (<c>GET /api/audit</c>). Never carries secret content, only action/timestamp/network metadata —
/// see docs/features/audit-log.md. The server already scopes results by role (Admin sees the whole
/// tenant, Operator only their own actions), so this client has no role-specific logic of its own.
/// </summary>
public sealed class AuditApiClient
{
    private readonly HttpClient _http;

    public AuditApiClient(HttpClient http) => _http = http;

    public async Task<IReadOnlyList<AuditLogEntryResponse>> ListAsync(
        string? action, int skip, int take, CancellationToken ct = default)
    {
        string url = $"/api/audit?skip={skip}&take={take}";
        if (!string.IsNullOrEmpty(action))
        {
            url += $"&action={Uri.EscapeDataString(action)}";
        }

        return await _http.GetJsonListOrEmptyAsync<AuditLogEntryResponse>(url, ct);
    }
}

public sealed record AuditLogEntryResponse(
    Guid Id,
    Guid UserId,
    Guid? VaultItemId,
    string Action,
    DateTimeOffset Timestamp,
    string? IpAddress,
    string? UserAgent);

/// <summary>Local mirror of Domain.Enums.AuditAction — see the layering note in VaultApiClient.VaultItemTypes.</summary>
public static class AuditActions
{
    public const string Created = "Created";
    public const string Viewed = "Viewed";
    public const string Updated = "Updated";
    public const string Deleted = "Deleted";
    public const string Shared = "Shared";
    public const string Revoked = "Revoked";
    public const string Revealed = "Revealed";
    public const string MfaEnabled = "MfaEnabled";
    public const string LoginSuccess = "LoginSuccess";
    public const string LoginFailed = "LoginFailed";
    public const string AccountLocked = "AccountLocked";
    public const string SessionsRevoked = "SessionsRevoked";
    public const string MfaChallenge = "MfaChallenge";
    public const string EmailOtpRequested = "EmailOtpRequested";
    public const string EmailOtpVerified = "EmailOtpVerified";
    public const string EmailOtpFailed = "EmailOtpFailed";
    public const string TenantProvisioned = "TenantProvisioned";
    public const string TenantSuspended = "TenantSuspended";
    public const string TenantReactivated = "TenantReactivated";
    public const string UserRoleChanged = "UserRoleChanged";
    public const string PermanentlyDeleted = "PermanentlyDeleted";
    public const string MasterPasswordChanged = "MasterPasswordChanged";
    public const string MfaEmailOtpEnabled = "MfaEmailOtpEnabled";
    public const string MfaEmailOtpDisabled = "MfaEmailOtpDisabled";
    public const string WebAuthnCredentialRegistered = "WebAuthnCredentialRegistered";
    public const string WebAuthnCredentialRemoved = "WebAuthnCredentialRemoved";
}
