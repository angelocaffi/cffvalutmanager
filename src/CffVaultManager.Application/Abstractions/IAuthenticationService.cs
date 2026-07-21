using CffVaultManager.Application.Dtos.Authentication;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Drives the zero-knowledge login flow: password (auth hash) verification followed, when enabled,
/// by a TOTP second factor. Failures are always generic to avoid account enumeration.
/// </summary>
public interface IAuthenticationService
{
    /// <summary>
    /// Verifies the auth hash for <paramref name="email"/>. On success with MFA disabled, returns a
    /// full session (access + refresh token + crypto material). With MFA enabled, returns only a
    /// short-lived challenge. On failure, returns a generic failure without revealing the cause.
    /// </summary>
    Task<LoginResult> LoginAsync(string email, byte[] authHash, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Completes an MFA challenge: validates the challenge token and the TOTP code, and on success
    /// returns the full session.
    /// </summary>
    Task<LoginResult> VerifyMfaAsync(string challengeToken, string totpCode, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Rotates an opaque refresh token and mints a fresh access token for its owner. Returns a
    /// generic failure when the refresh token is unknown, already rotated/revoked, or expired.
    /// </summary>
    Task<LoginResult> RefreshAsync(string refreshToken, string? ip, string? userAgent, CancellationToken ct = default);
}
