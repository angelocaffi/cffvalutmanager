using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Issues and rotates opaque refresh tokens. Only the SHA-256 hash of a token is ever persisted,
/// so a database leak cannot be replayed; rotation records the successor so token reuse can be
/// detected and the chain invalidated.
/// </summary>
public interface IRefreshTokenService
{
    Task<IssuedRefreshToken> IssueAsync(Guid userId, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Validates <paramref name="plainToken"/>, and on success revokes it and issues a replacement.
    /// Returns null when the token is unknown, already revoked/rotated, or expired.
    /// </summary>
    Task<IssuedRefreshToken?> ValidateAndRotateAsync(string plainToken, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>Lists the caller's own active (non-revoked, non-expired) sessions, newest first. Never exposes the token or its hash.</summary>
    Task<IReadOnlyList<ActiveSessionDto>> ListActiveSessionsAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Revokes a single session the caller owns (idempotent — a no-op if already revoked or
    /// expired). Throws <see cref="KeyNotFoundException"/> if no such session belongs to this user.
    /// Does not invalidate an already-issued access token (see docs/features/authentication.md
    /// "Logout remoto" for the accepted residual window).
    /// </summary>
    Task RevokeSessionAsync(Guid userId, Guid? tenantId, Guid sessionId, CancellationToken ct = default);

    /// <summary>Revokes every active session the caller owns ("logout remoto" — e.g. on suspected compromise).</summary>
    Task RevokeAllSessionsAsync(Guid userId, Guid? tenantId, CancellationToken ct = default);
}
