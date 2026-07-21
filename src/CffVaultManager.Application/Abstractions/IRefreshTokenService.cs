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
}
