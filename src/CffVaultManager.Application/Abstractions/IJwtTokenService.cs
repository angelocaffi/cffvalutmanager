using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Issues and validates the platform's JWTs. The full access token carries the caller's tenant
/// and role; the MFA-challenge token deliberately carries neither, so a stolen challenge token
/// cannot be used as an access token.
/// </summary>
public interface IJwtTokenService
{
    /// <summary>
    /// Creates a full access JWT (<c>sub</c>, <c>tenant_id</c> unless null, <c>role</c>, <c>jti</c>,
    /// <c>iat</c>/<c>exp</c>, optional <c>purpose</c>).
    /// </summary>
    string CreateAccessToken(Guid userId, Guid? tenantId, UserRole role, TimeSpan lifetime, string? purpose = null);

    /// <summary>
    /// Creates a short-lived MFA-challenge JWT carrying only <c>sub</c> and <c>purpose=mfa_challenge</c>.
    /// </summary>
    string CreateMfaChallengeToken(Guid userId, TimeSpan lifetime);

    /// <summary>
    /// Validates a token's signature and lifetime and, when <paramref name="expectedPurpose"/> is
    /// supplied, that its <c>purpose</c> matches. Returns null when the token is invalid, expired,
    /// or the purpose does not match.
    /// </summary>
    Task<JwtClaims?> ValidateAsync(string token, string? expectedPurpose = null);
}
