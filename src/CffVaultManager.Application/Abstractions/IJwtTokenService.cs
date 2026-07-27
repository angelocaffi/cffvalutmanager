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
    /// <c>iat</c>/<c>exp</c>, optional <c>purpose</c>, optional <c>tenant_read_only</c> when
    /// <paramref name="isReadOnly"/> is true — see docs/features/billing.md).
    /// </summary>
    string CreateAccessToken(Guid userId, Guid? tenantId, UserRole role, TimeSpan lifetime, string? purpose = null, bool isReadOnly = false);

    /// <summary>
    /// Creates a short-lived challenge JWT carrying only <c>sub</c> and <c>purpose</c> (e.g.
    /// login's "mfa_challenge" or recovery's own, distinct purpose — see
    /// <c>JwtTokenService.RecoveryMfaChallengePurpose</c>). <paramref name="purpose"/> is required
    /// here (not defaulted) because the concrete implementation's own purpose constants are
    /// <c>internal</c> to Infrastructure and cannot be referenced from this Application-layer
    /// interface; callers within Infrastructure pass them explicitly.
    /// </summary>
    string CreateMfaChallengeToken(Guid userId, TimeSpan lifetime, string purpose);

    /// <summary>
    /// Creates a short-lived JWT proving the caller completed the recovery-kit flow (Recovery Key
    /// possession + MFA if enabled) — see docs/security-model.md#recovery-kit. Same minimal-claims
    /// shape as the MFA-challenge token (only <c>sub</c>+<c>purpose</c>+<c>jti</c>, no tenant/role):
    /// a stolen token must not confer any access beyond submitting a new master password.
    /// </summary>
    string CreateRecoveryAuthorizedToken(Guid userId, TimeSpan lifetime);

    /// <summary>
    /// Validates a token's signature and lifetime and, when <paramref name="expectedPurpose"/> is
    /// supplied, that its <c>purpose</c> matches. Returns null when the token is invalid, expired,
    /// or the purpose does not match.
    /// </summary>
    Task<JwtClaims?> ValidateAsync(string token, string? expectedPurpose = null);
}
