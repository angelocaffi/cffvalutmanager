using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Outcome of a login or MFA-verification attempt. A failure never says whether the email
/// existed or the auth hash was wrong (anti-enumeration): callers only see the generic
/// <see cref="FailureReason"/>. Crypto material is attached only on a fully authenticated result.
/// </summary>
public sealed record LoginResult
{
    private LoginResult()
    {
    }

    public bool Success { get; private init; }

    /// <summary>True when only an MFA challenge was issued and a second factor is still required.</summary>
    public bool RequiresMfa { get; private init; }

    /// <summary>Generic, non-specific message when <see cref="Success"/> is false. Never leaks which check failed.</summary>
    public string? FailureReason { get; private init; }

    /// <summary>Full access JWT, present only on a fully authenticated result.</summary>
    public string? AccessToken { get; private init; }

    /// <summary>Opaque refresh token in clear text (never persisted in clear), present only when fully authenticated.</summary>
    public string? RefreshToken { get; private init; }

    /// <summary>Short-lived challenge JWT, present only when <see cref="RequiresMfa"/> is true.</summary>
    public string? MfaChallengeToken { get; private init; }

    /// <summary>
    /// The factor(s) the user has registered and may complete the challenge with, present only
    /// when <see cref="RequiresMfa"/> is true — lets the client offer a choice (or send the Email
    /// OTP code) when more than one is enabled.
    /// </summary>
    public IReadOnlyList<MfaFactor> AvailableMfaFactors { get; private init; } = Array.Empty<MfaFactor>();

    /// <summary>Zero-knowledge material for the client, present only on a fully authenticated result.</summary>
    public CryptoMaterials? CryptoMaterials { get; private init; }

    /// <summary>
    /// The account's own email, present only on a fully authenticated result. Every login path
    /// already has it server-side; the client only strictly needs it for passwordless passkey
    /// login, which never had the user type one (every other flow already knows it locally, from
    /// the form the user filled in).
    /// </summary>
    public string? Email { get; private init; }

    public static LoginResult Authenticated(string accessToken, string refreshToken, CryptoMaterials materials, string? email = null) => new()
    {
        Success = true,
        AccessToken = accessToken,
        RefreshToken = refreshToken,
        CryptoMaterials = materials,
        Email = email,
    };

    public static LoginResult MfaRequired(string challengeToken, IReadOnlyList<MfaFactor> availableFactors) => new()
    {
        Success = false,
        RequiresMfa = true,
        MfaChallengeToken = challengeToken,
        AvailableMfaFactors = availableFactors,
    };

    public static LoginResult Failure(string reason = "Invalid credentials.") => new()
    {
        Success = false,
        FailureReason = reason,
    };
}
