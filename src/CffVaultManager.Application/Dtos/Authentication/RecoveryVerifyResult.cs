using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Result of a step in the recovery-kit flow (see docs/security-model.md#recovery-kit). Deliberately
/// not <c>LoginResult</c>: a different payload shape (no <c>CryptoMaterials</c>/session tokens) —
/// conflating the two would let a recovery-flow token be routed to a login endpoint or vice versa,
/// exactly the cross-endpoint issue the recovery-specific JWT purposes exist to prevent.
/// </summary>
public sealed record RecoveryVerifyResult
{
    private RecoveryVerifyResult()
    {
    }

    public bool Success { get; private init; }

    public bool RequiresMfa { get; private init; }

    public string? MfaChallengeToken { get; private init; }

    public IReadOnlyList<MfaFactor> AvailableMfaFactors { get; private init; } = [];

    /// <summary>Short-lived, scoped only to POST /api/auth/recovery/complete — see <c>IJwtTokenService.CreateRecoveryAuthorizedToken</c>.</summary>
    public string? RecoveryToken { get; private init; }

    public static RecoveryVerifyResult MfaRequired(string challengeToken, IReadOnlyList<MfaFactor> factors) =>
        new() { RequiresMfa = true, MfaChallengeToken = challengeToken, AvailableMfaFactors = factors };

    public static RecoveryVerifyResult Authorized(string recoveryToken) =>
        new() { Success = true, RecoveryToken = recoveryToken };

    public static RecoveryVerifyResult Failure() => new();
}
