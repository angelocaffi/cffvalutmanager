namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Email OTP as an MFA factor (docs/features/authentication.md "Email OTP come fattore MFA") —
/// distinct from email-ownership verification at registration (<see cref="IEmailVerificationService"/>),
/// though it reuses the same <c>OneTimeCode</c> infrastructure with <c>OtpPurpose.MfaLogin</c>.
/// Never produces a cryptographic key and never replaces the master password: it is always an
/// additional check layered on top of a successful password verification.
/// </summary>
public interface IEmailOtpMfaService
{
    /// <summary>
    /// Enables Email OTP as a login factor for the user. Requires the account's email to already
    /// be verified (<see cref="IEmailVerificationService"/>) — otherwise the code would be sent to
    /// an address nobody has proven ownership of.
    /// </summary>
    Task EnableAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Disables Email OTP as a login factor for the user.</summary>
    Task DisableAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Generates and emails a fresh code for an in-progress MFA challenge. A no-op if the user has
    /// not enabled this factor, or if the last code for this user was requested within the resend
    /// cooldown — the caller (an MFA challenge endpoint reachable without further authentication)
    /// gets a uniform response regardless.
    /// </summary>
    Task SendChallengeCodeAsync(Guid userId, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Verifies a code against the current pending Email OTP challenge for the user. Returns false
    /// uniformly when the factor is not enabled, no code is pending, the code is wrong/expired, or
    /// its attempt budget is exhausted.
    /// </summary>
    Task<bool> VerifyChallengeCodeAsync(Guid userId, string code, string? ip, string? userAgent, CancellationToken ct = default);
}
