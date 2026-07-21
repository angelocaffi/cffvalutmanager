namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Email-ownership verification for newly registered users, via a short numeric one-time code.
/// Reuses the <c>OneTimeCode</c> entity scaffolded since Fase 0 for this and the (not yet built)
/// Email OTP MFA factor — see docs/features/authentication.md "Verifica email in registrazione" —
/// sharing its security guarantees (crypto RNG code, short expiry, single use, hashed at rest,
/// rate limited) without depending on that other feature existing yet.
/// </summary>
public interface IEmailVerificationService
{
    /// <summary>
    /// Generates and sends a fresh code to an already-known user — called right after
    /// registration completes. Not anti-enumeration-guarded: the caller already knows this user
    /// exists (it just created them).
    /// </summary>
    Task RequestAsync(Guid userId, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Client-triggered resend by email address. Anti-enumeration: always completes the same way
    /// whether the email is unknown, already verified, or still within its resend cooldown — a
    /// code is only actually (re)sent when none of those apply.
    /// </summary>
    Task ResendAsync(string email, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Verifies a code for the given email. Returns false uniformly for an unknown email, a
    /// wrong/expired code, or a code that already exhausted its attempt budget — the caller can
    /// never distinguish which case occurred.
    /// </summary>
    Task<bool> ConfirmAsync(string email, string code, string? ip, string? userAgent, CancellationToken ct = default);
}
