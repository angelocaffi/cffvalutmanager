namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Best-effort security email alerts for events a user should know about even when they weren't
/// the one at the keyboard (e.g. a stolen session) — see docs/features/notifications.md. Scoped
/// deliberately to events the server can observe on its own; alerts that would require decrypting
/// vault content (card expiry, breached passwords) are out of scope, since the server must never
/// do that (docs/security-model.md). Never includes secret content, only a description of what
/// happened. A delivery failure here must never fail the underlying operation — same "best
/// effort, after the real state change is already committed" framing already used by
/// IEmailVerificationService/IEmailOtpMfaService.
/// </summary>
public interface ISecurityNotificationService
{
    /// <summary>Alerts the user only if <paramref name="ip"/> has never appeared on a previous successful login for this account.</summary>
    Task NotifyLoginIfNewIpAsync(Guid userId, string? ip, string? userAgent, CancellationToken ct = default);

    Task NotifyMasterPasswordChangedAsync(Guid userId, CancellationToken ct = default);

    /// <summary><paramref name="factorDescription"/> is a human-readable label (e.g. "Email OTP", "una passkey") — never a secret.</summary>
    Task NotifyMfaFactorDisabledAsync(Guid userId, string factorDescription, CancellationToken ct = default);

    /// <summary>A recovery kit was successfully used to reset the master password — see docs/security-model.md#recovery-kit.</summary>
    Task NotifyAccountRecoveredAsync(Guid userId, CancellationToken ct = default);

    /// <summary>A DEK rotation silently invalidated an existing recovery kit; the user should regenerate one if they still want it.</summary>
    Task NotifyRecoveryKitInvalidatedAsync(Guid userId, CancellationToken ct = default);

    /// <summary>A DEK rotation invalidated one or more passwordless-passkey wrapped DEK copies; the user should re-enable it per device if they still want it (docs/security-model.md#sblocco-senza-password-via-passkey-webauthn-prf).</summary>
    Task NotifyPasskeyLoginInvalidatedAsync(Guid userId, CancellationToken ct = default);
}
