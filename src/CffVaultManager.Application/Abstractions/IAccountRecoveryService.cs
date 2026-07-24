using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// The optional, opt-in recovery-kit flow — see docs/security-model.md#recovery-kit and
/// docs/features/authentication.md#recovery-kit for the full design. Lets a user regain access to
/// their vault without the master password, via a Recovery Key the server never sees, without
/// weakening zero-knowledge: the server only ever verifies a proof of possession
/// (<c>RecoveryAuthHash</c>) and stores an opaque, client-wrapped copy of the DEK.
/// </summary>
public interface IAccountRecoveryService
{
    /// <summary>Generates (or regenerates, overwriting any prior one) a kit for the authenticated caller.</summary>
    Task<bool> GenerateKitAsync(Guid userId, GenerateRecoveryKitRequest request, CancellationToken ct = default);

    /// <summary>
    /// Always returns a fixed-length, opaque blob — the real <c>RecoveryEncryptedDek</c> if the
    /// account and kit exist, otherwise a stable but fake one of the same shape (anti-enumeration,
    /// same principle as PreloginAsync's fake salt). Public, unauthenticated.
    /// </summary>
    Task<byte[]> StartAsync(string email, CancellationToken ct = default);

    /// <summary>
    /// Verifies proof of Recovery Key possession. On success, either an MFA challenge (if the
    /// account has any factor enabled) or a <c>RecoveryToken</c> directly. Public, unauthenticated,
    /// anti-enumeration (same failure shape for an unknown email, a kit-less account, or a wrong hash).
    /// </summary>
    Task<RecoveryVerifyResult> VerifyAsync(string email, byte[] recoveryAuthHash, string? ip, string? userAgent, CancellationToken ct = default);

    Task<RecoveryVerifyResult> VerifyMfaAsync(string challengeToken, string code, MfaFactor factor, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>Sends an Email OTP code for an in-progress recovery MFA challenge — mirrors <c>IAuthenticationService.RequestMfaEmailOtpAsync</c> but scoped to recovery's own challenge purpose.</summary>
    Task<bool> RequestMfaEmailOtpAsync(string challengeToken, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>Begins a WebAuthn assertion ceremony for an in-progress recovery MFA challenge. Null if the challenge token itself is invalid/expired.</summary>
    Task<string?> RequestWebAuthnAssertionOptionsAsync(string challengeToken, CancellationToken ct = default);

    Task<RecoveryVerifyResult> VerifyWebAuthnAsync(string challengeToken, string assertionResponseJson, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Applies the new master password, consumes the kit (clears <c>RecoveryEncryptedDek</c>/
    /// <c>RecoveryKeyHash</c>, keeps <c>RecoveryKitGeneratedAt</c> so /security can show "invalidated,
    /// regenerate"), revokes every session, and notifies the account owner. Public, requires a
    /// valid <c>RecoveryToken</c> (no separate authentication).
    /// </summary>
    Task<bool> CompleteAsync(RecoveryCompleteRequest request, CancellationToken ct = default);
}
