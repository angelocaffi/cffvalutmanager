using CffVaultManager.Application.Dtos.Authentication;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// WebAuthn/FIDO2 as an MFA factor (docs/features/authentication.md — biometric/platform
/// authenticator login). A user may register several credentials (one per device); presence of
/// any is what makes <c>MfaFactor.WebAuthn</c> available at login, mirroring how
/// <c>MfaFactor.EmailOtp</c> is gated by <c>User.MfaEmailOtpEnabled</c> but for a factor with no
/// single on/off flag. JSON payloads in/out are the browser's raw <c>navigator.credentials</c>
/// request/response shapes (<c>CredentialCreateOptions</c>/<c>AssertionOptions</c> and the
/// attestation/assertion responses) — kept as opaque strings here so the WebAuthn library itself
/// stays an Infrastructure-only dependency.
/// </summary>
public interface IWebAuthnService
{
    /// <summary>
    /// Starts a registration ceremony for an already-authenticated user and returns the
    /// <c>CredentialCreateOptions</c> JSON to hand to <c>navigator.credentials.create()</c>.
    /// </summary>
    Task<string> BeginRegistrationAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Verifies the browser's attestation response against the pending registration ceremony and,
    /// on success, persists the new credential. Throws <see cref="InvalidOperationException"/> if
    /// no matching ceremony is pending (expired, already consumed, or never started) or the
    /// attestation itself fails verification.
    /// </summary>
    Task<Guid> CompleteRegistrationAsync(Guid userId, string attestationResponseJson, string? nickname, CancellationToken ct = default);

    /// <summary>Lists the user's own registered credentials (device-management view — never the public key or credential ID).</summary>
    Task<IReadOnlyList<WebAuthnCredentialDto>> ListCredentialsAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Removes one of the user's own registered credentials. A no-op if it doesn't exist or belongs to someone else.</summary>
    Task RemoveCredentialAsync(Guid userId, Guid credentialId, CancellationToken ct = default);

    /// <summary>
    /// Starts an assertion ceremony for an MFA login challenge and returns the
    /// <c>AssertionOptions</c> JSON to hand to <c>navigator.credentials.get()</c>. Returns null if
    /// the user has no registered credentials — there is nothing to assert against.
    /// </summary>
    Task<string?> BeginAssertionAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Verifies the browser's assertion response against the pending assertion ceremony and the
    /// matched credential's stored public key/sign count, updating the sign count and
    /// <c>LastUsedAt</c> on success. Returns false uniformly for any failure (expired/missing
    /// ceremony, unknown credential, bad signature) — the caller can't distinguish which.
    /// </summary>
    Task<bool> CompleteAssertionAsync(Guid userId, string assertionResponseJson, CancellationToken ct = default);
}
