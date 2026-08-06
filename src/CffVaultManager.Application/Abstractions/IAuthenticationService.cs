using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Drives the zero-knowledge login flow: password (auth hash) verification followed, when enabled,
/// by a second factor (TOTP and/or Email OTP — see <see cref="MfaFactor"/>). Failures are always
/// generic to avoid account enumeration.
/// </summary>
public interface IAuthenticationService
{
    /// <summary>
    /// Returns the Argon2id salt/parameters <paramref name="email"/> needs to derive its KEK
    /// before it can compute an auth hash to log in with — the "prelogin" step a fresh device with
    /// no cached copy of these needs. For an unknown email, returns a fake-but-stable (same
    /// values on every call, for this process's lifetime) response rather than an error, so this
    /// endpoint cannot be used to enumerate registered addresses.
    /// </summary>
    Task<PreloginResult> PreloginAsync(string email, CancellationToken ct = default);

    /// <summary>
    /// Verifies the auth hash for <paramref name="email"/>. On success with MFA disabled, returns a
    /// full session (access + refresh token + crypto material). With MFA enabled, returns only a
    /// short-lived challenge. On failure, returns a generic failure without revealing the cause.
    /// </summary>
    Task<LoginResult> LoginAsync(string email, byte[] authHash, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Completes an MFA challenge: validates the challenge token and the code against the chosen
    /// <paramref name="factor"/>, and on success returns the full session.
    /// </summary>
    Task<LoginResult> VerifyMfaAsync(string challengeToken, string code, MfaFactor factor, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Sends an Email OTP code for an in-progress MFA challenge (see docs/features/authentication.md
    /// "Email OTP come fattore MFA") — unlike TOTP, which the user already has on their device, an
    /// Email OTP code must be actively dispatched before it can be entered. Returns false only when
    /// the challenge token itself is missing/invalid/expired; a user without this factor enabled
    /// still gets true (uniform response, no-op internally).
    /// </summary>
    Task<bool> RequestMfaEmailOtpAsync(string challengeToken, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Starts a WebAuthn assertion for an in-progress MFA challenge and returns the
    /// <c>AssertionOptions</c> JSON the client needs for <c>navigator.credentials.get()</c>. Null
    /// if the challenge token itself is missing/invalid/expired, or the user has no registered
    /// credential to assert against.
    /// </summary>
    Task<string?> RequestWebAuthnAssertionOptionsAsync(string challengeToken, CancellationToken ct = default);

    /// <summary>
    /// Completes an MFA challenge with a WebAuthn assertion response — a separate method from
    /// <see cref="VerifyMfaAsync"/> because the payload is a structured JSON object, not a short
    /// typed code. On success returns the full session.
    /// </summary>
    Task<LoginResult> VerifyWebAuthnAsync(string challengeToken, string assertionResponseJson, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Rotates an opaque refresh token and mints a fresh access token for its owner. Returns a
    /// generic failure when the refresh token is unknown, already rotated/revoked, or expired.
    /// </summary>
    Task<LoginResult> RefreshAsync(string refreshToken, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Starts a passwordless, usernameless login (docs/security-model.md#sblocco-senza-password-via-passkey-webauthn-prf)
    /// — no email, no prior password step. Unlike <see cref="RequestWebAuthnAssertionOptionsAsync"/>,
    /// there is no challenge token from an earlier step; the caller only has a fresh ceremony id.
    /// </summary>
    Task<PasskeyLoginCeremony> BeginPasskeyLoginAsync(CancellationToken ct = default);

    /// <summary>
    /// Completes a passwordless login: verifies the assertion, discovers the user from the
    /// credential, and on success returns the full session — <see cref="LoginResult.CryptoMaterials"/>
    /// carries <c>PrfWrappedDek</c> instead of relying on the caller already knowing
    /// <c>EncryptedDek</c>, since no master-password-derived KEK exists in this flow at all.
    /// </summary>
    Task<LoginResult> CompletePasskeyLoginAsync(Guid ceremonyId, string assertionResponseJson, string? ip, string? userAgent, CancellationToken ct = default);
}
