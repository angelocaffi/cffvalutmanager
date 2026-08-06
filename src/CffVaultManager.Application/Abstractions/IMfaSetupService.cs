namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Enrollment flow for TOTP. Setup generates and stores an encrypted, not-yet-active secret and
/// returns its provisioning URI; confirmation verifies the first code before activating MFA, so a
/// mistyped or unscanned secret can never lock the user out.
/// </summary>
public interface IMfaSetupService
{
    /// <summary>
    /// Generates a new TOTP secret for the user, stores it encrypted (MFA stays disabled), and
    /// returns the <c>otpauth://</c> provisioning URI to display as a QR code.
    /// </summary>
    Task<string> SetupTotpAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Verifies the first code against the pending secret and, if valid, enables MFA for the user.
    /// </summary>
    Task<bool> ConfirmTotpAsync(Guid userId, string code, CancellationToken ct = default);

    /// <summary>Turns TOTP off and discards the stored secret. Safe to call even if not enabled.</summary>
    Task DisableTotpAsync(Guid userId, CancellationToken ct = default);
}
