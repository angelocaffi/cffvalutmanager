namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// TOTP (RFC 6238) second-factor operations. Secrets are raw bytes; callers are responsible for
/// protecting them at rest (see <see cref="ISecretProtector"/>).
/// </summary>
public interface ITotpService
{
    /// <summary>Generates a new random TOTP shared secret.</summary>
    byte[] GenerateSecret();

    /// <summary>Validates a user-entered code against the secret, allowing a small clock-drift window.</summary>
    bool ValidateCode(byte[] secret, string code);

    /// <summary>Builds the <c>otpauth://</c> provisioning URI used to render an enrollment QR code.</summary>
    string GetProvisioningUri(byte[] secret, string accountEmail, string issuer);
}
