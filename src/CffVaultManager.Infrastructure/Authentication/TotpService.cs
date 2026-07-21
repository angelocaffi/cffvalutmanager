using CffVaultManager.Application.Abstractions;
using OtpNet;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>TOTP (RFC 6238) operations backed by Otp.NET.</summary>
internal sealed class TotpService : ITotpService
{
    // 160-bit secret, the standard size for HMAC-SHA1 TOTP.
    private const int SecretLengthBytes = 20;

    public byte[] GenerateSecret() => KeyGeneration.GenerateRandomKey(SecretLengthBytes);

    public bool ValidateCode(byte[] secret, string code)
    {
        if (secret is null || secret.Length == 0 || string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        var totp = new Totp(secret);
        // Tolerate one step of clock drift on either side (~±30s).
        return totp.VerifyTotp(code.Trim(), out _, new VerificationWindow(previous: 1, future: 1));
    }

    public string GetProvisioningUri(byte[] secret, string accountEmail, string issuer)
    {
        var uri = new OtpUri(OtpType.Totp, Base32Encoding.ToString(secret), accountEmail, issuer);
        return uri.ToString();
    }
}
