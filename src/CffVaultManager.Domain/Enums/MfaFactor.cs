namespace CffVaultManager.Domain.Enums;

/// <summary>A second factor a user can register and choose between at login (see OtpPurpose.MfaLogin).</summary>
public enum MfaFactor
{
    Totp,
    EmailOtp,
    WebAuthn,
}
