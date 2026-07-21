namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// The caller's own account status — enough for the client to render security settings (which
/// MFA factors are on, whether the email is verified) without exposing any other user's data.
/// </summary>
public sealed record UserProfileDto(string Email, bool EmailVerified, bool MfaEnabled, bool MfaEmailOtpEnabled);
