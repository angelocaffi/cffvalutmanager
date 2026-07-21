namespace CffVaultManager.Domain.Enums;

public enum AuditAction
{
    Created,
    Viewed,
    Updated,
    Deleted,
    Shared,
    Revealed,
    MfaEnabled,
    LoginSuccess,
    LoginFailed,
    MfaChallenge,
    EmailOtpRequested,
    EmailOtpVerified,
    EmailOtpFailed,
    TenantProvisioned,
    TenantSuspended,
    UserRoleChanged,
}
