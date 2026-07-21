namespace CffVaultManager.Domain.Enums;

public enum AuditAction
{
    Created,
    Viewed,
    Updated,
    Deleted,
    Shared,
    Revoked,
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
