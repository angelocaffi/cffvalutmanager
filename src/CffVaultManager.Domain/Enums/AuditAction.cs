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
    AccountLocked,
    MfaChallenge,
    EmailOtpRequested,
    EmailOtpVerified,
    EmailOtpFailed,
    TenantProvisioned,
    TenantSuspended,
    TenantReactivated,
    UserRoleChanged,
}
