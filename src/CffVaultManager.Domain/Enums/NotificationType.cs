namespace CffVaultManager.Domain.Enums;

public enum NotificationType
{
    NewLoginFromUnknownIp,
    MasterPasswordChanged,
    MfaFactorDisabled,
    AccountRecovered,
    RecoveryKitInvalidated,
}
