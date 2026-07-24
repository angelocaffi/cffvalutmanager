namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Submits the new master password material after the recovery flow has proven Recovery Key
/// possession (and MFA, if enabled) — see docs/security-model.md#recovery-kit.
/// <paramref name="RecoveryToken"/> is what proves that; no email/user id is passed separately,
/// it is derived from the validated token's own claims.
/// </summary>
public sealed record RecoveryCompleteRequest(
    string RecoveryToken,
    byte[] NewAuthHash,
    byte[] NewEncryptedDek,
    byte[] NewMasterPasswordSalt,
    int NewKdfMemoryKb,
    int NewKdfIterations,
    int NewKdfVersion);
