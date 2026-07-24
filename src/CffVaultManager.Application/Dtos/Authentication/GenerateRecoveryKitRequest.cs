namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Both fields are produced client-side from a Recovery Key the server never sees — see
/// docs/security-model.md#recovery-kit. Generating a kit overwrites any prior one, no re-proof of
/// the current master password required (same convention as /api/auth/mfa/setup and
/// /api/auth/keypair — the caller already has an unlocked, authenticated session).
/// </summary>
public sealed record GenerateRecoveryKitRequest(byte[] RecoveryEncryptedDek, byte[] RecoveryAuthHash);
