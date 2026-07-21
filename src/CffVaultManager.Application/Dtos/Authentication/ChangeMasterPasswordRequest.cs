namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Request to change the caller's own master password. <see cref="CurrentAuthHash"/> proves
/// knowledge of the current master password; the rest are already produced client-side with the
/// new master password (new salt, new KDF parameters, DEK re-wrapped with the new KEK) — the
/// server only ever re-encrypts the DEK, never any vault item, and never sees a master password
/// (old or new) in the clear.
/// </summary>
public sealed record ChangeMasterPasswordRequest(
    byte[] CurrentAuthHash,
    byte[] NewAuthHash,
    byte[] NewEncryptedDek,
    byte[] NewMasterPasswordSalt,
    int NewKdfMemoryKb,
    int NewKdfIterations,
    int NewKdfVersion);
