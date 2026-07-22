namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// The caller's own keypair, returned only to themselves: <see cref="EncryptedPrivateKey"/> is opaque
/// to the server (encrypted client-side with the owner's own DEK) — returning it is safe because only
/// its owner, holding that DEK, can ever decrypt it.
/// </summary>
public sealed record KeyPairDto(byte[] PublicKey, byte[] EncryptedPrivateKey);
