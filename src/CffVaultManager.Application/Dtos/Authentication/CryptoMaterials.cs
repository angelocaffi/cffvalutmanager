namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// The zero-knowledge material the client needs after a successful login to re-derive its KEK
/// and unwrap its DEK. The server stores and returns these opaque values but never decrypts them:
/// <see cref="EncryptedDek"/> is only ever unwrapped on the client with the KEK the client
/// re-derives from the master password using the returned KDF parameters.
/// </summary>
public sealed record CryptoMaterials(
    byte[] EncryptedDek,
    byte[]? MasterPasswordSalt,
    int? KdfMemoryKb,
    int? KdfIterations,
    int? KdfVersion);
