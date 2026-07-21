namespace CffVaultManager.Crypto.Abstractions;

/// <summary>
/// Authenticated encryption (AES-256-GCM). Used for both DEK-under-KEK and payload-under-DEK.
/// </summary>
public interface IAeadCipherService
{
    EncryptedBlob Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad = default);

    /// <summary>Throws <see cref="System.Security.Cryptography.CryptographicException"/> if the tag does not verify.</summary>
    byte[] Decrypt(EncryptedBlob blob, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad = default);
}
