namespace CffVaultManager.Crypto.Abstractions;

public interface IDekService
{
    /// <summary>Generates a fresh random 32-byte data-encryption key.</summary>
    byte[] GenerateDek();

    EncryptedBlob EncryptDek(ReadOnlySpan<byte> dek, ReadOnlySpan<byte> kek);

    /// <summary>Throws <see cref="System.Security.Cryptography.CryptographicException"/> if the KEK is wrong or the blob was tampered with.</summary>
    byte[] DecryptDek(EncryptedBlob encryptedDek, ReadOnlySpan<byte> kek);
}
