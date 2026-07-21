using System.Security.Cryptography;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

public sealed class DekService : IDekService
{
    private readonly IAeadCipherService _cipher;

    public DekService(IAeadCipherService cipher)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        _cipher = cipher;
    }

    public byte[] GenerateDek() => RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);

    public EncryptedBlob EncryptDek(ReadOnlySpan<byte> dek, ReadOnlySpan<byte> kek) => _cipher.Encrypt(dek, kek);

    public byte[] DecryptDek(EncryptedBlob encryptedDek, ReadOnlySpan<byte> kek) => _cipher.Decrypt(encryptedDek, kek);
}
