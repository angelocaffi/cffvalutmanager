using System.Security.Cryptography;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

public sealed class AesGcmCipherService : IAeadCipherService
{
    public EncryptedBlob Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad = default)
    {
        if (key.Length != CryptoConstants.KeyLengthBytes)
        {
            throw new ArgumentException($"Key must be {CryptoConstants.KeyLengthBytes} bytes.", nameof(key));
        }

        Span<byte> nonce = stackalloc byte[CryptoConstants.GcmNonceLengthBytes];
        RandomNumberGenerator.Fill(nonce);

        Span<byte> tag = stackalloc byte[CryptoConstants.GcmTagLengthBytes];
        byte[] ciphertext = new byte[plaintext.Length];

        using var aesGcm = new AesGcm(key, CryptoConstants.GcmTagLengthBytes);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        return new EncryptedBlob(CryptoConstants.CurrentBlobVersion, nonce, ciphertext, tag);
    }

    public byte[] Decrypt(EncryptedBlob blob, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad = default)
    {
        ArgumentNullException.ThrowIfNull(blob);
        if (key.Length != CryptoConstants.KeyLengthBytes)
        {
            throw new ArgumentException($"Key must be {CryptoConstants.KeyLengthBytes} bytes.", nameof(key));
        }

        byte[] plaintext = new byte[blob.Ciphertext.Length];

        using var aesGcm = new AesGcm(key, CryptoConstants.GcmTagLengthBytes);
        // AesGcm.Decrypt throws CryptographicException on tag mismatch (wrong key / tampering).
        aesGcm.Decrypt(blob.Nonce, blob.Ciphertext, blob.Tag, plaintext, aad);

        return plaintext;
    }
}
