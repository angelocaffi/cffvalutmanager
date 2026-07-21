using System.Security.Cryptography;
using CffVaultManager.Crypto;

namespace CffVaultManager.Crypto.Tests;

public class AesGcmCipherServiceTests
{
    private readonly AesGcmCipherService _cipher = new();

    private static byte[] NewKey() => RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(1024)]
    public void Encrypt_Decrypt_RoundTrip(int length)
    {
        byte[] key = NewKey();
        byte[] plaintext = RandomNumberGenerator.GetBytes(length);

        EncryptedBlob blob = _cipher.Encrypt(plaintext, key);
        byte[] decrypted = _cipher.Decrypt(blob, key);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithAad_RoundTrip()
    {
        byte[] key = NewKey();
        byte[] plaintext = RandomNumberGenerator.GetBytes(64);
        byte[] aad = RandomNumberGenerator.GetBytes(16);

        EncryptedBlob blob = _cipher.Encrypt(plaintext, key, aad);
        byte[] decrypted = _cipher.Decrypt(blob, key, aad);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithWrongAad_Throws()
    {
        byte[] key = NewKey();
        byte[] plaintext = RandomNumberGenerator.GetBytes(64);
        byte[] aad = RandomNumberGenerator.GetBytes(16);

        EncryptedBlob blob = _cipher.Encrypt(plaintext, key, aad);

        Assert.ThrowsAny<CryptographicException>(() => _cipher.Decrypt(blob, key, RandomNumberGenerator.GetBytes(16)));
    }

    [Fact]
    public void Decrypt_WithWrongKey_ThrowsCryptographicException()
    {
        byte[] key = NewKey();
        byte[] wrongKey = NewKey();
        byte[] plaintext = RandomNumberGenerator.GetBytes(64);

        EncryptedBlob blob = _cipher.Encrypt(plaintext, key);

        Assert.ThrowsAny<CryptographicException>(() => _cipher.Decrypt(blob, wrongKey));
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_ThrowsCryptographicException()
    {
        byte[] key = NewKey();
        byte[] plaintext = RandomNumberGenerator.GetBytes(64);

        EncryptedBlob blob = _cipher.Encrypt(plaintext, key);
        byte[] raw = blob.ToBytes();
        // Flip a bit inside the ciphertext region (past version + nonce).
        int ciphertextStart = 1 + CryptoConstants.GcmNonceLengthBytes;
        raw[ciphertextStart] ^= 0x01;

        EncryptedBlob tampered = EncryptedBlob.FromBytes(raw);
        Assert.ThrowsAny<CryptographicException>(() => _cipher.Decrypt(tampered, key));
    }

    [Fact]
    public void Decrypt_WithTamperedTag_ThrowsCryptographicException()
    {
        byte[] key = NewKey();
        byte[] plaintext = RandomNumberGenerator.GetBytes(64);

        EncryptedBlob blob = _cipher.Encrypt(plaintext, key);
        byte[] raw = blob.ToBytes();
        raw[^1] ^= 0x01;

        EncryptedBlob tampered = EncryptedBlob.FromBytes(raw);
        Assert.ThrowsAny<CryptographicException>(() => _cipher.Decrypt(tampered, key));
    }

    [Fact]
    public void Decrypt_WithTamperedNonce_ThrowsCryptographicException()
    {
        byte[] key = NewKey();
        byte[] plaintext = RandomNumberGenerator.GetBytes(64);

        EncryptedBlob blob = _cipher.Encrypt(plaintext, key);
        byte[] raw = blob.ToBytes();
        // Flip a bit inside the nonce region (index 1..12).
        raw[1] ^= 0x01;

        EncryptedBlob tampered = EncryptedBlob.FromBytes(raw);
        Assert.ThrowsAny<CryptographicException>(() => _cipher.Decrypt(tampered, key));
    }

    [Fact]
    public void Encrypt_ProducesDistinctNonces_AcrossManyCalls()
    {
        byte[] key = NewKey();
        byte[] plaintext = RandomNumberGenerator.GetBytes(32);

        var nonces = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            EncryptedBlob blob = _cipher.Encrypt(plaintext, key);
            Assert.Equal(CryptoConstants.GcmNonceLengthBytes, blob.Nonce.Length);
            Assert.True(nonces.Add(Convert.ToHexString(blob.Nonce)), "Nonce was reused.");
        }
    }
}
