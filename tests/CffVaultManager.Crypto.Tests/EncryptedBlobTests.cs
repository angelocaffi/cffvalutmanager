using System.Security.Cryptography;
using CffVaultManager.Crypto;

namespace CffVaultManager.Crypto.Tests;

public class EncryptedBlobTests
{
    [Fact]
    public void ToBytes_FromBytes_PreservesAllFields()
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(CryptoConstants.GcmNonceLengthBytes);
        byte[] ciphertext = RandomNumberGenerator.GetBytes(50);
        byte[] tag = RandomNumberGenerator.GetBytes(CryptoConstants.GcmTagLengthBytes);
        const byte version = CryptoConstants.CurrentBlobVersion;

        var blob = new EncryptedBlob(version, nonce, ciphertext, tag);
        byte[] serialized = blob.ToBytes();
        EncryptedBlob restored = EncryptedBlob.FromBytes(serialized);

        Assert.Equal(version, restored.Version);
        Assert.Equal(nonce, restored.Nonce.ToArray());
        Assert.Equal(ciphertext, restored.Ciphertext.ToArray());
        Assert.Equal(tag, restored.Tag.ToArray());
    }

    [Fact]
    public void ByteLayout_IsVersionNonceCiphertextTag()
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(CryptoConstants.GcmNonceLengthBytes);
        byte[] ciphertext = RandomNumberGenerator.GetBytes(10);
        byte[] tag = RandomNumberGenerator.GetBytes(CryptoConstants.GcmTagLengthBytes);

        var blob = new EncryptedBlob(7, nonce, ciphertext, tag);
        byte[] bytes = blob.ToBytes();

        Assert.Equal(1 + nonce.Length + ciphertext.Length + tag.Length, bytes.Length);
        Assert.Equal(7, bytes[0]);
        Assert.Equal(nonce, bytes[1..(1 + nonce.Length)]);
        Assert.Equal(ciphertext, bytes[(1 + nonce.Length)..(1 + nonce.Length + ciphertext.Length)]);
        Assert.Equal(tag, bytes[^tag.Length..]);
    }

    [Fact]
    public void FromBytes_TooShort_Throws()
    {
        Assert.Throws<ArgumentException>(() => EncryptedBlob.FromBytes(new byte[5]));
    }

    [Fact]
    public void ToBytes_ReturnsIndependentCopy()
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(CryptoConstants.GcmNonceLengthBytes);
        byte[] ciphertext = RandomNumberGenerator.GetBytes(8);
        byte[] tag = RandomNumberGenerator.GetBytes(CryptoConstants.GcmTagLengthBytes);

        var blob = new EncryptedBlob(1, nonce, ciphertext, tag);
        byte[] first = blob.ToBytes();
        first[0] ^= 0xFF;

        Assert.Equal(1, blob.Version);
    }
}
