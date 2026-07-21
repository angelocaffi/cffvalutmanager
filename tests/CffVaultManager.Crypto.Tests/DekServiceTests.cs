using System.Security.Cryptography;
using CffVaultManager.Crypto;

namespace CffVaultManager.Crypto.Tests;

public class DekServiceTests
{
    private readonly DekService _dekService = new(new AesGcmCipherService());

    private static byte[] NewKek() => RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);

    [Fact]
    public void EncryptDek_DecryptDek_RoundTrip()
    {
        byte[] kek = NewKek();
        byte[] dek = _dekService.GenerateDek();

        EncryptedBlob blob = _dekService.EncryptDek(dek, kek);
        byte[] recovered = _dekService.DecryptDek(blob, kek);

        Assert.Equal(dek, recovered);
    }

    [Fact]
    public void DecryptDek_WithWrongKek_ThrowsCryptographicException()
    {
        byte[] kek = NewKek();
        byte[] dek = _dekService.GenerateDek();

        EncryptedBlob blob = _dekService.EncryptDek(dek, kek);

        Assert.ThrowsAny<CryptographicException>(() => _dekService.DecryptDek(blob, NewKek()));
    }

    [Fact]
    public void GenerateDek_HasCorrectLength()
    {
        byte[] dek = _dekService.GenerateDek();
        Assert.Equal(CryptoConstants.KeyLengthBytes, dek.Length);
    }

    [Fact]
    public void GenerateDek_ProducesDistinctValues()
    {
        var seen = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            byte[] dek = _dekService.GenerateDek();
            Assert.Equal(CryptoConstants.KeyLengthBytes, dek.Length);
            Assert.True(seen.Add(Convert.ToHexString(dek)), "GenerateDek produced a duplicate value.");
        }
    }
}
