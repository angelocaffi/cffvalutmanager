using System.Security.Cryptography;
using CffVaultManager.Crypto;

namespace CffVaultManager.Crypto.Tests;

/// <summary>
/// Coverage for the client-side ECIES-over-X25519 key-wrapping service used to share an organization
/// vault's DEK between members (see docs/features/sharing-access-control.md). Mirrors the round-trip /
/// wrong-key / distinctness conventions already used by <see cref="AesGcmCipherServiceTests"/> and
/// <see cref="DekServiceTests"/>.
/// </summary>
public class X25519KeyExchangeServiceTests
{
    private readonly X25519KeyExchangeService _service = new(new AesGcmCipherService());

    private static byte[] NewDek() => RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);

    [Fact]
    public void GenerateKeyPair_ReturnsThirtyTwoByteKeys()
    {
        var (publicKey, privateKey) = _service.GenerateKeyPair();

        Assert.Equal(CryptoConstants.X25519KeyLengthBytes, publicKey.Length);
        Assert.Equal(CryptoConstants.X25519KeyLengthBytes, privateKey.Length);
    }

    [Fact]
    public void GenerateKeyPair_ProducesDistinctValues()
    {
        var publicKeys = new HashSet<string>();
        var privateKeys = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            var (publicKey, privateKey) = _service.GenerateKeyPair();
            Assert.Equal(CryptoConstants.X25519KeyLengthBytes, publicKey.Length);
            Assert.Equal(CryptoConstants.X25519KeyLengthBytes, privateKey.Length);
            Assert.True(publicKeys.Add(Convert.ToHexString(publicKey)), "GenerateKeyPair produced a duplicate public key.");
            Assert.True(privateKeys.Add(Convert.ToHexString(privateKey)), "GenerateKeyPair produced a duplicate private key.");
        }
    }

    [Fact]
    public void WrapKey_UnwrapKey_RoundTrip()
    {
        var (recipientPublic, recipientPrivate) = _service.GenerateKeyPair();
        byte[] dek = NewDek();

        var (ephemeralPublicKey, wrappedKey) = _service.WrapKey(recipientPublic, dek);
        byte[] unwrapped = _service.UnwrapKey(ephemeralPublicKey, recipientPrivate, wrappedKey);

        Assert.Equal(dek, unwrapped);
    }

    [Fact]
    public void UnwrapKey_WithWrongPrivateKey_ThrowsCryptographicException()
    {
        var (recipientPublic, _) = _service.GenerateKeyPair();
        var (_, wrongPrivate) = _service.GenerateKeyPair();
        byte[] dek = NewDek();

        var (ephemeralPublicKey, wrappedKey) = _service.WrapKey(recipientPublic, dek);

        // A different recipient's private key derives a different AES key, so the GCM tag check fails.
        Assert.ThrowsAny<CryptographicException>(() =>
            _service.UnwrapKey(ephemeralPublicKey, wrongPrivate, wrappedKey));
    }

    [Fact]
    public void WrapKey_ProducesDistinctEphemeralPublicKeys_AcrossManyCalls()
    {
        var (recipientPublic, _) = _service.GenerateKeyPair();
        byte[] dek = NewDek();

        var ephemerals = new HashSet<string>();
        for (int i = 0; i < 50; i++)
        {
            // Even wrapping the same key to the same recipient must use a fresh ephemeral each time.
            var (ephemeralPublicKey, _) = _service.WrapKey(recipientPublic, dek);
            Assert.Equal(CryptoConstants.X25519KeyLengthBytes, ephemeralPublicKey.Length);
            Assert.True(ephemerals.Add(Convert.ToHexString(ephemeralPublicKey)), "Ephemeral public key was reused.");
        }
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void WrapKey_WithWrongLengthPublicKey_ThrowsArgumentException(int keyLength)
    {
        byte[] dek = NewDek();
        Assert.Throws<ArgumentException>(() => { _service.WrapKey(new byte[keyLength], dek); });
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void UnwrapKey_WithWrongLengthEphemeralPublicKey_ThrowsArgumentException(int keyLength)
    {
        var (recipientPublic, recipientPrivate) = _service.GenerateKeyPair();
        var (_, wrappedKey) = _service.WrapKey(recipientPublic, NewDek());

        Assert.Throws<ArgumentException>(() => { _service.UnwrapKey(new byte[keyLength], recipientPrivate, wrappedKey); });
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void UnwrapKey_WithWrongLengthPrivateKey_ThrowsArgumentException(int keyLength)
    {
        var (recipientPublic, _) = _service.GenerateKeyPair();
        var (ephemeralPublicKey, wrappedKey) = _service.WrapKey(recipientPublic, NewDek());

        Assert.Throws<ArgumentException>(() => { _service.UnwrapKey(ephemeralPublicKey, new byte[keyLength], wrappedKey); });
    }

    [Fact]
    public void WrapKey_FromPartyA_ToPartyB_UnwrapsOnlyWithPartyBPrivateKey()
    {
        // The real feature usage: two independently generated keypairs; a sender (A) wraps the vault
        // DEK for a recipient (B) using B's long-term public key, and only B can unwrap it.
        var (aPublic, aPrivate) = _service.GenerateKeyPair();
        var (bPublic, bPrivate) = _service.GenerateKeyPair();
        Assert.NotEqual(Convert.ToHexString(aPublic), Convert.ToHexString(bPublic));

        byte[] dek = NewDek();
        var (ephemeralPublicKey, wrappedKey) = _service.WrapKey(bPublic, dek);

        byte[] recovered = _service.UnwrapKey(ephemeralPublicKey, bPrivate, wrappedKey);
        Assert.Equal(dek, recovered);

        // A's private key (a different recipient) cannot unwrap a blob wrapped for B.
        Assert.ThrowsAny<CryptographicException>(() => _service.UnwrapKey(ephemeralPublicKey, aPrivate, wrappedKey));
    }
}
