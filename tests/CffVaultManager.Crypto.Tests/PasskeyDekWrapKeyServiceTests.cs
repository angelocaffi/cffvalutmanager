using System.Security.Cryptography;
using CffVaultManager.Crypto;

namespace CffVaultManager.Crypto.Tests;

public class PasskeyDekWrapKeyServiceTests
{
    private readonly PasskeyDekWrapKeyService _service = new();

    [Fact]
    public void DeriveKey_IsDeterministic_ForTheSamePrfOutput()
    {
        byte[] prfOutput = RandomNumberGenerator.GetBytes(32);

        byte[] a = _service.DeriveKey(prfOutput);
        byte[] b = _service.DeriveKey(prfOutput);

        Assert.Equal(a, b);
    }

    [Fact]
    public void DeriveKey_DifferentPrfOutput_ProducesDifferentKey()
    {
        byte[] a = _service.DeriveKey(RandomNumberGenerator.GetBytes(32));
        byte[] b = _service.DeriveKey(RandomNumberGenerator.GetBytes(32));

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveKey_ReturnsThirtyTwoBytes()
    {
        byte[] key = _service.DeriveKey(RandomNumberGenerator.GetBytes(32));

        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void DeriveKey_EmptyPrfOutput_Throws()
    {
        Assert.Throws<ArgumentException>(() => _service.DeriveKey(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void DeriveKey_wrappedDekRoundTrips_throughTheExistingAesGcmDekService()
    {
        // Exercises the actual downstream use of this key — wrapping/unwrapping a DEK with
        // DekService, exactly as Login.razor/Security.razor do — rather than only checking the
        // raw derived bytes in isolation.
        var dekService = new DekService(new AesGcmCipherService());
        byte[] dek = dekService.GenerateDek();
        byte[] prfKek = _service.DeriveKey(RandomNumberGenerator.GetBytes(32));

        var wrapped = dekService.EncryptDek(dek, prfKek);
        byte[] unwrapped = dekService.DecryptDek(wrapped, prfKek);

        Assert.Equal(dek, unwrapped);
    }
}
