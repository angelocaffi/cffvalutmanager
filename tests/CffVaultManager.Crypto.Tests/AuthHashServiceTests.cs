using System.Security.Cryptography;
using CffVaultManager.Crypto;

namespace CffVaultManager.Crypto.Tests;

public class AuthHashServiceTests
{
    private readonly AuthHashService _authHash = new();

    private static DerivedKey NewKek() => new(RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes));

    [Fact]
    public void DeriveAuthHash_IsDeterministic_ForSameKekAndPassword()
    {
        byte[] keyBytes = RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);

        using var kekA = new DerivedKey((byte[])keyBytes.Clone());
        using var kekB = new DerivedKey((byte[])keyBytes.Clone());

        byte[] a = _authHash.DeriveAuthHash(kekA, "correct horse battery staple");
        byte[] b = _authHash.DeriveAuthHash(kekB, "correct horse battery staple");

        Assert.Equal(a, b);
    }

    [Fact]
    public void DeriveAuthHash_DifferentKek_ProducesDifferentHash()
    {
        using DerivedKey kekA = NewKek();
        using DerivedKey kekB = NewKek();

        byte[] a = _authHash.DeriveAuthHash(kekA, "same password");
        byte[] b = _authHash.DeriveAuthHash(kekB, "same password");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveAuthHash_DifferentPassword_ProducesDifferentHash()
    {
        byte[] keyBytes = RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);

        using var kekA = new DerivedKey((byte[])keyBytes.Clone());
        using var kekB = new DerivedKey((byte[])keyBytes.Clone());

        byte[] a = _authHash.DeriveAuthHash(kekA, "password one");
        byte[] b = _authHash.DeriveAuthHash(kekB, "password two");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveAuthHash_ReturnsThirtyTwoBytes()
    {
        using DerivedKey kek = NewKek();

        byte[] hash = _authHash.DeriveAuthHash(kek, "some master password");

        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void DeriveAuthHash_EmptyPassword_Throws()
    {
        using DerivedKey kek = NewKek();

        Assert.Throws<ArgumentException>(() => _authHash.DeriveAuthHash(kek, ReadOnlySpan<char>.Empty));
    }
}
