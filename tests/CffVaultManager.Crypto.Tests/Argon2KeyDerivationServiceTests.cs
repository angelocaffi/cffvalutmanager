using System.Security.Cryptography;
using CffVaultManager.Crypto;

namespace CffVaultManager.Crypto.Tests;

public class Argon2KeyDerivationServiceTests
{
    private readonly Argon2KeyDerivationService _kdf = new();

    // Small cost parameters to keep the test suite fast; production values live in Argon2Parameters.Default.
    private static readonly Argon2Parameters TestParams = new(memoryKb: 1024, iterations: 1);

    private static byte[] NewSalt() => RandomNumberGenerator.GetBytes(16);

    [Fact]
    public void DeriveKek_IsDeterministic_ForSameInputs()
    {
        byte[] salt = NewSalt();

        using DerivedKey a = _kdf.DeriveKek("correct horse battery staple", salt, TestParams);
        using DerivedKey b = _kdf.DeriveKek("correct horse battery staple", salt, TestParams);

        Assert.Equal(CryptoConstants.KeyLengthBytes, a.Length);
        Assert.Equal(a.Key.ToArray(), b.Key.ToArray());
    }

    [Fact]
    public void DeriveKek_DifferentSalt_ProducesDifferentKey()
    {
        using DerivedKey a = _kdf.DeriveKek("same password", NewSalt(), TestParams);
        using DerivedKey b = _kdf.DeriveKek("same password", NewSalt(), TestParams);

        Assert.NotEqual(a.Key.ToArray(), b.Key.ToArray());
    }

    [Fact]
    public void DeriveKek_DifferentPassword_ProducesDifferentKey()
    {
        byte[] salt = NewSalt();

        using DerivedKey a = _kdf.DeriveKek("password one", salt, TestParams);
        using DerivedKey b = _kdf.DeriveKek("password two", salt, TestParams);

        Assert.NotEqual(a.Key.ToArray(), b.Key.ToArray());
    }

    [Fact]
    public void DeriveKek_EmptyPassword_Throws()
    {
        Assert.Throws<ArgumentException>(() => _kdf.DeriveKek(ReadOnlySpan<char>.Empty, NewSalt(), TestParams));
    }

    [Fact]
    public void DeriveKek_EmptySalt_Throws()
    {
        Assert.Throws<ArgumentException>(() => _kdf.DeriveKek("password", Array.Empty<byte>(), TestParams));
    }

    [Fact]
    public void DegreeOfParallelism_IsAlwaysOne_RegardlessOfRequest()
    {
        // Constructor coerces the value to 1...
        var coerced = new Argon2Parameters(memoryKb: 1024, iterations: 1, degreeOfParallelism: 8);
        Assert.Equal(1, coerced.DegreeOfParallelism);

        // ...and even if an init-only 'with' expression forces a different lane count,
        // the service ignores it and still derives a stable, deterministic key.
        Argon2Parameters malicious = TestParams with { DegreeOfParallelism = 8 };
        Assert.Equal(8, malicious.DegreeOfParallelism);

        byte[] salt = NewSalt();
        using DerivedKey withMalicious = _kdf.DeriveKek("password", salt, malicious);
        using DerivedKey withEnforced = _kdf.DeriveKek("password", salt, TestParams);

        Assert.Equal(withEnforced.Key.ToArray(), withMalicious.Key.ToArray());
    }
}
