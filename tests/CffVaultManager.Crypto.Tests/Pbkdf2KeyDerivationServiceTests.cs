using System.Security.Cryptography;
using CffVaultManager.Crypto;

namespace CffVaultManager.Crypto.Tests;

public class Pbkdf2KeyDerivationServiceTests
{
    // Iteration floor is enforced internally; keep params minimal.
    private readonly Pbkdf2KeyDerivationService _kdf = new();
    private static readonly Argon2Parameters Params = Argon2Parameters.Default;

    private static byte[] NewSalt() => RandomNumberGenerator.GetBytes(16);

    [Fact]
    public void DeriveKek_IsDeterministic_ForSameInputs()
    {
        byte[] salt = NewSalt();

        using DerivedKey a = _kdf.DeriveKek("hunter2 hunter2", salt, Params);
        using DerivedKey b = _kdf.DeriveKek("hunter2 hunter2", salt, Params);

        Assert.Equal(CryptoConstants.KeyLengthBytes, a.Length);
        Assert.Equal(a.Key.ToArray(), b.Key.ToArray());
    }

    [Fact]
    public void DeriveKek_DifferentSalt_ProducesDifferentKey()
    {
        using DerivedKey a = _kdf.DeriveKek("same password", NewSalt(), Params);
        using DerivedKey b = _kdf.DeriveKek("same password", NewSalt(), Params);

        Assert.NotEqual(a.Key.ToArray(), b.Key.ToArray());
    }

    [Fact]
    public void DeriveKek_DifferentPassword_ProducesDifferentKey()
    {
        byte[] salt = NewSalt();

        using DerivedKey a = _kdf.DeriveKek("password one", salt, Params);
        using DerivedKey b = _kdf.DeriveKek("password two", salt, Params);

        Assert.NotEqual(a.Key.ToArray(), b.Key.ToArray());
    }

    [Fact]
    public void DerivedKek_CanEncryptAndDecrypt_RoundTrip()
    {
        byte[] salt = NewSalt();
        var cipher = new AesGcmCipherService();
        byte[] payload = RandomNumberGenerator.GetBytes(48);

        using DerivedKey kek = _kdf.DeriveKek("master pw", salt, Params);
        EncryptedBlob blob = cipher.Encrypt(payload, kek.Key);

        using DerivedKey kekAgain = _kdf.DeriveKek("master pw", salt, Params);
        byte[] decrypted = cipher.Decrypt(blob, kekAgain.Key);

        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void DerivedKek_WrongPassword_FailsToDecrypt()
    {
        byte[] salt = NewSalt();
        var cipher = new AesGcmCipherService();
        byte[] payload = RandomNumberGenerator.GetBytes(48);

        using DerivedKey kek = _kdf.DeriveKek("master pw", salt, Params);
        EncryptedBlob blob = cipher.Encrypt(payload, kek.Key);

        using DerivedKey wrong = _kdf.DeriveKek("wrong pw", salt, Params);
        Assert.ThrowsAny<CryptographicException>(() => cipher.Decrypt(blob, wrong.Key));
    }

    [Fact]
    public void Constructor_EnforcesIterationFloor()
    {
        Assert.Equal(600_000, Pbkdf2KeyDerivationService.MinimumIterations);
        // Requesting fewer iterations must not weaken the KDF below the floor.
        var weakRequest = new Pbkdf2KeyDerivationService(iterations: 1);
        byte[] salt = NewSalt();

        using DerivedKey a = weakRequest.DeriveKek("pw", salt, Params);
        using DerivedKey b = _kdf.DeriveKek("pw", salt, Params);

        // Both clamp to the 600k floor, so they produce the same key.
        Assert.Equal(a.Key.ToArray(), b.Key.ToArray());
    }
}
