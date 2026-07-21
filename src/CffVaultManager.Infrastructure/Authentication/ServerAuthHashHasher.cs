using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Crypto;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Server-side rehash of the client's auth hash. This lives in Infrastructure, not Crypto,
/// because it is a server-only concern: the client never performs it.
/// </summary>
/// <remarks>
/// The stored value is <c>[16-byte salt][32-byte Argon2id output]</c>. Rehashing with a
/// per-record salt means a leaked <c>MasterPasswordHash</c> column cannot be replayed against
/// the login endpoint as-is — an attacker would have to brute-force the (already high-entropy)
/// auth hash through Argon2. We reuse the existing Argon2 KEK derivation verbatim rather than
/// duplicate an Argon2 pipeline: the auth hash is base64-encoded and fed in as the "master
/// password" input that <see cref="IKeyDerivationService.DeriveKek"/> already expects.
/// </remarks>
internal sealed class ServerAuthHashHasher : IAuthHashHasher
{
    private const int SaltLength = 16;
    private const int HashLength = CryptoConstants.KeyLengthBytes; // 32
    private const int StoredLength = SaltLength + HashLength;

    private readonly IKeyDerivationService _keyDerivation;
    private readonly Argon2Parameters _parameters;

    // parameters is optional so DI resolves it to the production default; tests can inject a
    // cheaper cost to keep the suite fast.
    public ServerAuthHashHasher(IKeyDerivationService keyDerivation, Argon2Parameters? parameters = null)
    {
        _keyDerivation = keyDerivation;
        _parameters = parameters ?? Argon2Parameters.Default;
    }

    public byte[] Hash(byte[] authHash)
    {
        ArgumentNullException.ThrowIfNull(authHash);
        if (authHash.Length == 0)
        {
            throw new ArgumentException("Auth hash must not be empty.", nameof(authHash));
        }

        byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
        byte[] derived = Derive(authHash, salt);

        byte[] stored = new byte[StoredLength];
        salt.CopyTo(stored, 0);
        derived.CopyTo(stored.AsSpan(SaltLength));
        return stored;
    }

    public bool Verify(byte[] authHash, byte[] storedHash)
    {
        if (authHash is null || authHash.Length == 0 || storedHash is null || storedHash.Length != StoredLength)
        {
            return false;
        }

        byte[] salt = storedHash.AsSpan(0, SaltLength).ToArray();
        byte[] expected = storedHash.AsSpan(SaltLength, HashLength).ToArray();
        byte[] actual = Derive(authHash, salt);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private byte[] Derive(byte[] authHash, byte[] salt)
    {
        string encoded = Convert.ToBase64String(authHash);
        using DerivedKey key = _keyDerivation.DeriveKek(encoded.AsSpan(), salt, _parameters);
        return key.Key.ToArray();
    }
}
