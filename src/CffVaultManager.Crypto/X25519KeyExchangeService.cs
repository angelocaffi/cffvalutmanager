using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Crypto.Abstractions;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CffVaultManager.Crypto;

/// <summary>
/// ECIES-style hybrid key wrapping over X25519 + HKDF-SHA256 + AES-256-GCM, implemented with
/// BouncyCastle's pure-managed primitives so it behaves identically on server .NET and browser-wasm
/// (the same reason <see cref="AesGcmCipherService"/> avoids the BCL's <c>AesGcm</c> — see
/// docs/features/encryption-key-management.md). This is client-side crypto only and is never
/// registered in the server DI container; the AES-GCM step reuses <see cref="IAeadCipherService"/>
/// verbatim rather than reimplementing authenticated encryption.
/// </summary>
public sealed class X25519KeyExchangeService : IAsymmetricKeyExchangeService
{
    private const string HkdfInfo = "CffVaultManager.OrgVaultDek.v1";

    private readonly IAeadCipherService _cipher;

    public X25519KeyExchangeService(IAeadCipherService cipher)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        _cipher = cipher;
    }

    public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
    {
        var generator = new X25519KeyPairGenerator();
        generator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var pair = generator.GenerateKeyPair();

        var publicKey = ((X25519PublicKeyParameters)pair.Public).GetEncoded();
        var privateKey = ((X25519PrivateKeyParameters)pair.Private).GetEncoded();
        return (publicKey, privateKey);
    }

    public (byte[] EphemeralPublicKey, EncryptedBlob WrappedKey) WrapKey(
        ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> keyToWrap)
    {
        if (recipientPublicKey.Length != CryptoConstants.X25519KeyLengthBytes)
        {
            throw new ArgumentException(
                $"Public key must be {CryptoConstants.X25519KeyLengthBytes} bytes.", nameof(recipientPublicKey));
        }

        var generator = new X25519KeyPairGenerator();
        generator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var ephemeral = generator.GenerateKeyPair();
        var ephemeralPrivate = (X25519PrivateKeyParameters)ephemeral.Private;
        byte[] ephemeralPublic = ((X25519PublicKeyParameters)ephemeral.Public).GetEncoded();

        var recipient = new X25519PublicKeyParameters(recipientPublicKey.ToArray(), 0);

        byte[] aesKey = DeriveSharedKey(ephemeralPrivate, recipient);
        try
        {
            var wrapped = _cipher.Encrypt(keyToWrap, aesKey);
            return (ephemeralPublic, wrapped);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    public byte[] UnwrapKey(
        ReadOnlySpan<byte> ephemeralPublicKey, ReadOnlySpan<byte> ownPrivateKey, EncryptedBlob wrappedKey)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);
        if (ephemeralPublicKey.Length != CryptoConstants.X25519KeyLengthBytes)
        {
            throw new ArgumentException(
                $"Ephemeral public key must be {CryptoConstants.X25519KeyLengthBytes} bytes.", nameof(ephemeralPublicKey));
        }

        if (ownPrivateKey.Length != CryptoConstants.X25519KeyLengthBytes)
        {
            throw new ArgumentException(
                $"Private key must be {CryptoConstants.X25519KeyLengthBytes} bytes.", nameof(ownPrivateKey));
        }

        var privateParams = new X25519PrivateKeyParameters(ownPrivateKey.ToArray(), 0);
        var ephemeralPublic = new X25519PublicKeyParameters(ephemeralPublicKey.ToArray(), 0);

        byte[] aesKey = DeriveSharedKey(privateParams, ephemeralPublic);
        try
        {
            return _cipher.Decrypt(wrappedKey, aesKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    /// <summary>
    /// Runs the X25519 agreement and derives the 32-byte AES key via HKDF-SHA256. The shared secret
    /// is zeroed before returning; the caller owns zeroing the returned key.
    /// </summary>
    private static byte[] DeriveSharedKey(X25519PrivateKeyParameters ownPrivate, X25519PublicKeyParameters otherPublic)
    {
        var agreement = new X25519Agreement();
        agreement.Init(ownPrivate);

        byte[] shared = new byte[agreement.AgreementSize];
        try
        {
            agreement.CalculateAgreement(otherPublic, shared, 0);

            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(shared, null, Encoding.UTF8.GetBytes(HkdfInfo)));

            byte[] aesKey = new byte[CryptoConstants.KeyLengthBytes];
            hkdf.GenerateBytes(aesKey, 0, aesKey.Length);
            return aesKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
        }
    }
}
