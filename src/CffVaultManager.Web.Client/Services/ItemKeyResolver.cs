using System.Security.Cryptography;
using CffVaultManager.Crypto;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Unwraps a shared item's dedicated key using the caller's own X25519 keypair (see
/// docs/features/sharing-access-control.md "Condivisione live di singola voce"). The private key is
/// fetched and decrypted fresh for each call rather than cached in <see cref="SessionState"/>:
/// sharing is used occasionally, not on every page, so minimizing how long the raw private key sits
/// in memory outweighs the cost of one extra round trip.
/// </summary>
public sealed class ItemKeyResolver
{
    private readonly AuthApiClient _authApi;
    private readonly SessionState _session;
    private readonly IAeadCipherService _aeadCipher;
    private readonly IAsymmetricKeyExchangeService _keyExchange;

    public ItemKeyResolver(AuthApiClient authApi, SessionState session, IAeadCipherService aeadCipher, IAsymmetricKeyExchangeService keyExchange)
    {
        _authApi = authApi;
        _session = session;
        _aeadCipher = aeadCipher;
        _keyExchange = keyExchange;
    }

    /// <summary>The caller's own long-term public key — needed to wrap a fresh item key "for themselves" when sharing an item for the first time.</summary>
    public async Task<byte[]> GetOwnPublicKeyAsync()
    {
        var keyPair = await _authApi.GetKeyPairAsync() ?? throw new InvalidOperationException("No key pair found for this account.");
        return keyPair.PublicKey;
    }

    /// <summary>Unwraps a shared item's key using the caller's own private key.</summary>
    public async Task<byte[]> UnwrapAsync(byte[] wrappedItemKey, byte[] ephemeralPublicKey)
    {
        var keyPair = await _authApi.GetKeyPairAsync() ?? throw new InvalidOperationException("No key pair found for this account.");
        byte[] dek = _session.RequireDek();
        var encryptedPrivateKeyBlob = EncryptedBlob.FromBytes(keyPair.EncryptedPrivateKey);
        byte[] privateKey = _aeadCipher.Decrypt(encryptedPrivateKeyBlob, dek);
        try
        {
            var wrappedBlob = EncryptedBlob.FromBytes(wrappedItemKey);
            return _keyExchange.UnwrapKey(ephemeralPublicKey, privateKey, wrappedBlob);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    /// <summary>Wraps a raw item key for a recipient's public key.</summary>
    public (byte[] EphemeralPublicKey, byte[] WrappedItemKey) Wrap(byte[] recipientPublicKey, byte[] itemKey)
    {
        var (ephemeralPublicKey, wrapped) = _keyExchange.WrapKey(recipientPublicKey, itemKey);
        return (ephemeralPublicKey, wrapped.ToBytes());
    }
}
