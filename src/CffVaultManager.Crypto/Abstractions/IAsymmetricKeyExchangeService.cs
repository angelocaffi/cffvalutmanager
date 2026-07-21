namespace CffVaultManager.Crypto.Abstractions;

/// <summary>
/// Client-side asymmetric key exchange used to share an organization vault's DEK between members
/// while staying zero-knowledge (see docs/features/sharing-access-control.md). The construction is
/// ECIES-style hybrid encryption over X25519: the sender derives a one-time AES key from an
/// ephemeral X25519 keypair agreed against the recipient's long-term public key
/// (X25519 ECDH → HKDF-SHA256), then wraps the target key with AES-256-GCM via
/// <see cref="IAeadCipherService"/>. The recipient mirrors the agreement with its own private key.
/// This interface is strictly client-side: it is never registered in the server's DI container and
/// the server never sees any private key or unwrapped key material — only the opaque ephemeral
/// public key and wrapped blob are persisted.
/// </summary>
public interface IAsymmetricKeyExchangeService
{
    /// <summary>Generates a fresh long-term X25519 keypair as raw 32-byte public/private material.</summary>
    (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair();

    /// <summary>
    /// Wraps <paramref name="keyToWrap"/> (e.g. a vault DEK) for the holder of
    /// <paramref name="recipientPublicKey"/>, returning the ephemeral public key and the wrapped blob
    /// to persist.
    /// </summary>
    (byte[] EphemeralPublicKey, EncryptedBlob WrappedKey) WrapKey(ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> keyToWrap);

    /// <summary>
    /// Unwraps a blob produced by <see cref="WrapKey"/> using the recipient's own private key and the
    /// stored ephemeral public key.
    /// </summary>
    byte[] UnwrapKey(ReadOnlySpan<byte> ephemeralPublicKey, ReadOnlySpan<byte> ownPrivateKey, EncryptedBlob wrappedKey);
}
