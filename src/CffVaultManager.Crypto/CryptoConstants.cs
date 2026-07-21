namespace CffVaultManager.Crypto;

public static class CryptoConstants
{
    /// <summary>Symmetric key length in bytes (AES-256 / KEK / DEK).</summary>
    public const int KeyLengthBytes = 32;

    /// <summary>AES-GCM nonce length in bytes.</summary>
    public const int GcmNonceLengthBytes = 12;

    /// <summary>AES-GCM authentication tag length in bytes.</summary>
    public const int GcmTagLengthBytes = 16;

    /// <summary>Current on-disk version byte for <see cref="EncryptedBlob"/> serialization.</summary>
    public const byte CurrentBlobVersion = 1;
}
