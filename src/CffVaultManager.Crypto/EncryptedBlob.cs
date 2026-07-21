namespace CffVaultManager.Crypto;

/// <summary>
/// An AES-GCM encrypted value serialized as a single contiguous buffer:
/// <c>[1 byte version][12 byte nonce][N byte ciphertext][16 byte tag]</c>.
/// </summary>
public sealed class EncryptedBlob
{
    private readonly byte[] _bytes;

    private EncryptedBlob(byte[] bytes)
    {
        _bytes = bytes;
    }

    public EncryptedBlob(byte version, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
    {
        if (nonce.Length != CryptoConstants.GcmNonceLengthBytes)
        {
            throw new ArgumentException($"Nonce must be {CryptoConstants.GcmNonceLengthBytes} bytes.", nameof(nonce));
        }

        if (tag.Length != CryptoConstants.GcmTagLengthBytes)
        {
            throw new ArgumentException($"Tag must be {CryptoConstants.GcmTagLengthBytes} bytes.", nameof(tag));
        }

        _bytes = new byte[HeaderLength + ciphertext.Length + CryptoConstants.GcmTagLengthBytes];
        _bytes[0] = version;
        nonce.CopyTo(_bytes.AsSpan(VersionLength));
        ciphertext.CopyTo(_bytes.AsSpan(HeaderLength));
        tag.CopyTo(_bytes.AsSpan(HeaderLength + ciphertext.Length));
    }

    private const int VersionLength = 1;
    private const int HeaderLength = VersionLength + CryptoConstants.GcmNonceLengthBytes;
    private const int MinLength = HeaderLength + CryptoConstants.GcmTagLengthBytes;

    public byte Version => _bytes[0];

    public ReadOnlySpan<byte> Nonce => _bytes.AsSpan(VersionLength, CryptoConstants.GcmNonceLengthBytes);

    public ReadOnlySpan<byte> Ciphertext =>
        _bytes.AsSpan(HeaderLength, _bytes.Length - MinLength);

    public ReadOnlySpan<byte> Tag =>
        _bytes.AsSpan(_bytes.Length - CryptoConstants.GcmTagLengthBytes, CryptoConstants.GcmTagLengthBytes);

    public byte[] ToBytes() => (byte[])_bytes.Clone();

    public static EncryptedBlob FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length < MinLength)
        {
            throw new ArgumentException(
                $"Encrypted blob must be at least {MinLength} bytes.", nameof(bytes));
        }

        return new EncryptedBlob((byte[])bytes.Clone());
    }
}
