using System.Security.Cryptography;
using CffVaultManager.Crypto.Abstractions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CffVaultManager.Crypto;

/// <summary>
/// AES-256-GCM via BouncyCastle's managed <see cref="GcmBlockCipher"/> rather than
/// <see cref="System.Security.Cryptography.AesGcm"/>: the BCL's <c>AesGcm</c> throws
/// <see cref="PlatformNotSupportedException"/> under the Blazor WASM (browser-wasm) runtime this
/// library must run under client-side — confirmed live in-browser — because it has no OS-native
/// crypto provider to call into there. BouncyCastle's implementation is pure managed code and
/// behaves identically on both the server .NET runtime and browser-wasm.
/// </summary>
public sealed class AesGcmCipherService : IAeadCipherService
{
    private const int MacSizeBits = CryptoConstants.GcmTagLengthBytes * 8;

    public EncryptedBlob Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad = default)
    {
        if (key.Length != CryptoConstants.KeyLengthBytes)
        {
            throw new ArgumentException($"Key must be {CryptoConstants.KeyLengthBytes} bytes.", nameof(key));
        }

        byte[] nonce = RandomNumberGenerator.GetBytes(CryptoConstants.GcmNonceLengthBytes);

        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(true, BuildParameters(key, nonce, aad));

        byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];
        int len = cipher.ProcessBytes(plaintext.ToArray(), 0, plaintext.Length, output, 0);
        len += cipher.DoFinal(output, len);

        // BouncyCastle appends the tag to the ciphertext in its output; split it back apart to
        // match EncryptedBlob's [version][nonce][ciphertext][tag] layout.
        int ciphertextLength = len - CryptoConstants.GcmTagLengthBytes;
        ReadOnlySpan<byte> ciphertext = output.AsSpan(0, ciphertextLength);
        ReadOnlySpan<byte> tag = output.AsSpan(ciphertextLength, CryptoConstants.GcmTagLengthBytes);

        return new EncryptedBlob(CryptoConstants.CurrentBlobVersion, nonce, ciphertext, tag);
    }

    public byte[] Decrypt(EncryptedBlob blob, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad = default)
    {
        ArgumentNullException.ThrowIfNull(blob);
        if (key.Length != CryptoConstants.KeyLengthBytes)
        {
            throw new ArgumentException($"Key must be {CryptoConstants.KeyLengthBytes} bytes.", nameof(key));
        }

        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(false, BuildParameters(key, blob.Nonce.ToArray(), aad));

        // BouncyCastle expects ciphertext and tag as one contiguous input for decryption.
        byte[] input = new byte[blob.Ciphertext.Length + CryptoConstants.GcmTagLengthBytes];
        blob.Ciphertext.CopyTo(input);
        blob.Tag.CopyTo(input.AsSpan(blob.Ciphertext.Length));

        byte[] output = new byte[cipher.GetOutputSize(input.Length)];

        try
        {
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);
            return len == output.Length ? output : output[..len];
        }
        catch (InvalidCipherTextException ex)
        {
            // Wrong key / tampered ciphertext / tampered tag / tampered AAD all surface here;
            // normalize to the exception type callers (and existing tests) expect.
            throw new CryptographicException("The authentication tag did not verify.", ex);
        }
    }

    private static AeadParameters BuildParameters(ReadOnlySpan<byte> key, byte[] nonce, ReadOnlySpan<byte> aad) =>
        new(new KeyParameter(key.ToArray()), MacSizeBits, nonce, aad.IsEmpty ? null : aad.ToArray());
}
