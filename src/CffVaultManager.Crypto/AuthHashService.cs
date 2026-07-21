using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

public sealed class AuthHashService : IAuthHashService
{
    public byte[] DeriveAuthHash(DerivedKey kek, ReadOnlySpan<char> masterPassword)
    {
        ArgumentNullException.ThrowIfNull(kek);
        if (masterPassword.IsEmpty)
        {
            throw new ArgumentException("Master password must not be empty.", nameof(masterPassword));
        }

        byte[] passwordBytes = EncodeToUtf8(masterPassword);
        try
        {
            // HMAC-SHA256 keyed by the KEK: a one-way, deterministic 32-byte digest that
            // reveals nothing about the KEK to the server that verifies it.
            return HMACSHA256.HashData(kek.Key, passwordBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] EncodeToUtf8(ReadOnlySpan<char> chars)
    {
        int byteCount = Encoding.UTF8.GetByteCount(chars);
        byte[] bytes = new byte[byteCount];
        Encoding.UTF8.GetBytes(chars, bytes);
        return bytes;
    }
}
