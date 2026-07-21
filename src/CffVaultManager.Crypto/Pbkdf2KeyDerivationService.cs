using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

/// <summary>
/// PBKDF2 (HMAC-SHA256) fallback for environments where Argon2 is unavailable.
/// Ignores <see cref="Argon2Parameters.MemoryKb"/>/<see cref="Argon2Parameters.DegreeOfParallelism"/>;
/// uses the iteration count only, with a strong floor.
/// </summary>
public sealed class Pbkdf2KeyDerivationService : IKeyDerivationService
{
    /// <summary>OWASP-recommended minimum for PBKDF2-HMAC-SHA256 (2023+).</summary>
    public const int MinimumIterations = 600_000;

    private readonly int _iterations;

    public Pbkdf2KeyDerivationService(int iterations = MinimumIterations)
    {
        _iterations = Math.Max(iterations, MinimumIterations);
    }

    public DerivedKey DeriveKek(ReadOnlySpan<char> masterPassword, byte[] salt, Argon2Parameters parameters)
    {
        if (masterPassword.IsEmpty)
        {
            throw new ArgumentException("Master password must not be empty.", nameof(masterPassword));
        }

        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length == 0)
        {
            throw new ArgumentException("Salt must not be empty.", nameof(salt));
        }

        byte[] passwordBytes = EncodeToUtf8(masterPassword);
        try
        {
            byte[] key = Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes,
                salt,
                _iterations,
                HashAlgorithmName.SHA256,
                CryptoConstants.KeyLengthBytes);

            return new DerivedKey(key);
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
