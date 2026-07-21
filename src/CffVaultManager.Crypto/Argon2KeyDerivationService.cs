using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Crypto.Abstractions;
using Konscious.Security.Cryptography;

namespace CffVaultManager.Crypto;

public sealed class Argon2KeyDerivationService : IKeyDerivationService
{
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

        ArgumentNullException.ThrowIfNull(parameters);

        byte[] passwordBytes = EncodeToUtf8(masterPassword);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                // Always 1, whatever the caller put in parameters: Blazor WASM cannot run
                // Argon2 lanes on real threads, so parallelism is unreliable there.
                DegreeOfParallelism = Argon2Parameters.EnforcedDegreeOfParallelism,
                Iterations = parameters.Iterations,
                MemorySize = parameters.MemoryKb,
            };

            return new DerivedKey(argon2.GetBytes(CryptoConstants.KeyLengthBytes));
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
