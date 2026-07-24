using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

public sealed class RecoveryKeyService : IRecoveryKeyService
{
    // Domain separation: without this, DeriveRecoveryAuthHash(key) would be indistinguishable from
    // a plain SHA-256(key) computed for some unrelated purpose, which would let a hash collected in
    // one context be replayed as proof-of-possession in another.
    private static readonly byte[] DomainSeparator = Encoding.UTF8.GetBytes("CffVaultManager-recovery-auth-v1");

    public byte[] GenerateRecoveryKey() => RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);

    public byte[] DeriveRecoveryAuthHash(ReadOnlySpan<byte> recoveryKey)
    {
        if (recoveryKey.Length != CryptoConstants.KeyLengthBytes)
        {
            throw new ArgumentException($"Recovery key must be {CryptoConstants.KeyLengthBytes} bytes.", nameof(recoveryKey));
        }

        byte[] input = new byte[recoveryKey.Length + DomainSeparator.Length];
        try
        {
            recoveryKey.CopyTo(input);
            DomainSeparator.CopyTo(input.AsSpan(recoveryKey.Length));
            return SHA256.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }
}
