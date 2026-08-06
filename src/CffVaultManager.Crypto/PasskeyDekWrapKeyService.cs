using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

/// <summary>
/// Derives the passkey DEK-wrap key from a WebAuthn PRF output via a single HMAC-SHA256 round —
/// not HKDF, not any other new primitive: HMAC-SHA256 is the one keyed-hash function already
/// proven to work client-side under Blazor WASM in this project (see
/// <see cref="AuthHashService.DeriveAuthHash"/>), and the PRF output is already uniformly random
/// (that's the whole point of a PRF), so a single HMAC round is sufficient — no need for a full
/// HKDF-Extract+Expand ceremony meant for possibly-non-uniform input.
/// </summary>
public sealed class PasskeyDekWrapKeyService : IPasskeyDekWrapKeyService
{
    /// <summary>Domain-separation context, not a secret — fixed and public, mirrors the fixed PRF eval salt set server-side.</summary>
    private static readonly byte[] Context = Encoding.UTF8.GetBytes("CffVaultManager:PasskeyDekWrap:v1");

    public byte[] DeriveKey(ReadOnlySpan<byte> prfOutput)
    {
        if (prfOutput.IsEmpty)
        {
            throw new ArgumentException("PRF output must not be empty.", nameof(prfOutput));
        }

        return HMACSHA256.HashData(prfOutput, Context);
    }
}
