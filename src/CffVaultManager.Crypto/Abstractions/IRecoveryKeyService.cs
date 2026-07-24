namespace CffVaultManager.Crypto.Abstractions;

/// <summary>
/// Client-side primitives for the recovery kit (see docs/security-model.md#recovery-kit). The
/// Recovery Key itself is wrapped around the DEK via the existing generic <see cref="IDekService"/>
/// (no new AEAD code needed) — this interface only covers the two pieces that don't fit anywhere
/// else: generating the key and deriving the server-verifiable proof of possession.
/// </summary>
public interface IRecoveryKeyService
{
    /// <summary>A fresh, high-entropy 256-bit Recovery Key. Never persisted after first display.</summary>
    byte[] GenerateRecoveryKey();

    /// <summary>
    /// A deterministic, domain-separated hash of the Recovery Key, sent to the server as proof of
    /// possession (mirrors AuthHash for the master password). Deliberately not Argon2id: the input
    /// is already 256 bits of RNG output, not a human-chosen low-entropy secret — memory-hardening
    /// it would add cost without adding security.
    /// </summary>
    byte[] DeriveRecoveryAuthHash(ReadOnlySpan<byte> recoveryKey);
}
