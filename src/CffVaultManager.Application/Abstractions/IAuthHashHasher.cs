namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Re-hashes the client-supplied auth hash before it is persisted, and verifies it at login.
/// </summary>
/// <remarks>
/// The client already sends a one-way auth hash (never the master password), but storing that
/// value verbatim would let anyone with a database dump replay it directly against the login
/// endpoint. A per-record salted server-side rehash means the stored value is useless without
/// recomputation, so a leaked table cannot be used to authenticate as-is.
/// </remarks>
public interface IAuthHashHasher
{
    /// <summary>Produces a salted, server-side rehash of <paramref name="authHash"/> suitable for storage.</summary>
    byte[] Hash(byte[] authHash);

    /// <summary>Constant-time verification of <paramref name="authHash"/> against a previously stored value.</summary>
    bool Verify(byte[] authHash, byte[] storedHash);
}
