namespace CffVaultManager.Crypto.Abstractions;

public interface IAuthHashService
{
    /// <summary>
    /// Derives a 32-byte authentication hash from the KEK and master password, to be sent
    /// to the server for zero-knowledge login.
    /// </summary>
    /// <remarks>
    /// The auth hash is a one-way function of the KEK and master password: the server can
    /// verify it, but it is computationally infeasible to recover the KEK (and therefore the
    /// DEK/plaintext) from it. The master password is taken as <see cref="ReadOnlySpan{Char}"/>
    /// rather than <see cref="string"/> so the caller can hold it in a buffer it can zero out.
    /// </remarks>
    byte[] DeriveAuthHash(DerivedKey kek, ReadOnlySpan<char> masterPassword);
}
