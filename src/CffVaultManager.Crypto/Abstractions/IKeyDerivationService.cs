namespace CffVaultManager.Crypto.Abstractions;

public interface IKeyDerivationService
{
    /// <summary>
    /// Derives a 32-byte key-encryption key from the master password.
    /// </summary>
    /// <remarks>
    /// The master password is taken as <see cref="ReadOnlySpan{Char}"/> rather than
    /// <see cref="string"/> so the caller can hold it in a buffer it can zero out;
    /// interned/GC-managed strings cannot be reliably wiped from memory.
    /// </remarks>
    DerivedKey DeriveKek(ReadOnlySpan<char> masterPassword, byte[] salt, Argon2Parameters parameters);
}
