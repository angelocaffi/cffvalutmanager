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

    /// <summary>
    /// Same derivation as <see cref="DeriveKek"/>, but awaited rather than blocking. Required in
    /// Blazor WebAssembly: Konscious's synchronous <c>Argon2.GetBytes</c> blocks internally via
    /// <c>Task.Result</c>, which throws <see cref="PlatformNotSupportedException"/> ("Cannot wait
    /// on monitors on this runtime") under the single-threaded WASM runtime — confirmed live in a
    /// browser, not just desktop tests (see docs/features/encryption-key-management.md). The
    /// password is taken as <see cref="string"/>, not <see cref="ReadOnlySpan{Char}"/>: spans
    /// cannot cross an <c>await</c> boundary.
    /// </summary>
    Task<DerivedKey> DeriveKekAsync(string masterPassword, byte[] salt, Argon2Parameters parameters);
}
