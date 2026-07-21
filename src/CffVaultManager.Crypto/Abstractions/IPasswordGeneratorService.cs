namespace CffVaultManager.Crypto.Abstractions;

public interface IPasswordGeneratorService
{
    /// <summary>Generates a random password using a cryptographically secure RNG.</summary>
    /// <exception cref="ArgumentException">No character set is selected, or the length is too short to fit one character from each selected set.</exception>
    string GeneratePassword(PasswordGeneratorOptions options);

    /// <summary>Generates a word-based passphrase (e.g. "amber-tunnel-glow-42") using a cryptographically secure RNG.</summary>
    /// <exception cref="ArgumentException"><see cref="PassphraseGeneratorOptions.WordCount"/> is less than 1.</exception>
    string GeneratePassphrase(PassphraseGeneratorOptions options);
}
