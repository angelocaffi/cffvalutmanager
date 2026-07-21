using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

/// <summary>
/// Estimates password strength from character-set diversity and length
/// (bits ≈ length × log2(pool size)) — the same simple, widely-used baseline most strength meters
/// use. Deliberately not a full pattern-aware estimator (à la zxcvbn): it won't detect a repeated
/// or dictionary-word password scoring artificially high on pool size alone. Runs entirely
/// client-side (this assembly is referenced by the Blazor WASM client); nothing here ever touches
/// the server (see docs/features/password-health.md).
/// </summary>
public sealed class PasswordStrengthService : IPasswordStrengthService
{
    private const int LowercasePoolSize = 26;
    private const int UppercasePoolSize = 26;
    private const int DigitPoolSize = 10;
    private const int SymbolPoolSize = 32;

    // Rough, commonly-cited entropy buckets (bits): <28 crackable in seconds-minutes on
    // consumer hardware, 80+ infeasible for the foreseeable future.
    private const double WeakThreshold = 28;
    private const double FairThreshold = 36;
    private const double StrongThreshold = 60;
    private const double VeryStrongThreshold = 80;

    public PasswordStrengthResult EstimateStrength(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length == 0)
        {
            return new PasswordStrengthResult(0, PasswordStrengthLevel.VeryWeak);
        }

        int poolSize = 0;
        if (password.Any(char.IsLower)) poolSize += LowercasePoolSize;
        if (password.Any(char.IsUpper)) poolSize += UppercasePoolSize;
        if (password.Any(char.IsDigit)) poolSize += DigitPoolSize;
        if (password.Any(c => !char.IsLetterOrDigit(c))) poolSize += SymbolPoolSize;

        double bits = password.Length * Math.Log2(poolSize);

        var level = bits switch
        {
            < WeakThreshold => PasswordStrengthLevel.VeryWeak,
            < FairThreshold => PasswordStrengthLevel.Weak,
            < StrongThreshold => PasswordStrengthLevel.Fair,
            < VeryStrongThreshold => PasswordStrengthLevel.Strong,
            _ => PasswordStrengthLevel.VeryStrong,
        };

        return new PasswordStrengthResult(bits, level);
    }
}
