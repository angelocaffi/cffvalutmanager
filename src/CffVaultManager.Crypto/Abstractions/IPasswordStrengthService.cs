namespace CffVaultManager.Crypto.Abstractions;

/// <summary>
/// Client-side password strength estimation (see docs/features/password-health.md). Runs entirely
/// in the browser on an already-decrypted password — nothing here ever touches the server.
/// </summary>
public interface IPasswordStrengthService
{
    /// <summary>Estimates entropy from character-set diversity and length, and buckets it into a strength level.</summary>
    PasswordStrengthResult EstimateStrength(string password);
}
