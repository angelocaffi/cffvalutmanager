namespace CffVaultManager.Crypto.Abstractions;

/// <summary>
/// Checks whether a password appears in known breach corpora, using the Have I Been Pwned
/// k-anonymity range API (see docs/features/password-health.md and docs/security-model.md). Only
/// the first 5 hex characters of the password's SHA-1 hash are ever sent over the network — never
/// the password or its full hash — the one deliberate, documented exception to this project's
/// "nothing about a secret ever leaves the client unencrypted" rule, because even that partial
/// hash prefix cannot be reversed to the original password.
/// </summary>
public interface IBreachCheckService
{
    /// <summary>Returns how many times the password has been seen in known breaches (0 = not found).</summary>
    Task<long> CheckPasswordAsync(string password, CancellationToken ct = default);
}
