using System.Security.Cryptography;
using System.Text;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Shared hashing for <see cref="CffVaultManager.Domain.Entities.OneTimeCode"/>, used by every
/// purpose (email verification, Email OTP MFA): HMAC-SHA256 salted per record, not Argon2id — a
/// deliberately cheap hash, because the real defenses against brute force for a short-lived 6-digit
/// code are its expiry, its per-code attempt cap, and IP rate limiting on the HTTP endpoints, not
/// an expensive KDF that would only slow down legitimate retries.
/// </summary>
internal static class OneTimeCodeHasher
{
    private const int SaltLength = 16;
    private const int DigestLength = 32;

    public static string GenerateNumericCode() => RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");

    public static byte[] Hash(string code)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
        byte[] digest = HMACSHA256.HashData(salt, Encoding.UTF8.GetBytes(code));

        byte[] stored = new byte[SaltLength + DigestLength];
        salt.CopyTo(stored, 0);
        digest.CopyTo(stored, SaltLength);
        return stored;
    }

    public static bool Verify(string code, byte[] storedHash)
    {
        if (storedHash.Length != SaltLength + DigestLength)
        {
            return false;
        }

        byte[] salt = storedHash.AsSpan(0, SaltLength).ToArray();
        byte[] expected = storedHash.AsSpan(SaltLength, DigestLength).ToArray();
        byte[] actual = HMACSHA256.HashData(salt, Encoding.UTF8.GetBytes(code));
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
