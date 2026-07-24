using CffVaultManager.Crypto;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Display-only formatting for a raw 256-bit Recovery Key (see docs/security-model.md#recovery-kit)
/// — hex, grouped in dash-separated 8-character blocks for readability when copied/typed by hand.
/// Not a security primitive (no hashing/crypto here, just text shaping), shared between
/// <c>Security.razor</c> (shows a freshly generated key) and <c>Recovery.razor</c> (parses one back
/// in) so the two don't duplicate the same formatting rules.
/// </summary>
public static class RecoveryKeyFormatter
{
    public static string Format(byte[] key) =>
        string.Join('-', Chunk(Convert.ToHexString(key), 8));

    /// <summary>Strips whitespace/dashes and validates length before attempting to parse — a clean, local error beats a cryptic AEAD failure for an obviously mistyped key.</summary>
    public static bool TryParse(string input, out byte[] key)
    {
        string hex = new(input.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != CryptoConstants.KeyLengthBytes * 2)
        {
            key = [];
            return false;
        }

        try
        {
            key = Convert.FromHexString(hex);
            return true;
        }
        catch (FormatException)
        {
            key = [];
            return false;
        }
    }

    private static IEnumerable<string> Chunk(string value, int size)
    {
        for (int i = 0; i < value.Length; i += size)
        {
            yield return value.Substring(i, Math.Min(size, value.Length - i));
        }
    }
}
