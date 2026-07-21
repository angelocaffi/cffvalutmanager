using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

/// <inheritdoc cref="ICryptoWalletValidationService"/>
public sealed class CryptoWalletValidationService : ICryptoWalletValidationService
{
    private static readonly int[] ValidMnemonicWordCounts = { 12, 15, 18, 21, 24 };

    public WalletNetwork DetectNetwork(string address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (IsHexAddress(address)) return WalletNetwork.Ethereum;
        if (address.StartsWith("bc1", StringComparison.OrdinalIgnoreCase)) return WalletNetwork.Bitcoin;
        if (address.StartsWith("ltc1", StringComparison.OrdinalIgnoreCase)) return WalletNetwork.Litecoin;
        if (address.Length > 0 && (address[0] == '1' || address[0] == '3')) return WalletNetwork.Bitcoin;
        if (address.Length > 0 && address[0] == 'L') return WalletNetwork.Litecoin;

        return WalletNetwork.Unknown;
    }

    public bool IsPlausibleAddress(string address)
    {
        ArgumentNullException.ThrowIfNull(address);

        return DetectNetwork(address) switch
        {
            WalletNetwork.Ethereum => IsHexAddress(address),
            WalletNetwork.Bitcoin or WalletNetwork.Litecoin => IsPlausibleBase58OrBech32(address),
            _ => false,
        };
    }

    public bool IsPlausibleMnemonicWordCount(string mnemonic)
    {
        ArgumentNullException.ThrowIfNull(mnemonic);

        int wordCount = mnemonic.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length;
        return ValidMnemonicWordCounts.Contains(wordCount);
    }

    public string MaskSecret(string value, int visibleSuffixLength = 4)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (visibleSuffixLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(visibleSuffixLength), "Must be zero or greater.");
        }

        if (value.Length < visibleSuffixLength)
        {
            throw new ArgumentException($"Value must be at least {visibleSuffixLength} characters to mask.", nameof(value));
        }

        return new string('•', value.Length - visibleSuffixLength) + value[(value.Length - visibleSuffixLength)..];
    }

    private static bool IsHexAddress(string address) =>
        address.Length == 42 && address.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && address[2..].All(Uri.IsHexDigit);

    // Loose length/charset plausibility only — not a Base58Check or bech32 checksum validation
    // (see the interface doc comment).
    private static bool IsPlausibleBase58OrBech32(string address) =>
        address.Length is >= 25 and <= 62 && address.All(char.IsLetterOrDigit);
}
