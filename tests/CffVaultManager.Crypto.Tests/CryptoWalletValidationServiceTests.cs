namespace CffVaultManager.Crypto.Tests;

public class CryptoWalletValidationServiceTests
{
    private readonly CryptoWalletValidationService _service = new();

    // Ethereum: synthetic but correctly formatted (0x + 40 hex chars).
    private const string EthereumAddress = "0x1234567890123456789012345678901234567890";

    // Bitcoin: the genesis-block address (legacy P2PKH) and the official BIP-173 bech32 example.
    private const string BitcoinLegacyAddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    private const string BitcoinP2shAddress = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    private const string BitcoinBech32Address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

    // Litecoin: synthetic but correctly formatted (legacy 'L'/bech32 'ltc1' prefix).
    private const string LitecoinLegacyAddress = "L1234567890abcdefghijklmnopqrstu";
    private const string LitecoinBech32Address = "ltc1q1234567890abcdefghijklmnopqrstuvwx";

    [Theory]
    [InlineData(EthereumAddress, WalletNetwork.Ethereum)]
    [InlineData(BitcoinLegacyAddress, WalletNetwork.Bitcoin)]
    [InlineData(BitcoinP2shAddress, WalletNetwork.Bitcoin)]
    [InlineData(BitcoinBech32Address, WalletNetwork.Bitcoin)]
    [InlineData(LitecoinLegacyAddress, WalletNetwork.Litecoin)]
    [InlineData(LitecoinBech32Address, WalletNetwork.Litecoin)]
    [InlineData("not-an-address", WalletNetwork.Unknown)]
    [InlineData("", WalletNetwork.Unknown)]
    public void DetectNetwork_ReturnsExpectedNetwork(string address, WalletNetwork expected)
    {
        Assert.Equal(expected, _service.DetectNetwork(address));
    }

    [Fact]
    public void DetectNetwork_WithNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.DetectNetwork(null!));
    }

    [Theory]
    [InlineData(EthereumAddress)]
    [InlineData(BitcoinLegacyAddress)]
    [InlineData(BitcoinP2shAddress)]
    [InlineData(BitcoinBech32Address)]
    [InlineData(LitecoinLegacyAddress)]
    [InlineData(LitecoinBech32Address)]
    public void IsPlausibleAddress_WithWellFormedAddresses_ReturnsTrue(string address)
    {
        Assert.True(_service.IsPlausibleAddress(address));
    }

    [Theory]
    [InlineData("0x123")] // too short for Ethereum
    [InlineData("0xZZZ4567890123456789012345678901234567890")] // non-hex characters
    [InlineData("1tooShort")] // too short for Bitcoin-style plausibility
    [InlineData("not-an-address")]
    [InlineData("")]
    public void IsPlausibleAddress_WithMalformedAddresses_ReturnsFalse(string address)
    {
        Assert.False(_service.IsPlausibleAddress(address));
    }

    [Fact]
    public void IsPlausibleAddress_WithNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.IsPlausibleAddress(null!));
    }

    [Theory]
    [InlineData(12)]
    [InlineData(15)]
    [InlineData(18)]
    [InlineData(21)]
    [InlineData(24)]
    public void IsPlausibleMnemonicWordCount_WithValidBip39Counts_ReturnsTrue(int wordCount)
    {
        string mnemonic = string.Join(' ', Enumerable.Repeat("word", wordCount));
        Assert.True(_service.IsPlausibleMnemonicWordCount(mnemonic));
    }

    [Theory]
    [InlineData(11)]
    [InlineData(13)]
    [InlineData(0)]
    [InlineData(25)]
    public void IsPlausibleMnemonicWordCount_WithInvalidCounts_ReturnsFalse(int wordCount)
    {
        string mnemonic = string.Join(' ', Enumerable.Repeat("word", wordCount));
        Assert.False(_service.IsPlausibleMnemonicWordCount(mnemonic));
    }

    [Fact]
    public void IsPlausibleMnemonicWordCount_IgnoresExtraWhitespace()
    {
        string mnemonic = "  " + string.Join("   ", Enumerable.Repeat("word", 12)) + "  ";
        Assert.True(_service.IsPlausibleMnemonicWordCount(mnemonic));
    }

    [Fact]
    public void IsPlausibleMnemonicWordCount_WithNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.IsPlausibleMnemonicWordCount(null!));
    }

    [Fact]
    public void MaskSecret_DefaultsToShowingLastFourCharacters()
    {
        string masked = _service.MaskSecret("abcdef1234567890");
        Assert.Equal("••••••••••••7890", masked);
    }

    [Fact]
    public void MaskSecret_WithCustomSuffixLength_ShowsThatManyCharacters()
    {
        string masked = _service.MaskSecret("abcdef1234567890", visibleSuffixLength: 6);
        Assert.Equal("••••••••••567890", masked);
    }

    [Fact]
    public void MaskSecret_WithValueShorterThanSuffixLength_Throws()
    {
        Assert.Throws<ArgumentException>(() => _service.MaskSecret("ab", visibleSuffixLength: 4));
    }

    [Fact]
    public void MaskSecret_WithNegativeSuffixLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _service.MaskSecret("abcdef", visibleSuffixLength: -1));
    }

    [Fact]
    public void MaskSecret_WithNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.MaskSecret(null!));
    }
}
