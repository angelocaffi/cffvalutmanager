namespace CffVaultManager.Crypto.Abstractions;

/// <summary>
/// Client-side helpers for crypto-wallet entry (see docs/features/crypto-wallets.md). These never
/// touch the server: addresses and mnemonics are checked in the browser, before encryption, so
/// the plaintext secret never needs to round-trip for a format check.
/// </summary>
public interface ICryptoWalletValidationService
{
    /// <summary>Detects the network from an address's format. Returns <see cref="WalletNetwork.Unknown"/> for unrecognized input — this is a UX nicety, not a definitive classification.</summary>
    WalletNetwork DetectNetwork(string address);

    /// <summary>
    /// Checks that an address's length/charset/prefix are plausible for its detected network.
    /// This is a format check only — it does <b>not</b> verify the network's own address
    /// checksum (e.g. Base58Check, EIP-55), so a plausible-looking but invalid address can still
    /// pass. Never throws; returns <c>false</c> for unrecognized or malformed input.
    /// </summary>
    bool IsPlausibleAddress(string address);

    /// <summary>
    /// Checks that a mnemonic recovery phrase has one of the word counts BIP-39 allows (12, 15,
    /// 18, 21 or 24). This is a structural check only — it does <b>not</b> verify that each word
    /// belongs to the official BIP-39 wordlist, nor the phrase's checksum; full BIP-39 validation
    /// is deferred (see docs/features/crypto-wallets.md). Never throws.
    /// </summary>
    bool IsPlausibleMnemonicWordCount(string mnemonic);

    /// <summary>Masks all but the last <paramref name="visibleSuffixLength"/> characters (e.g. "••••••••cdef") — for wallet addresses, private keys, or any other long secret.</summary>
    /// <exception cref="ArgumentException"><paramref name="value"/> is shorter than <paramref name="visibleSuffixLength"/>.</exception>
    string MaskSecret(string value, int visibleSuffixLength = 4);
}
