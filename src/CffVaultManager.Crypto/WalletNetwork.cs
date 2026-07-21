namespace CffVaultManager.Crypto;

/// <summary>
/// Blockchain network, detected client-side from an address's format for UX purposes only (icon
/// selection) — never used to validate or move funds (see docs/features/crypto-wallets.md).
/// </summary>
public enum WalletNetwork
{
    Unknown,
    Bitcoin,
    Ethereum,
    Litecoin,
}
