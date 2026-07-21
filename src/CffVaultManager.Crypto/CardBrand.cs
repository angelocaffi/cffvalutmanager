namespace CffVaultManager.Crypto;

/// <summary>
/// Payment card network, detected client-side from the number prefix for UX purposes only (icon
/// selection) — never used for payment processing (see docs/features/credit-cards.md).
/// </summary>
public enum CardBrand
{
    Unknown,
    Visa,
    Mastercard,
    AmericanExpress,
    Discover,
    DinersClub,
    Jcb,
    UnionPay,
}
