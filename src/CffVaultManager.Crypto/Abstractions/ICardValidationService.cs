namespace CffVaultManager.Crypto.Abstractions;

/// <summary>
/// Client-side helpers for credit-card entry (see docs/features/credit-cards.md). These never
/// touch the server: card numbers are validated and masked in the browser, before encryption,
/// so the plaintext number never needs to round-trip for a format check.
/// </summary>
public interface ICardValidationService
{
    /// <summary>
    /// Validates a card number using the Luhn checksum. Tolerant of spaces/dashes; returns
    /// <c>false</c> (never throws) for malformed input so it can back live form validation.
    /// </summary>
    bool IsValidCardNumber(string cardNumber);

    /// <summary>Detects the card network from the number prefix. Returns <see cref="CardBrand.Unknown"/> for malformed or unrecognized input — this is a UX nicety, not a definitive classification.</summary>
    CardBrand DetectBrand(string cardNumber);

    /// <summary>Masks all but the last 4 digits (e.g. "•••• •••• •••• 1234"), grouped in blocks of 4.</summary>
    /// <exception cref="ArgumentException">Fewer than 4 digits after stripping spaces/dashes.</exception>
    string MaskCardNumber(string cardNumber);
}
