using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

/// <inheritdoc cref="ICardValidationService"/>
public sealed class CardValidationService : ICardValidationService
{
    public bool IsValidCardNumber(string cardNumber)
    {
        string digits = CleanDigits(cardNumber);
        if (digits.Length < 12 || digits.Length > 19 || !digits.All(char.IsAsciiDigit))
        {
            return false;
        }

        // Luhn checksum: double every second digit from the right, subtracting 9 if it overflows.
        int sum = 0;
        bool doubleDigit = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int d = digits[i] - '0';
            if (doubleDigit)
            {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            doubleDigit = !doubleDigit;
        }

        return sum % 10 == 0;
    }

    public CardBrand DetectBrand(string cardNumber)
    {
        string digits = CleanDigits(cardNumber);
        if (digits.Length == 0 || !digits.All(char.IsAsciiDigit))
        {
            return CardBrand.Unknown;
        }

        if (digits[0] == '4') return CardBrand.Visa;
        if (PrefixInRange(digits, 2, 34, 34) || PrefixInRange(digits, 2, 37, 37)) return CardBrand.AmericanExpress;
        if (PrefixInRange(digits, 4, 3528, 3589)) return CardBrand.Jcb;
        if (PrefixInRange(digits, 3, 300, 305) || PrefixInRange(digits, 2, 36, 36) || PrefixInRange(digits, 2, 38, 38)) return CardBrand.DinersClub;
        if (PrefixInRange(digits, 4, 6011, 6011) || PrefixInRange(digits, 2, 65, 65) || PrefixInRange(digits, 3, 644, 649)) return CardBrand.Discover;
        if (PrefixInRange(digits, 2, 62, 62)) return CardBrand.UnionPay;
        if (PrefixInRange(digits, 2, 51, 55) || PrefixInRange(digits, 4, 2221, 2720)) return CardBrand.Mastercard;

        return CardBrand.Unknown;
    }

    public string MaskCardNumber(string cardNumber)
    {
        string digits = CleanDigits(cardNumber);
        if (digits.Length < 4)
        {
            throw new ArgumentException("Card number must have at least 4 digits to mask.", nameof(cardNumber));
        }

        string masked = new string('•', digits.Length - 4) + digits[^4..];

        var chunks = new List<string>();
        for (int i = 0; i < masked.Length; i += 4)
        {
            chunks.Add(masked.Substring(i, Math.Min(4, masked.Length - i)));
        }

        return string.Join(' ', chunks);
    }

    private static bool PrefixInRange(string digits, int prefixLength, int min, int max)
    {
        if (digits.Length < prefixLength)
        {
            return false;
        }

        int prefix = int.Parse(digits[..prefixLength]);
        return prefix >= min && prefix <= max;
    }

    private static string CleanDigits(string cardNumber)
    {
        ArgumentNullException.ThrowIfNull(cardNumber);
        return cardNumber.Replace(" ", "").Replace("-", "");
    }
}
