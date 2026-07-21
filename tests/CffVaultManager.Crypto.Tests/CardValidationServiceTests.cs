namespace CffVaultManager.Crypto.Tests;

public class CardValidationServiceTests
{
    private readonly CardValidationService _service = new();

    // Well-known publicly documented test card numbers (Stripe/PayPal sandbox docs) — not real cards.
    [Theory]
    [InlineData("4111111111111111")]
    [InlineData("4111 1111 1111 1111")]
    [InlineData("4111-1111-1111-1111")]
    [InlineData("5555555555554444")]
    [InlineData("378282246310005")]
    [InlineData("6011111111111117")]
    [InlineData("30569309025904")]
    [InlineData("3530111333300000")]
    public void IsValidCardNumber_WithKnownValidNumbers_ReturnsTrue(string cardNumber)
    {
        Assert.True(_service.IsValidCardNumber(cardNumber));
    }

    [Theory]
    [InlineData("4111111111111112")] // last digit flipped, breaks the Luhn checksum
    [InlineData("1234567890123")]
    [InlineData("")]
    [InlineData("411111111111111a")]
    [InlineData("123")] // too short
    [InlineData("41111111111111111111")] // too long
    public void IsValidCardNumber_WithInvalidNumbers_ReturnsFalse(string cardNumber)
    {
        Assert.False(_service.IsValidCardNumber(cardNumber));
    }

    [Fact]
    public void IsValidCardNumber_WithNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.IsValidCardNumber(null!));
    }

    [Theory]
    [InlineData("4111111111111111", CardBrand.Visa)]
    [InlineData("5555555555554444", CardBrand.Mastercard)]
    [InlineData("2221000000000009", CardBrand.Mastercard)]
    [InlineData("378282246310005", CardBrand.AmericanExpress)]
    [InlineData("6011111111111117", CardBrand.Discover)]
    [InlineData("30569309025904", CardBrand.DinersClub)]
    [InlineData("3530111333300000", CardBrand.Jcb)]
    [InlineData("6222020000000005", CardBrand.UnionPay)]
    [InlineData("9999999999999999", CardBrand.Unknown)]
    [InlineData("", CardBrand.Unknown)]
    public void DetectBrand_ReturnsExpectedBrand(string cardNumber, CardBrand expected)
    {
        Assert.Equal(expected, _service.DetectBrand(cardNumber));
    }

    [Fact]
    public void MaskCardNumber_ShowsOnlyLastFourDigits()
    {
        string masked = _service.MaskCardNumber("4111111111111111");

        Assert.EndsWith("1111", masked.Replace(" ", ""));
        Assert.DoesNotContain("4111111111111", masked.Replace(" ", "").Replace("•", ""));
    }

    [Fact]
    public void MaskCardNumber_GroupsInBlocksOfFour()
    {
        string masked = _service.MaskCardNumber("4111111111111111");
        Assert.Equal("•••• •••• •••• 1111", masked);
    }

    [Fact]
    public void MaskCardNumber_StripsSpacesAndDashesBeforeMasking()
    {
        Assert.Equal(
            _service.MaskCardNumber("4111111111111111"),
            _service.MaskCardNumber("4111-1111-1111-1111"));
    }

    [Fact]
    public void MaskCardNumber_WithFewerThanFourDigits_Throws()
    {
        Assert.Throws<ArgumentException>(() => _service.MaskCardNumber("123"));
    }
}
