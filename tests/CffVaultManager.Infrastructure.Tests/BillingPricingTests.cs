using CffVaultManager.Domain.Entities;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>Pure-entity coverage of <see cref="BillingPricing"/> — no database involved (see docs/features/billing.md "Prezzo modificabile da SuperAdmin").</summary>
public sealed class BillingPricingTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static BillingPricing NewPricing(decimal standardPrice = 49.00m) =>
        new(standardPrice, null, null, null, Guid.NewGuid(), Now);

    [Fact]
    public void Constructor_standardPriceZeroOrNegative_throws()
    {
        Assert.Throws<ArgumentException>(() => new BillingPricing(0m, null, null, null, Guid.NewGuid(), Now));
        Assert.Throws<ArgumentException>(() => new BillingPricing(-1m, null, null, null, Guid.NewGuid(), Now));
    }

    [Fact]
    public void Update_discountWithoutExpiry_throws()
    {
        var pricing = NewPricing();
        Assert.Throws<ArgumentException>(() => pricing.Update(49.00m, 29.00m, null, null, Guid.NewGuid(), Now));
    }

    [Fact]
    public void Update_expiryWithoutDiscount_throws()
    {
        var pricing = NewPricing();
        Assert.Throws<ArgumentException>(() => pricing.Update(49.00m, null, Now.AddDays(7), null, Guid.NewGuid(), Now));
    }

    [Fact]
    public void Update_discountedPriceNotLowerThanStandard_throws()
    {
        var pricing = NewPricing();
        Assert.Throws<ArgumentException>(() => pricing.Update(49.00m, 49.00m, Now.AddDays(7), null, Guid.NewGuid(), Now));
        Assert.Throws<ArgumentException>(() => pricing.Update(49.00m, 50.00m, Now.AddDays(7), null, Guid.NewGuid(), Now));
    }

    [Fact]
    public void Update_discountedPriceZeroOrNegative_throws()
    {
        var pricing = NewPricing();
        Assert.Throws<ArgumentException>(() => pricing.Update(49.00m, 0m, Now.AddDays(7), null, Guid.NewGuid(), Now));
    }

    [Fact]
    public void Update_expiryInThePastOrNow_throws()
    {
        var pricing = NewPricing();
        Assert.Throws<ArgumentException>(() => pricing.Update(49.00m, 29.00m, Now.AddDays(-1), null, Guid.NewGuid(), Now));
        Assert.Throws<ArgumentException>(() => pricing.Update(49.00m, 29.00m, Now, null, Guid.NewGuid(), Now));
    }

    [Fact]
    public void Update_promoMessageOver280Characters_throws()
    {
        var pricing = NewPricing();
        Assert.Throws<ArgumentException>(() => pricing.Update(49.00m, null, null, new string('x', 281), Guid.NewGuid(), Now));
    }

    [Fact]
    public void Update_validDiscount_setsAllFields_andIsDiscountActive()
    {
        var pricing = NewPricing();
        var expiry = Now.AddDays(7);
        pricing.Update(49.00m, 29.00m, expiry, "Offerta di lancio", Guid.NewGuid(), Now);

        Assert.Equal(29.00m, pricing.DiscountedAnnualPrice);
        Assert.Equal(expiry, pricing.DiscountExpiresAt);
        Assert.Equal("Offerta di lancio", pricing.PromoMessage);
        Assert.True(pricing.IsDiscountActive(Now));
        Assert.Equal(29.00m, pricing.EffectivePrice(Now));
    }

    [Fact]
    public void IsDiscountActive_falseOnceExpiryHasPassed()
    {
        var pricing = NewPricing();
        var expiry = Now.AddDays(7);
        pricing.Update(49.00m, 29.00m, expiry, null, Guid.NewGuid(), Now);

        Assert.False(pricing.IsDiscountActive(expiry.AddSeconds(1)));
        Assert.Equal(49.00m, pricing.EffectivePrice(expiry.AddSeconds(1)));
    }

    [Fact]
    public void Update_clearingTheDiscount_byPassingBothNull_succeeds()
    {
        var pricing = NewPricing();
        pricing.Update(49.00m, 29.00m, Now.AddDays(7), "promo", Guid.NewGuid(), Now);

        pricing.Update(49.00m, null, null, null, Guid.NewGuid(), Now);

        Assert.Null(pricing.DiscountedAnnualPrice);
        Assert.Null(pricing.DiscountExpiresAt);
        Assert.Null(pricing.PromoMessage);
        Assert.False(pricing.IsDiscountActive(Now));
    }

    [Fact]
    public void Update_blankPromoMessage_isStoredAsNull()
    {
        var pricing = NewPricing();
        pricing.Update(49.00m, null, null, "   ", Guid.NewGuid(), Now);

        Assert.Null(pricing.PromoMessage);
    }
}
