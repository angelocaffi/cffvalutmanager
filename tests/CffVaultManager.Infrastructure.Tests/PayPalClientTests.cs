using CffVaultManager.Infrastructure.Billing;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Coverage of <see cref="PayPalClient"/> against a fake <see cref="HttpMessageHandler"/> — no real
/// network call ever happens in this test class (see docs/features/billing.md "Test previsti").
/// </summary>
public sealed class PayPalClientTests
{
    [Fact]
    public async Task CreateOrderAsync_ReturnsTheOrderId()
    {
        var handler = new FakePayPalHttpMessageHandler();
        var client = new PayPalClient(new FakeHttpClientFactory(handler), TestConfiguration.PayPal());

        string orderId = await client.CreateOrderAsync(49.00m, "EUR");

        Assert.Equal("ORDER-123", orderId);
    }

    [Fact]
    public async Task CreateOrderAsync_SendsAnAuthorizationBearerHeaderFromTheOAuthToken()
    {
        var handler = new FakePayPalHttpMessageHandler();
        var client = new PayPalClient(new FakeHttpClientFactory(handler), TestConfiguration.PayPal());

        await client.CreateOrderAsync(49.00m, "EUR");

        var orderRequest = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/v2/checkout/orders");
        Assert.Equal("Bearer", orderRequest.Headers.Authorization!.Scheme);
        Assert.Equal("fake-access-token", orderRequest.Headers.Authorization.Parameter);
    }

    [Fact]
    public async Task AccessToken_IsCachedAcrossMultipleCalls()
    {
        var handler = new FakePayPalHttpMessageHandler();
        var client = new PayPalClient(new FakeHttpClientFactory(handler), TestConfiguration.PayPal());

        await client.CreateOrderAsync(49.00m, "EUR");
        await client.CreateOrderAsync(49.00m, "EUR");
        await client.CaptureOrderAsync("ORDER-123");

        Assert.Equal(1, handler.TokenRequestCount);
    }

    [Fact]
    public async Task CaptureOrderAsync_ReturnsStatusAndCaptureId()
    {
        var handler = new FakePayPalHttpMessageHandler();
        var client = new PayPalClient(new FakeHttpClientFactory(handler), TestConfiguration.PayPal());

        var result = await client.CaptureOrderAsync("ORDER-123");

        Assert.Equal("COMPLETED", result.Status);
        Assert.Equal("CAPTURE-123", result.CaptureId);
    }

    [Fact]
    public async Task CaptureOrderAsync_WhenPayPalReportsANonCompletedStatus_ReturnsItAsIs()
    {
        var handler = new FakePayPalHttpMessageHandler { CaptureStatus = "PENDING" };
        var client = new PayPalClient(new FakeHttpClientFactory(handler), TestConfiguration.PayPal());

        var result = await client.CaptureOrderAsync("ORDER-123");

        Assert.Equal("PENDING", result.Status);
    }
}
