using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Billing;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>Test double for <see cref="IPayPalClient"/> — no real PayPal call, used by <see cref="BillingService"/> tests.</summary>
internal sealed class FakePayPalClient : IPayPalClient
{
    public string NextOrderId { get; set; } = "ORDER-1";

    public string NextCaptureStatus { get; set; } = "COMPLETED";

    public int CreateOrderCallCount { get; private set; }

    public int CaptureOrderCallCount { get; private set; }

    public Task<string> CreateOrderAsync(decimal amount, string currency, CancellationToken ct = default)
    {
        CreateOrderCallCount++;
        return Task.FromResult(NextOrderId);
    }

    public Task<PayPalOrderCapture> CaptureOrderAsync(string orderId, CancellationToken ct = default)
    {
        CaptureOrderCallCount++;
        return Task.FromResult(new PayPalOrderCapture(NextCaptureStatus, "CAPTURE-FAKE"));
    }
}
