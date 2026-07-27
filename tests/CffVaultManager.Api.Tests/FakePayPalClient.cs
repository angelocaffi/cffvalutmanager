using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Billing;

namespace CffVaultManager.Api.Tests;

/// <summary>Test double for <see cref="IPayPalClient"/>, swapped in per-test via a customized <see cref="ApiTestFactory"/> host — no real PayPal call.</summary>
public sealed class FakePayPalClient : IPayPalClient
{
    public string NextOrderId { get; set; } = "ORDER-FAKE";

    public string NextCaptureStatus { get; set; } = "COMPLETED";

    public Task<string> CreateOrderAsync(decimal amount, string currency, CancellationToken ct = default) =>
        Task.FromResult(NextOrderId);

    public Task<PayPalOrderCapture> CaptureOrderAsync(string orderId, CancellationToken ct = default) =>
        Task.FromResult(new PayPalOrderCapture(NextCaptureStatus, "CAPTURE-FAKE"));
}
