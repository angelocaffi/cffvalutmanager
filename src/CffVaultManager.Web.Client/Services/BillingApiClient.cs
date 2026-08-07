using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for <c>/api/billing/*</c> (see
/// docs/features/billing.md): trial/paid-plan status and PayPal checkout/capture.
/// </summary>
public sealed class BillingApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;

    public BillingApiClient(HttpClient http) => _http = http;

    public async Task<BillingStatusResponse> GetStatusAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<BillingStatusResponse>("/api/billing/status", JsonOptions, ct))!;

    /// <summary>Creates a PayPal order for the fixed server-configured price; returns its order id to hand to the PayPal JS SDK.</summary>
    public async Task<(string? OrderId, string? Error)> CreateCheckoutAsync(CancellationToken ct = default)
    {
        var response = await _http.PostAsync("/api/billing/checkout", content: null, ct);
        if (response.StatusCode == System.Net.HttpStatusCode.ServiceUnavailable)
        {
            return (null, "Il pagamento non è al momento configurato su questo server.");
        }

        if (!response.IsSuccessStatusCode)
        {
            return (null, "Impossibile avviare il pagamento.");
        }

        var result = await response.Content.ReadFromJsonAsync<CreateCheckoutResponse>(JsonOptions, ct);
        return (result?.OrderId, null);
    }

    public async Task<(bool Success, DateTimeOffset? PlanExpiresAt, string? Error)> CaptureCheckoutAsync(string orderId, CancellationToken ct = default)
    {
        var response = await _http.PostAsync($"/api/billing/checkout/{orderId}/capture", content: null, ct);
        if (!response.IsSuccessStatusCode)
        {
            return (false, null, "Impossibile completare il pagamento.");
        }

        var result = await response.Content.ReadFromJsonAsync<CaptureCheckoutResponse>(JsonOptions, ct);
        return (result?.Success ?? false, result?.PlanExpiresAt, result is { Success: false } ? "Pagamento non completato da PayPal." : null);
    }
}

public sealed record BillingStatusResponse(
    string? PlanName,
    DateTimeOffset TrialEndsAt,
    DateTimeOffset? PlanExpiresAt,
    bool IsReadOnly,
    decimal StandardAnnualPrice,
    decimal EffectivePrice,
    string Currency,
    string? PromoMessage,
    DateTimeOffset? PromoExpiresAt);

public sealed record CreateCheckoutResponse(string OrderId);

public sealed record CaptureCheckoutResponse(bool Success, DateTimeOffset? PlanExpiresAt);
