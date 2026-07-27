using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Billing;
using Microsoft.Extensions.Configuration;

namespace CffVaultManager.Infrastructure.Billing;

/// <summary>
/// Server-to-server PayPal Orders API v2 client (see docs/features/billing.md). Registered as a
/// singleton so the OAuth2 access token is cached in memory and shared across every call for the
/// app's lifetime, refreshed only once it's close to its declared expiry (~9h) — not per request.
/// Uses <see cref="IHttpClientFactory"/> (rather than holding one injected <see cref="HttpClient"/>)
/// so the underlying handler is still pooled/recycled normally despite this class's own singleton
/// lifetime.
/// </summary>
internal sealed class PayPalClient : IPayPalClient
{
    public const string HttpClientName = "PayPal";

    // Refresh a bit before the token's declared expiry so an in-flight request never races an
    // exact-boundary expiration.
    private static readonly TimeSpan ExpiryBuffer = TimeSpan.FromMinutes(2);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);

    private string? _cachedAccessToken;
    private DateTimeOffset _cachedAccessTokenExpiresAt;

    public PayPalClient(IHttpClientFactory httpClientFactory, IConfiguration configuration)
    {
        _httpClientFactory = httpClientFactory;
        _clientId = configuration["PayPal:ClientId"] ?? string.Empty;
        _clientSecret = configuration["PayPal:ClientSecret"] ?? string.Empty;
    }

    public async Task<string> CreateOrderAsync(decimal amount, string currency, CancellationToken ct = default)
    {
        string token = await GetAccessTokenAsync(ct);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/v2/checkout/orders")
        {
            Content = JsonContent.Create(new
            {
                intent = "CAPTURE",
                purchase_units = new[]
                {
                    new { amount = new { currency_code = currency, value = amount.ToString("F2", System.Globalization.CultureInfo.InvariantCulture) } },
                },
            }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await _httpClientFactory.CreateClient(HttpClientName).SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        return doc.RootElement.GetProperty("id").GetString()!;
    }

    public async Task<PayPalOrderCapture> CaptureOrderAsync(string orderId, CancellationToken ct = default)
    {
        string token = await GetAccessTokenAsync(ct);

        // PayPal requires a Content-Type: application/json header on this call even though the
        // capture itself takes no body — confirmed live against the sandbox: an empty request
        // with no Content at all (and so no Content-Type) comes back 415 Unsupported Media Type.
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/v2/checkout/orders/{orderId}/capture")
        {
            Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await _httpClientFactory.CreateClient(HttpClientName).SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        string status = doc.RootElement.GetProperty("status").GetString()!;
        string captureId = doc.RootElement
            .GetProperty("purchase_units")[0]
            .GetProperty("payments")
            .GetProperty("captures")[0]
            .GetProperty("id")
            .GetString()!;

        return new PayPalOrderCapture(status, captureId);
    }

    private async Task<string> GetAccessTokenAsync(CancellationToken ct)
    {
        if (_cachedAccessToken is not null && DateTimeOffset.UtcNow < _cachedAccessTokenExpiresAt)
        {
            return _cachedAccessToken;
        }

        await _tokenLock.WaitAsync(ct);
        try
        {
            if (_cachedAccessToken is not null && DateTimeOffset.UtcNow < _cachedAccessTokenExpiresAt)
            {
                return _cachedAccessToken;
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/oauth2/token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "client_credentials" }),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{_clientId}:{_clientSecret}")));

            using var response = await _httpClientFactory.CreateClient(HttpClientName).SendAsync(request, ct);
            response.EnsureSuccessStatusCode();

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
            string accessToken = doc.RootElement.GetProperty("access_token").GetString()!;
            int expiresInSeconds = doc.RootElement.GetProperty("expires_in").GetInt32();

            _cachedAccessToken = accessToken;
            _cachedAccessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresInSeconds) - ExpiryBuffer;

            return accessToken;
        }
        finally
        {
            _tokenLock.Release();
        }
    }
}
