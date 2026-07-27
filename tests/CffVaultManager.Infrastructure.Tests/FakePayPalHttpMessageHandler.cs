using System.Net;
using Microsoft.Extensions.Configuration;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>Test double standing in for the real PayPal API — routes by path so a single handler serves oauth/create/capture.</summary>
internal sealed class FakePayPalHttpMessageHandler : HttpMessageHandler
{
    public int TokenRequestCount { get; private set; }

    public List<HttpRequestMessage> Requests { get; } = new();

    public string CaptureStatus { get; set; } = "COMPLETED";

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Requests.Add(request);
        string path = request.RequestUri!.AbsolutePath;

        if (path == "/v1/oauth2/token")
        {
            TokenRequestCount++;
            return Task.FromResult(Json("""{"access_token":"fake-access-token","expires_in":32400,"token_type":"Bearer"}"""));
        }

        if (path.EndsWith("/capture", StringComparison.Ordinal))
        {
            string body = System.Text.Json.JsonSerializer.Serialize(new
            {
                id = "CAP-1",
                status = CaptureStatus,
                purchase_units = new[] { new { payments = new { captures = new[] { new { id = "CAPTURE-123" } } } } },
            });
            return Task.FromResult(Json(body));
        }

        return Task.FromResult(Json("""{"id":"ORDER-123","status":"CREATED"}"""));
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
}

internal sealed class FakeHttpClientFactory : IHttpClientFactory
{
    private readonly HttpMessageHandler _handler;

    public FakeHttpClientFactory(HttpMessageHandler handler) => _handler = handler;

    public HttpClient CreateClient(string name) =>
        new(_handler, disposeHandler: false) { BaseAddress = new Uri("https://fake.paypal.test") };
}

internal static class TestConfiguration
{
    public static IConfiguration PayPal(string clientId = "test-client-id", string clientSecret = "test-client-secret") =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PayPal:ClientId"] = clientId,
                ["PayPal:ClientSecret"] = clientSecret,
            })
            .Build();
}
