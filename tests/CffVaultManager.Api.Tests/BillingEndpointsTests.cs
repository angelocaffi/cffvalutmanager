using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of <c>/api/billing/*</c> (see docs/features/billing.md): trial/paid-plan
/// status, checkout/capture round-trip against a fake <see cref="IPayPalClient"/>, the
/// <c>tenant_read_only</c> JWT claim's 402 enforcement on a vault-content-mutating endpoint, and
/// the 503 that results when PayPal is not configured at all (the default for <see cref="ApiTestFactory"/>).
/// </summary>
public sealed class BillingEndpointsTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private ApiTestFactory _factory = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _factory = new ApiTestFactory();
        await _factory.EnsureDatabaseCreatedAsync();
        _client = _factory.CreateClient();
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task GET_status_without_auth_returns_401()
    {
        var response = await _client.GetAsync("/api/billing/status");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GET_status_for_a_freshly_provisioned_tenant_is_not_read_only()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        string token = await LoginAsync("admin@acme.test", authHash);

        var response = await GetAuthorizedAsync("/api/billing/status", token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(body.RootElement.GetProperty("isReadOnly").GetBoolean());
        Assert.True(body.RootElement.GetProperty("planExpiresAt").ValueKind is JsonValueKind.Null);
    }

    [Fact]
    public async Task POST_checkout_when_PayPal_is_not_configured_returns_503()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", authHash);
        string token = await LoginAsync("admin@acme.test", authHash);

        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/billing/checkout", token, null);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task POST_checkout_as_Operator_returns_403()
    {
        var adminAuthHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", adminAuthHash);
        string adminToken = await LoginAsync("admin@acme.test", adminAuthHash);

        var operatorAuthHash = RandomBytes(32);
        await RegisterOperatorAsync(adminToken, "operator@acme.test", operatorAuthHash);
        string operatorToken = await LoginAsync("operator@acme.test", operatorAuthHash);

        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/billing/checkout", operatorToken, null);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Checkout_then_capture_round_trip_extends_the_plan_and_clears_the_read_only_claim_on_refresh()
    {
        using var payPalClient = CreateClientWithFakePayPal(new FakePayPalClient { NextOrderId = "ORDER-E2E", NextCaptureStatus = "COMPLETED" });

        var authHash = RandomBytes(32);
        await ProvisionTenantAsync(payPalClient, "acme-e2e", "admin@acme-e2e.test", authHash);
        var (accessToken, refreshToken) = await LoginWithRefreshAsync(payPalClient, "admin@acme-e2e.test", authHash);

        // Force the tenant into read-only (trial already ended) directly against the shared
        // in-memory database, same technique as CffVaultManager.Infrastructure.Tests.
        await ForceTrialExpiredAsync("acme-e2e");

        // The already-issued access token still carries the pre-expiry (non-read-only) claim —
        // accepted staleness, see docs/features/billing.md. Refresh to pick up the new state.
        (accessToken, refreshToken) = await RefreshAsync(payPalClient, refreshToken);

        // A vault-content mutation must now be blocked with 402.
        var blockedCreate = await SendAuthorizedAsync(payPalClient, HttpMethod.Post, "/api/vaults/organization", accessToken,
            new { Name = "Org vault", WrappedVaultDek = RandomBytes(4), EphemeralPublicKey = RandomBytes(32) });
        Assert.Equal(HttpStatusCode.PaymentRequired, blockedCreate.StatusCode);

        // But billing/status (GET) and checkout/capture must still work while read-only.
        var statusWhileReadOnly = await GetAuthorizedAsync(payPalClient, "/api/billing/status", accessToken);
        using (var statusBody = JsonDocument.Parse(await statusWhileReadOnly.Content.ReadAsStringAsync()))
        {
            Assert.True(statusBody.RootElement.GetProperty("isReadOnly").GetBoolean());
        }

        var checkoutResponse = await SendAuthorizedAsync(payPalClient, HttpMethod.Post, "/api/billing/checkout", accessToken, null);
        Assert.Equal(HttpStatusCode.OK, checkoutResponse.StatusCode);
        using var checkoutBody = JsonDocument.Parse(await checkoutResponse.Content.ReadAsStringAsync());
        string orderId = checkoutBody.RootElement.GetProperty("orderId").GetString()!;
        Assert.Equal("ORDER-E2E", orderId);

        var captureResponse = await SendAuthorizedAsync(payPalClient, HttpMethod.Post, $"/api/billing/checkout/{orderId}/capture", accessToken, null);
        Assert.Equal(HttpStatusCode.OK, captureResponse.StatusCode);
        using var captureBody = JsonDocument.Parse(await captureResponse.Content.ReadAsStringAsync());
        Assert.True(captureBody.RootElement.GetProperty("success").GetBoolean());
        Assert.False(captureBody.RootElement.GetProperty("planExpiresAt").ValueKind is JsonValueKind.Null);

        // Force a fresh token the same way the Billing page does right after a successful capture.
        (accessToken, refreshToken) = await RefreshAsync(payPalClient, refreshToken);

        var allowedCreate = await SendAuthorizedAsync(payPalClient, HttpMethod.Post, "/api/vaults/organization", accessToken,
            new { Name = "Org vault", WrappedVaultDek = RandomBytes(4), EphemeralPublicKey = RandomBytes(32) });
        Assert.Equal(HttpStatusCode.Created, allowedCreate.StatusCode);

        var statusAfterPayment = await GetAuthorizedAsync(payPalClient, "/api/billing/status", accessToken);
        using var finalBody = JsonDocument.Parse(await statusAfterPayment.Content.ReadAsStringAsync());
        Assert.False(finalBody.RootElement.GetProperty("isReadOnly").GetBoolean());
    }

    [Fact]
    public async Task Capturing_the_same_order_twice_is_idempotent()
    {
        using var payPalClient = CreateClientWithFakePayPal(new FakePayPalClient { NextOrderId = "ORDER-IDEMPOTENT" });

        var authHash = RandomBytes(32);
        await ProvisionTenantAsync(payPalClient, "acme-idem", "admin@acme-idem.test", authHash);
        string token = await LoginAsync(payPalClient, "admin@acme-idem.test", authHash);

        var checkoutResponse = await SendAuthorizedAsync(payPalClient, HttpMethod.Post, "/api/billing/checkout", token, null);
        using var checkoutBody = JsonDocument.Parse(await checkoutResponse.Content.ReadAsStringAsync());
        string orderId = checkoutBody.RootElement.GetProperty("orderId").GetString()!;

        var first = await SendAuthorizedAsync(payPalClient, HttpMethod.Post, $"/api/billing/checkout/{orderId}/capture", token, null);
        var second = await SendAuthorizedAsync(payPalClient, HttpMethod.Post, $"/api/billing/checkout/{orderId}/capture", token, null);

        using var firstBody = JsonDocument.Parse(await first.Content.ReadAsStringAsync());
        using var secondBody = JsonDocument.Parse(await second.Content.ReadAsStringAsync());
        Assert.Equal(
            firstBody.RootElement.GetProperty("planExpiresAt").GetString(),
            secondBody.RootElement.GetProperty("planExpiresAt").GetString());
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private HttpClient CreateClientWithFakePayPal(FakePayPalClient fake) =>
        _factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IPayPalClient>();
            services.AddSingleton<IPayPalClient>(fake);
        })).CreateClient();

    private async Task ForceTrialExpiredAsync(string slug)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CffVaultManagerDbContext>();
        var expired = DateTimeOffset.UtcNow.AddDays(-1);
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE Tenants SET TrialEndsAt = {expired} WHERE Slug = {slug}");
    }

    private Task ProvisionTenantAsync(string slug, string adminEmail, byte[] authHash) => ProvisionTenantAsync(_client, slug, adminEmail, authHash);

    private async Task ProvisionTenantAsync(HttpClient client, string slug, string adminEmail, byte[] authHash)
    {
        var response = await client.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = slug,
            TenantSlug = slug,
            AdminEmail = adminEmail,
            AuthHash = authHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private async Task RegisterOperatorAsync(string adminToken, string email, byte[] authHash)
    {
        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/users", adminToken, new
        {
            Email = email,
            Role = "Operator",
            AuthHash = authHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private Task<string> LoginAsync(string email, byte[] authHash) => LoginAsync(_client, email, authHash);

    private async Task<string> LoginAsync(HttpClient client, string email, byte[] authHash)
    {
        var (accessToken, _) = await LoginWithRefreshAsync(client, email, authHash);
        return accessToken;
    }

    private async Task<(string AccessToken, string RefreshToken)> LoginWithRefreshAsync(HttpClient client, string email, byte[] authHash)
    {
        var response = await client.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash });
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (body.RootElement.GetProperty("accessToken").GetString()!, body.RootElement.GetProperty("refreshToken").GetString()!);
    }

    private async Task<(string AccessToken, string RefreshToken)> RefreshAsync(HttpClient client, string refreshToken)
    {
        var response = await client.PostAsJsonAsync("/api/auth/refresh", new { RefreshToken = refreshToken });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (body.RootElement.GetProperty("accessToken").GetString()!, body.RootElement.GetProperty("refreshToken").GetString()!);
    }

    private Task<HttpResponseMessage> GetAuthorizedAsync(string url, string accessToken) => GetAuthorizedAsync(_client, url, accessToken);

    private Task<HttpResponseMessage> GetAuthorizedAsync(HttpClient client, string url, string accessToken) =>
        SendAuthorizedAsync(client, HttpMethod.Get, url, accessToken, null);

    private Task<HttpResponseMessage> SendAuthorizedAsync(HttpMethod method, string url, string accessToken, object? body) =>
        SendAuthorizedAsync(_client, method, url, accessToken, body);

    private async Task<HttpResponseMessage> SendAuthorizedAsync(HttpClient client, HttpMethod method, string url, string accessToken, object? body)
    {
        using var request = new HttpRequestMessage(method, url);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await client.SendAsync(request);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);
}
