using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// Coverage for the per-IP rate limiter on the unauthenticated auth endpoints (see
/// AuthRateLimiting in Program.cs / AuthEndpoints.cs). Account lockout (tested in
/// CffVaultManager.Infrastructure.Tests.AuthenticationTests) protects a specific account; this
/// protects the endpoint itself from a single caller regardless of which account they target.
/// </summary>
public sealed class RateLimitingTests : IAsyncLifetime
{
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
    public async Task Login_returns_429_after_the_per_ip_limit_is_exceeded_within_the_window()
    {
        // The test server reports a consistent RemoteIpAddress for every request, so these all
        // land in the same rate-limit partition (PermitLimit = 10 per minute, see Program.cs).
        HttpResponseMessage? last = null;
        for (int i = 0; i < 11; i++)
        {
            last = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "nobody@x.test", AuthHash = RandomBytes(32) });
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, last!.StatusCode);
    }

    [Fact]
    public async Task Login_within_the_limit_is_not_rate_limited()
    {
        for (int i = 0; i < 5; i++)
        {
            var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "nobody@x.test", AuthHash = RandomBytes(32) });
            Assert.NotEqual(HttpStatusCode.TooManyRequests, response.StatusCode);
        }
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);
}
