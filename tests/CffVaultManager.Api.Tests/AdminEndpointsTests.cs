using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the SuperAdmin tenant-suspend/reactivate surface, including that
/// suspension actually blocks login for the tenant's own users (not just a metadata flag).
/// </summary>
public sealed class AdminEndpointsTests : IAsyncLifetime
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
    public async Task SuperAdmin_can_suspend_a_tenant_and_its_admin_can_no_longer_log_in()
    {
        var adminAuthHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", adminAuthHash);
        var tenantId = await GetTenantIdBySlugAsync("acme");

        var superAdminAuthHash = RandomBytes(32);
        string superAdminToken = await SeedAndLoginSuperAdminAsync(superAdminAuthHash);

        var suspendResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/admin/tenants/{tenantId}/suspend", superAdminToken, null);
        Assert.Equal(HttpStatusCode.NoContent, suspendResponse.StatusCode);

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "admin@acme.test", AuthHash = adminAuthHash });
        using var body = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        Assert.False(body.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task SuperAdmin_can_reactivate_a_suspended_tenant_and_login_succeeds_again()
    {
        var adminAuthHash = RandomBytes(32);
        await ProvisionTenantAsync("acme", "admin@acme.test", adminAuthHash);
        var tenantId = await GetTenantIdBySlugAsync("acme");

        string superAdminToken = await SeedAndLoginSuperAdminAsync(RandomBytes(32));

        await SendAuthorizedAsync(HttpMethod.Post, $"/api/admin/tenants/{tenantId}/suspend", superAdminToken, null);
        var reactivateResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/admin/tenants/{tenantId}/reactivate", superAdminToken, null);
        Assert.Equal(HttpStatusCode.NoContent, reactivateResponse.StatusCode);

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "admin@acme.test", AuthHash = adminAuthHash });
        using var body = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Suspend_as_tenant_admin_returns_403()
    {
        var adminAuthHash = RandomBytes(32);
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test", adminAuthHash);
        var tenantId = await GetTenantIdBySlugAsync("acme");

        var response = await SendAuthorizedAsync(HttpMethod.Post, $"/api/admin/tenants/{tenantId}/suspend", adminToken, null);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Suspend_without_token_returns_401()
    {
        var response = await _client.PostAsync($"/api/admin/tenants/{Guid.NewGuid()}/suspend", null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Suspend_nonexistent_tenant_returns_404()
    {
        string superAdminToken = await SeedAndLoginSuperAdminAsync(RandomBytes(32));

        var response = await SendAuthorizedAsync(HttpMethod.Post, $"/api/admin/tenants/{Guid.NewGuid()}/suspend", superAdminToken, null);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetAllTenants_reflects_suspended_status()
    {
        await ProvisionTenantAsync("acme", "admin@acme.test", RandomBytes(32));
        var tenantId = await GetTenantIdBySlugAsync("acme");

        string superAdminToken = await SeedAndLoginSuperAdminAsync(RandomBytes(32));
        await SendAuthorizedAsync(HttpMethod.Post, $"/api/admin/tenants/{tenantId}/suspend", superAdminToken, null);

        var response = await GetAuthorizedAsync("/api/admin/tenants", superAdminToken);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var tenant = body.RootElement.EnumerateArray().Single(t => t.GetProperty("id").GetGuid() == tenantId);
        Assert.Equal("Suspended", tenant.GetProperty("status").GetString());
    }

    [Fact]
    public async Task GetPricing_as_SuperAdmin_returns200()
    {
        string superAdminToken = await SeedAndLoginSuperAdminAsync(RandomBytes(32));

        var response = await GetAuthorizedAsync("/api/admin/billing/pricing", superAdminToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetPricing_without_token_returns401()
    {
        var response = await _client.GetAsync("/api/admin/billing/pricing");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetPricing_as_tenant_admin_returns403()
    {
        string adminToken = await ProvisionAndLoginAsync("pricing-403", "admin@pricing403.test", RandomBytes(32));

        var response = await GetAuthorizedAsync("/api/admin/billing/pricing", adminToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task PutPricing_as_SuperAdmin_persistsAndReturnsTheUpdatedPricing()
    {
        string superAdminToken = await SeedAndLoginSuperAdminAsync(RandomBytes(32));

        var response = await SendAuthorizedAsync(HttpMethod.Put, "/api/admin/billing/pricing", superAdminToken, new
        {
            StandardAnnualPrice = 59.00m,
            DiscountedAnnualPrice = 39.00m,
            DiscountExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
            PromoMessage = "Offerta di lancio",
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(59.00m, body.RootElement.GetProperty("standardAnnualPrice").GetDecimal());
        Assert.Equal(39.00m, body.RootElement.GetProperty("discountedAnnualPrice").GetDecimal());
        Assert.True(body.RootElement.GetProperty("isDiscountActive").GetBoolean());

        // Persisted, not just echoed back — a fresh GET reflects the same values.
        var getResponse = await GetAuthorizedAsync("/api/admin/billing/pricing", superAdminToken);
        using var getBody = JsonDocument.Parse(await getResponse.Content.ReadAsStringAsync());
        Assert.Equal(59.00m, getBody.RootElement.GetProperty("standardAnnualPrice").GetDecimal());
    }

    [Fact]
    public async Task PutPricing_as_tenant_admin_returns403()
    {
        string adminToken = await ProvisionAndLoginAsync("pricing-put-403", "admin@pricingput403.test", RandomBytes(32));

        var response = await SendAuthorizedAsync(HttpMethod.Put, "/api/admin/billing/pricing", adminToken, new { StandardAnnualPrice = 59.00m });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task PutPricing_nonPositiveStandardPrice_returns400()
    {
        string superAdminToken = await SeedAndLoginSuperAdminAsync(RandomBytes(32));

        var response = await SendAuthorizedAsync(HttpMethod.Put, "/api/admin/billing/pricing", superAdminToken, new { StandardAnnualPrice = 0m });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task PutPricing_discountedPriceHigherThanStandard_returns400()
    {
        string superAdminToken = await SeedAndLoginSuperAdminAsync(RandomBytes(32));

        var response = await SendAuthorizedAsync(HttpMethod.Put, "/api/admin/billing/pricing", superAdminToken, new
        {
            StandardAnnualPrice = 49.00m,
            DiscountedAnnualPrice = 59.00m,
            DiscountExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task ProvisionTenantAsync(string slug, string adminEmail, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/tenants", new
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

    private async Task<string> ProvisionAndLoginAsync(string slug, string adminEmail, byte[] authHash)
    {
        await ProvisionTenantAsync(slug, adminEmail, authHash);
        var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = adminEmail, AuthHash = authHash });
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("accessToken").GetString()!;
    }

    private async Task<Guid> GetTenantIdBySlugAsync(string slug)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CffVaultManagerDbContext>();
        return (await db.Tenants.IgnoreQueryFilters().SingleAsync(t => t.Slug == slug)).Id;
    }

    private async Task<string> SeedAndLoginSuperAdminAsync(byte[] authHash)
    {
        string email = $"superadmin-{Guid.NewGuid()}@platform.test";

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CffVaultManagerDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IAuthHashHasher>();

            var user = User.CreateSuperAdmin(
                Guid.NewGuid(),
                email,
                encryptedDek: RandomBytes(4),
                masterPasswordHash: hasher.Hash(authHash),
                masterPasswordSalt: RandomBytes(16),
                kdfMemoryKb: 65536,
                kdfIterations: 3,
                kdfVersion: 1);

            db.Users.Add(user);
            await db.SaveChangesAsync();
        }

        var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash });
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("accessToken").GetString()!;
    }

    private Task<HttpResponseMessage> GetAuthorizedAsync(string url, string accessToken) =>
        SendAuthorizedAsync(HttpMethod.Get, url, accessToken, null);

    private async Task<HttpResponseMessage> SendAuthorizedAsync(HttpMethod method, string url, string accessToken, object? body)
    {
        using var request = new HttpRequestMessage(method, url);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await _client.SendAsync(request);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);
}
