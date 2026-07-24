using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the gated self-service tenant signup (see
/// docs/multi-tenancy.md#provisioning-di-un-nuovo-tenant): nothing is created by
/// POST /api/tenants/requests alone — only POST /api/tenants/requests/confirm, with the emailed
/// code, actually provisions the tenant/admin (same atomic path as POST /api/tenants).
/// </summary>
public sealed class TenantProvisioningRequestEndpointsTests : IAsyncLifetime
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
    public async Task Requesting_provisioning_returns_202_with_a_request_id_and_emails_a_code()
    {
        var response = await RequestAsync("acme", "admin@acme.test");

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.NotEqual(Guid.Empty, body.RootElement.GetProperty("requestId").GetGuid());
        Assert.Equal("admin@acme.test", _factory.EmailSender.LastToEmail);
        Assert.Matches(@"\d{6}", _factory.EmailSender.LastBody);
    }

    [Fact]
    public async Task Requesting_provisioning_with_a_slug_already_in_use_returns_409()
    {
        // A tenant provisioned directly (bootstrap path, unaffected by this gate).
        var directResponse = await _client.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = "acme",
            TenantSlug = "acme",
            AdminEmail = "existing-admin@acme.test",
            AuthHash = RandomBytes(32),
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, directResponse.StatusCode);

        var response = await RequestAsync("acme", "another-admin@acme.test");
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Confirming_with_the_right_code_provisions_the_tenant_and_login_works_immediately()
    {
        byte[] authHash = RandomBytes(32);
        var requestId = await RequestAndGetIdAsync("acme", "admin@acme.test", authHash);
        string code = ExtractCode(_factory.EmailSender.LastBody!);

        var confirm = await _client.PostAsJsonAsync("/api/tenants/requests/confirm", new { RequestId = requestId, Code = code });
        Assert.Equal(HttpStatusCode.Created, confirm.StatusCode);

        var login = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "admin@acme.test", AuthHash = authHash });
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.True(loginBody.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Confirming_with_the_wrong_code_returns_401_and_does_not_provision_anything()
    {
        byte[] authHash = RandomBytes(32);
        var requestId = await RequestAndGetIdAsync("acme", "admin@acme.test", authHash);
        string realCode = ExtractCode(_factory.EmailSender.LastBody!);
        string wrongCode = realCode == "000000" ? "111111" : "000000";

        var confirm = await _client.PostAsJsonAsync("/api/tenants/requests/confirm", new { RequestId = requestId, Code = wrongCode });
        Assert.Equal(HttpStatusCode.Unauthorized, confirm.StatusCode);

        // Login must still fail — no tenant/admin was ever created.
        var login = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "admin@acme.test", AuthHash = authHash });
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.False(loginBody.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Confirming_an_unknown_request_id_returns_401_same_as_a_wrong_code()
    {
        // Anti-enumeration: an unknown request id must look identical to a real one with a wrong code.
        var response = await _client.PostAsJsonAsync(
            "/api/tenants/requests/confirm", new { RequestId = Guid.NewGuid(), Code = "123456" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---- Helpers ------------------------------------------------------------------------------

    private Task<HttpResponseMessage> RequestAsync(string slug, string adminEmail) =>
        _client.PostAsJsonAsync("/api/tenants/requests", new
        {
            TenantName = slug,
            TenantSlug = slug,
            AdminEmail = adminEmail,
            AuthHash = RandomBytes(32),
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
            LegalName = "Mario Rossi",
            IsBusiness = false,
            AddressLine = "Via Roma 1",
            City = "Milano",
            PostalCode = "20100",
            Province = "MI",
            Country = "IT",
        });

    private async Task<Guid> RequestAndGetIdAsync(string slug, string adminEmail, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/tenants/requests", new
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
            LegalName = "Mario Rossi",
            IsBusiness = false,
            AddressLine = "Via Roma 1",
            City = "Milano",
            PostalCode = "20100",
            Province = "MI",
            Country = "IT",
        });
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("requestId").GetGuid();
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    private static string ExtractCode(string body) => Regex.Match(body, @"\d{6}").Value;
}
