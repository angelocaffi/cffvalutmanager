using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the in-app notification HTTP surface (GET /api/notifications,
/// GET /api/notifications/unread-count, POST .../{id}/read, POST .../read-all), over real HTTP
/// against the real DI wiring in Program.cs. Uses POST /api/auth/change-master-password as the
/// real trigger that produces a MasterPasswordChanged notification (see SecurityNotificationService)
/// — business-rule coverage of NotificationService itself lives in
/// CffVaultManager.Infrastructure.Tests/NotificationServiceTests.cs.
/// </summary>
public sealed class NotificationEndpointsTests : IAsyncLifetime
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
    public async Task GET_notifications_without_auth_returns_401()
    {
        var response = await _client.GetAsync("/api/notifications");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Changing_master_password_creates_a_listed_notification()
    {
        var authHash = RandomBytes(32);
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test", authHash);

        await ChangeMasterPasswordAsync(token, authHash);

        var listResponse = await GetAuthorizedAsync("/api/notifications", token);
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        using var body = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        var notifications = body.RootElement.EnumerateArray().ToList();
        Assert.Single(notifications);
        Assert.Equal("MasterPasswordChanged", notifications[0].GetProperty("type").GetString());
        Assert.Null(notifications[0].GetProperty("readAt").GetString());
    }

    [Fact]
    public async Task GET_unread_count_reflects_the_new_notification()
    {
        var authHash = RandomBytes(32);
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test", authHash);
        await ChangeMasterPasswordAsync(token, authHash);

        var response = await GetAuthorizedAsync("/api/notifications/unread-count", token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetInt32());
    }

    [Fact]
    public async Task POST_read_marks_the_notification_as_read_and_drops_the_unread_count()
    {
        var authHash = RandomBytes(32);
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test", authHash);
        await ChangeMasterPasswordAsync(token, authHash);
        Guid notificationId = await GetSingleNotificationIdAsync(token);

        var readResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/notifications/{notificationId}/read", token, null);
        Assert.Equal(HttpStatusCode.NoContent, readResponse.StatusCode);

        var countResponse = await GetAuthorizedAsync("/api/notifications/unread-count", token);
        Assert.Equal(0, JsonDocument.Parse(await countResponse.Content.ReadAsStringAsync()).RootElement.GetInt32());
    }

    [Fact]
    public async Task POST_read_for_another_users_notification_returns_404()
    {
        var adminAuthHash = RandomBytes(32);
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test", adminAuthHash);
        await ChangeMasterPasswordAsync(adminToken, adminAuthHash);
        Guid notificationId = await GetSingleNotificationIdAsync(adminToken);

        var operatorAuthHash = RandomBytes(32);
        await RegisterOperatorAsync(adminToken, "operator@acme.test", operatorAuthHash);
        string operatorToken = await LoginAsync("operator@acme.test", operatorAuthHash);

        var response = await SendAuthorizedAsync(HttpMethod.Post, $"/api/notifications/{notificationId}/read", operatorToken, null);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task POST_read_all_marks_every_unread_notification_as_read()
    {
        var authHash = RandomBytes(32);
        string token = await ProvisionAndLoginAsync("acme", "admin@acme.test", authHash);
        var newAuthHash1 = RandomBytes(32);
        await ChangeMasterPasswordAsync(token, authHash, newAuthHash1);
        token = await LoginAsync("admin@acme.test", newAuthHash1);
        var newAuthHash2 = RandomBytes(32);
        await ChangeMasterPasswordAsync(token, newAuthHash1, newAuthHash2);
        token = await LoginAsync("admin@acme.test", newAuthHash2);

        var readAllResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/notifications/read-all", token, null);
        Assert.Equal(HttpStatusCode.NoContent, readAllResponse.StatusCode);

        var countResponse = await GetAuthorizedAsync("/api/notifications/unread-count", token);
        Assert.Equal(0, JsonDocument.Parse(await countResponse.Content.ReadAsStringAsync()).RootElement.GetInt32());
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task<string> ProvisionAndLoginAsync(string slug, string adminEmail, byte[] authHash)
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

        return await LoginAsync(adminEmail, authHash);
    }

    private async Task<string> LoginAsync(string email, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash });
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("accessToken").GetString()!;
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

    private async Task ChangeMasterPasswordAsync(string token, byte[] currentAuthHash, byte[]? newAuthHash = null)
    {
        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/change-master-password", token, new
        {
            CurrentAuthHash = currentAuthHash,
            NewAuthHash = newAuthHash ?? RandomBytes(32),
            NewEncryptedDek = RandomBytes(4),
            NewMasterPasswordSalt = RandomBytes(16),
            NewKdfMemoryKb = 65536,
            NewKdfIterations = 3,
            NewKdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private async Task<Guid> GetSingleNotificationIdAsync(string token)
    {
        var response = await GetAuthorizedAsync("/api/notifications", token);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.EnumerateArray().Single().GetProperty("id").GetGuid();
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
