using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CffVaultManager.Api.Tests;

/// <summary>End-to-end coverage of inviting a new user into an existing tenant (see docs/features/roles-permissions.md "Invito di nuovi utenti").</summary>
public sealed class UserInvitationsEndpointsTests : IAsyncLifetime
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
    public async Task FullRoundTrip_invite_thenAccept_thenLoginWithTheNewCredentials_succeeds()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");

        var inviteResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/tenant/users/invitations", adminToken,
            new { Email = "newbie@acme.test", Role = "Operator" });
        Assert.Equal(HttpStatusCode.OK, inviteResponse.StatusCode);

        string token = ExtractInviteToken(_factory.EmailSender.LastBody!);

        var previewResponse = await _client.GetAsync($"/api/tenant/users/invitations/{token}");
        Assert.Equal(HttpStatusCode.OK, previewResponse.StatusCode);
        using (var previewBody = JsonDocument.Parse(await previewResponse.Content.ReadAsStringAsync()))
        {
            Assert.Equal("acme", previewBody.RootElement.GetProperty("tenantName").GetString());
        }

        byte[] newAuthHash = RandomBytes(32);
        var completeResponse = await _client.PostAsJsonAsync($"/api/tenant/users/invitations/{token}/complete", new
        {
            AuthHash = newAuthHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.OK, completeResponse.StatusCode);

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "newbie@acme.test", AuthHash = newAuthHash });
        using var loginBody = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        Assert.True(loginBody.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task InviteEndpoint_asNonAdmin_returns403()
    {
        // Operators can't invite — provision as Admin then invite an Operator to get a non-Admin token.
        string adminToken = await ProvisionAndLoginAsync("acme2", "admin2@acme.test");
        byte[] operatorAuthHash = RandomBytes(32);
        await SendAuthorizedAsync(HttpMethod.Post, "/api/tenant/users/invitations", adminToken, new { Email = "op@acme.test", Role = "Operator" });
        string token = ExtractInviteToken(_factory.EmailSender.LastBody!);
        await _client.PostAsJsonAsync($"/api/tenant/users/invitations/{token}/complete", new
        {
            AuthHash = operatorAuthHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "op@acme.test", AuthHash = operatorAuthHash });
        using var loginBody = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        string operatorToken = loginBody.RootElement.GetProperty("accessToken").GetString()!;

        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/tenant/users/invitations", operatorToken, new { Email = "x@acme.test", Role = "Operator" });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task InviteEndpoint_withoutToken_returns401()
    {
        var response = await _client.PostAsJsonAsync("/api/tenant/users/invitations", new { Email = "x@acme.test", Role = "Operator" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task InviteEndpoint_withAnAlreadyRegisteredEmail_returns409()
    {
        string adminToken = await ProvisionAndLoginAsync("acme3", "admin3@acme.test");

        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/tenant/users/invitations", adminToken, new { Email = "admin3@acme.test", Role = "Operator" });
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task RevokeEndpoint_preventsASubsequentAccept()
    {
        string adminToken = await ProvisionAndLoginAsync("acme4", "admin4@acme.test");
        var inviteResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/tenant/users/invitations", adminToken, new { Email = "newbie4@acme.test", Role = "Operator" });
        using var inviteBody = JsonDocument.Parse(await inviteResponse.Content.ReadAsStringAsync());
        Guid invitationId = inviteBody.RootElement.GetProperty("id").GetGuid();
        string token = ExtractInviteToken(_factory.EmailSender.LastBody!);

        var revokeResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/tenant/users/invitations/{invitationId}/revoke", adminToken, null);
        Assert.Equal(HttpStatusCode.NoContent, revokeResponse.StatusCode);

        var completeResponse = await _client.PostAsJsonAsync($"/api/tenant/users/invitations/{token}/complete", new
        {
            AuthHash = RandomBytes(32),
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.NotFound, completeResponse.StatusCode);
    }

    [Fact]
    public async Task PreviewEndpoint_forAnUnknownToken_returns404()
    {
        var response = await _client.GetAsync("/api/tenant/users/invitations/no-such-token");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ListUsersEndpoint_returnsExistingTenantMembers()
    {
        string adminToken = await ProvisionAndLoginAsync("acme5", "admin5@acme.test");

        var response = await GetAuthorizedAsync("/api/tenant/users", adminToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Contains(body.RootElement.EnumerateArray(), u => u.GetProperty("email").GetString() == "admin5@acme.test");
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task<string> ProvisionAndLoginAsync(string slug, string adminEmail)
    {
        byte[] authHash = RandomBytes(32);
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

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new { Email = adminEmail, AuthHash = authHash });
        using var body = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
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

    private static string ExtractInviteToken(string body) => Regex.Match(body, @"/invite/([\w-]+)").Groups[1].Value;

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);
}
