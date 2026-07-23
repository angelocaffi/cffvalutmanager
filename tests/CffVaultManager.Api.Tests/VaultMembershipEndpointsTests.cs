using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the organization-vault sharing HTTP surface (create org vault, public-key
/// mediation, invite/revoke/list memberships) and the permission-gating of vault-item writes, over
/// real HTTP against the real DI wiring in Program.cs. Business-rule coverage lives in
/// CffVaultManager.Infrastructure.Tests; these tests prove routes, status codes, and auth wiring.
/// Enums travel as JSON string names because of the global JsonStringEnumConverter (Program.cs).
/// </summary>
public sealed class VaultMembershipEndpointsTests : IAsyncLifetime
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

    // ---- Organization-vault creation --------------------------------------------------------

    [Fact]
    public async Task POST_organization_vault_as_admin_returns_201_and_is_listed_for_creator()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");

        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");

        var listResponse = await GetAuthorizedAsync("/api/vaults/organization", adminToken);
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        using var body = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        var ids = body.RootElement.EnumerateArray().Select(e => e.GetProperty("id").GetGuid()).ToList();
        Assert.Contains(vaultId, ids);
    }

    [Fact]
    public async Task POST_organization_vault_as_operator_returns_403()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        var operatorAuthHash = RandomBytes(32);
        await RegisterOperatorAsync(adminToken, "operator@acme.test", operatorAuthHash);
        string operatorToken = await LoginAsync("operator@acme.test", operatorAuthHash);

        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/vaults/organization", operatorToken, new
        {
            Name = "Team",
            WrappedVaultDek = RandomBytes(48),
            EphemeralPublicKey = RandomBytes(32),
        });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ---- Public key -------------------------------------------------------------------------

    [Fact]
    public async Task GET_public_key_for_nonexistent_user_returns_404()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");

        var response = await GetAuthorizedAsync($"/api/tenant/users/{Guid.NewGuid()}/public-key", adminToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GET_public_key_for_user_in_another_tenant_returns_404()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        await ProvisionAndLoginAsync("beta", "admin@beta.test");
        Guid foreignUserId = await GetUserIdByEmailAsync("admin@beta.test");

        var response = await GetAuthorizedAsync($"/api/tenant/users/{foreignUserId}/public-key", adminToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GET_public_key_for_user_without_a_keypair_returns_422()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", RandomBytes(32));

        var response = await GetAuthorizedAsync($"/api/tenant/users/{operatorId}/public-key", adminToken);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
    }

    [Fact]
    public async Task GET_public_key_after_key_is_set_returns_200_with_the_key()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", RandomBytes(32));
        var publicKey = RandomBytes(32);
        await SetPublicKeyAsync(operatorId, publicKey);

        var response = await GetAuthorizedAsync($"/api/tenant/users/{operatorId}/public-key", adminToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Convert.ToBase64String(publicKey), body.RootElement.GetProperty("publicKey").GetString());
    }

    // ---- Invite -----------------------------------------------------------------------------

    [Fact]
    public async Task POST_membership_invite_as_admin_returns_201()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", RandomBytes(32));
        await SetPublicKeyAsync(operatorId, RandomBytes(32));
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");

        var response = await InviteAsync(adminToken, vaultId, operatorId, "Read");
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task POST_membership_invite_as_a_non_member_returns_404()
    {
        // Invite/revoke no longer gate on the tenant Admin role at the endpoint level — the
        // operator here was never invited to the vault at all, so VaultAccessGuard reports it as
        // "not found" before any permission is even checked.
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        var operatorAuthHash = RandomBytes(32);
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", operatorAuthHash);
        string operatorToken = await LoginAsync("operator@acme.test", operatorAuthHash);
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");

        var response = await InviteAsync(operatorToken, vaultId, operatorId, "Read");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task POST_membership_invite_by_an_Operator_who_is_vault_Owner_returns_201()
    {
        // The point of decoupling membership authority from the tenant role: an Operator (not a
        // tenant Admin) invited as this vault's Owner can invite a third member end-to-end.
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        var operatorAuthHash = RandomBytes(32);
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", operatorAuthHash);
        string operatorToken = await LoginAsync("operator@acme.test", operatorAuthHash);
        Guid strangerId = await RegisterOperatorAsync(adminToken, "stranger@acme.test", RandomBytes(32));
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, operatorId, "Owner")).StatusCode);

        var response = await InviteAsync(operatorToken, vaultId, strangerId, "Read");
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task POST_membership_invite_same_user_twice_returns_409()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", RandomBytes(32));
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");

        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, operatorId, "Read")).StatusCode);
        var duplicate = await InviteAsync(adminToken, vaultId, operatorId, "ReadWrite");
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
    }

    [Fact]
    public async Task POST_membership_invite_into_a_personal_vault_returns_404()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", RandomBytes(32));
        Guid personalVaultId = await GetOwnedVaultIdAsync(adminToken);

        var response = await InviteAsync(adminToken, personalVaultId, operatorId, "Read");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task POST_membership_invite_into_a_nonexistent_vault_returns_404()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", RandomBytes(32));

        var response = await InviteAsync(adminToken, Guid.NewGuid(), operatorId, "Read");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---- Revoke -----------------------------------------------------------------------------

    [Fact]
    public async Task POST_revoke_as_admin_with_matching_sets_returns_204()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid adminId = await GetUserIdByEmailAsync("admin@acme.test");
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", RandomBytes(32));
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, operatorId, "Read")).StatusCode);

        var response = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/memberships/{operatorId}/revoke", adminToken, new
        {
            RevokedUserId = operatorId,
            ReencryptedItems = Array.Empty<object>(),
            NewMemberships = new[]
            {
                new { UserId = adminId, WrappedVaultDek = RandomBytes(48), EphemeralPublicKey = RandomBytes(32) },
            },
        });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task POST_revoke_with_mismatched_route_and_body_user_returns_400()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid adminId = await GetUserIdByEmailAsync("admin@acme.test");
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", RandomBytes(32));
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, operatorId, "Read")).StatusCode);

        // Route user id and body RevokedUserId differ -> the inline guard returns 400.
        var response = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/memberships/{operatorId}/revoke", adminToken, new
        {
            RevokedUserId = Guid.NewGuid(),
            ReencryptedItems = Array.Empty<object>(),
            NewMemberships = new[]
            {
                new { UserId = adminId, WrappedVaultDek = RandomBytes(48), EphemeralPublicKey = RandomBytes(32) },
            },
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task POST_revoke_by_a_non_owner_member_returns_403()
    {
        // The operator is a genuine member here (Read), so VaultAccessGuard resolves access fine;
        // the 403 now comes from the service-level Owner check, not a tenant role gate.
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        var operatorAuthHash = RandomBytes(32);
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", operatorAuthHash);
        string operatorToken = await LoginAsync("operator@acme.test", operatorAuthHash);
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, operatorId, "Read")).StatusCode);

        var response = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/memberships/{operatorId}/revoke", operatorToken, new
        {
            RevokedUserId = operatorId,
            ReencryptedItems = Array.Empty<object>(),
            NewMemberships = Array.Empty<object>(),
        });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task POST_revoke_with_incomplete_new_memberships_returns_409()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid operatorId = await RegisterOperatorAsync(adminToken, "operator@acme.test", RandomBytes(32));
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, operatorId, "Read")).StatusCode);

        // The admin creator remains after the revoke but is not covered by NewMemberships.
        var response = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/memberships/{operatorId}/revoke", adminToken, new
        {
            RevokedUserId = operatorId,
            ReencryptedItems = Array.Empty<object>(),
            NewMemberships = Array.Empty<object>(),
        });
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    // ---- List members -----------------------------------------------------------------------

    [Fact]
    public async Task GET_memberships_as_member_returns_only_active_members()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid adminId = await GetUserIdByEmailAsync("admin@acme.test");
        Guid op1 = await RegisterOperatorAsync(adminToken, "op1@acme.test", RandomBytes(32));
        Guid op2 = await RegisterOperatorAsync(adminToken, "op2@acme.test", RandomBytes(32));
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, op1, "Read")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, op2, "Read")).StatusCode);

        // Revoke op1, rewrapping for the remaining admin + op2.
        var revoke = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/memberships/{op1}/revoke", adminToken, new
        {
            RevokedUserId = op1,
            ReencryptedItems = Array.Empty<object>(),
            NewMemberships = new[]
            {
                new { UserId = adminId, WrappedVaultDek = RandomBytes(48), EphemeralPublicKey = RandomBytes(32) },
                new { UserId = op2, WrappedVaultDek = RandomBytes(48), EphemeralPublicKey = RandomBytes(32) },
            },
        });
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        var response = await GetAuthorizedAsync($"/api/vaults/{vaultId}/memberships", adminToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var userIds = body.RootElement.EnumerateArray().Select(e => e.GetProperty("userId").GetGuid()).ToList();

        Assert.Equal(2, userIds.Count);
        Assert.Contains(adminId, userIds);
        Assert.Contains(op2, userIds);
        Assert.DoesNotContain(op1, userIds);
    }

    [Fact]
    public async Task GET_memberships_as_non_member_returns_404()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        var strangerAuthHash = RandomBytes(32);
        await RegisterOperatorAsync(adminToken, "stranger@acme.test", strangerAuthHash);
        string strangerToken = await LoginAsync("stranger@acme.test", strangerAuthHash);
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");

        var response = await GetAuthorizedAsync($"/api/vaults/{vaultId}/memberships", strangerToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---- Get my membership -------------------------------------------------------------------

    [Fact]
    public async Task GET_my_membership_returns_the_callers_own_wrapped_dek()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        var operatorAuthHash = RandomBytes(32);
        Guid operatorId = await RegisterOperatorAsync(adminToken, "op@acme.test", operatorAuthHash);
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");
        var wrappedDek = RandomBytes(48);
        var invite = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/memberships", adminToken, new
        {
            UserId = operatorId,
            Permission = "Read",
            WrappedVaultDek = wrappedDek,
            EphemeralPublicKey = RandomBytes(32),
        });
        Assert.Equal(HttpStatusCode.Created, invite.StatusCode);
        string operatorToken = await LoginAsync("op@acme.test", operatorAuthHash);

        var response = await GetAuthorizedAsync($"/api/vaults/{vaultId}/memberships/me", operatorToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Read", body.RootElement.GetProperty("permission").GetString());
        Assert.Equal(Convert.ToBase64String(wrappedDek), body.RootElement.GetProperty("wrappedVaultDek").GetString());
    }

    [Fact]
    public async Task GET_my_membership_for_a_non_member_returns_404()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        var strangerAuthHash = RandomBytes(32);
        await RegisterOperatorAsync(adminToken, "stranger@acme.test", strangerAuthHash);
        string strangerToken = await LoginAsync("stranger@acme.test", strangerAuthHash);
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");

        var response = await GetAuthorizedAsync($"/api/vaults/{vaultId}/memberships/me", strangerToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GET_my_membership_for_a_personal_vault_returns_404()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid ownedVaultId = await GetOwnedVaultIdAsync(adminToken);

        var response = await GetAuthorizedAsync($"/api/vaults/{ownedVaultId}/memberships/me", adminToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---- Permission enforcement over HTTP ---------------------------------------------------

    [Fact]
    public async Task Read_operator_can_list_items_but_create_returns_403_while_readwrite_operator_can_create()
    {
        string adminToken = await ProvisionAndLoginAsync("acme", "admin@acme.test");
        Guid vaultId = await CreateOrgVaultAsync(adminToken, "Team");

        var readerAuthHash = RandomBytes(32);
        Guid readerId = await RegisterOperatorAsync(adminToken, "reader@acme.test", readerAuthHash);
        string readerToken = await LoginAsync("reader@acme.test", readerAuthHash);
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, readerId, "Read")).StatusCode);

        // A read-only member can list items.
        var listResponse = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items", readerToken);
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);

        // But cannot create one.
        var readerCreate = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", readerToken, new
        {
            Type = "Password",
            EncryptedPayload = RandomBytes(32),
            FolderId = (Guid?)null,
            IsFavorite = false,
        });
        Assert.Equal(HttpStatusCode.Forbidden, readerCreate.StatusCode);

        // A read-write member can create one.
        var writerAuthHash = RandomBytes(32);
        Guid writerId = await RegisterOperatorAsync(adminToken, "writer@acme.test", writerAuthHash);
        string writerToken = await LoginAsync("writer@acme.test", writerAuthHash);
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(adminToken, vaultId, writerId, "ReadWrite")).StatusCode);

        var writerCreate = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", writerToken, new
        {
            Type = "Password",
            EncryptedPayload = RandomBytes(32),
            FolderId = (Guid?)null,
            IsFavorite = false,
        });
        Assert.Equal(HttpStatusCode.Created, writerCreate.StatusCode);
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task<string> ProvisionAndLoginAsync(string slug, string adminEmail)
    {
        var authHash = RandomBytes(32);
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

    private async Task<Guid> RegisterOperatorAsync(string adminToken, string email, byte[] authHash)
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
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("id").GetGuid();
    }

    private async Task<Guid> CreateOrgVaultAsync(string token, string name)
    {
        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/vaults/organization", token, new
        {
            Name = name,
            WrappedVaultDek = RandomBytes(48),
            EphemeralPublicKey = RandomBytes(32),
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("id").GetGuid();
    }

    private Task<HttpResponseMessage> InviteAsync(string token, Guid vaultId, Guid userId, string permission) =>
        SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/memberships", token, new
        {
            UserId = userId,
            Permission = permission,
            WrappedVaultDek = RandomBytes(48),
            EphemeralPublicKey = RandomBytes(32),
        });

    private async Task<Guid> GetOwnedVaultIdAsync(string token)
    {
        var response = await GetAuthorizedAsync("/api/vaults", token);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.EnumerateArray().First().GetProperty("id").GetGuid();
    }

    private async Task<Guid> GetUserIdByEmailAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CffVaultManagerDbContext>();
        var user = await db.Users.IgnoreQueryFilters().SingleAsync(u => u.Email == email);
        return user.Id;
    }

    private async Task SetPublicKeyAsync(Guid userId, byte[] publicKey)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CffVaultManagerDbContext>();
        var user = await db.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        user.PublicKey = publicKey;
        await db.SaveChangesAsync();
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
