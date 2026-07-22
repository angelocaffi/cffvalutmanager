using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Crypto;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using CffVaultManager.Infrastructure.VaultCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Coverage for <see cref="ExternalShareLinkService"/> (see docs/features/sharing-access-control.md
/// "Link di condivisione esterna"): creation/expiry-clamping, anonymous token lookup (including
/// self-cleaning of expired/revoked rows), revocation, and listing — all against an in-memory SQLite
/// database, mirroring the fixture style of <see cref="VaultMembershipTests"/>.
/// </summary>
public sealed class ExternalShareLinkTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;

    private static readonly X25519KeyExchangeService KeyExchange = new(new AesGcmCipherService());
    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);

    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    private static readonly byte[] Payload = { 9, 8, 7, 6 };

    public ExternalShareLinkTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            ctx.Database.EnsureCreated();
        }

        _authHashHasher = new ServerAuthHashHasher(new Argon2KeyDerivationService(), CheapKdf);
    }

    public void Dispose() => _connection.Dispose();

    // ---- CreateAsync --------------------------------------------------------------------------

    [Fact]
    public async Task CreateAsync_creates_a_link_with_a_token_and_the_requested_expiry()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);

        ExternalShareLinkDto dto;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            dto = await new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, adminId,
                new CreateExternalShareLinkRequest(RandomBytes(32), ExpiresInMinutes: 60));
        }

        Assert.False(string.IsNullOrWhiteSpace(dto.Token));
        Assert.Equal(itemId, dto.VaultItemId);
        Assert.InRange(dto.ExpiresAt, DateTimeOffset.UtcNow.AddMinutes(59), DateTimeOffset.UtcNow.AddMinutes(61));

        using var verify = CreateContext(SuperAdmin());
        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.TenantId == tenantId && a.UserId == adminId && a.Action == AuditAction.ExternalShareLinkCreated));
    }

    [Fact]
    public async Task CreateAsync_clamps_an_excessive_expiry_to_the_server_maximum()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var dto = await new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, adminId,
            new CreateExternalShareLinkRequest(RandomBytes(32), ExpiresInMinutes: 999_999));

        Assert.True(dto.ExpiresAt <= DateTimeOffset.UtcNow.AddDays(7).AddMinutes(1));
    }

    [Fact]
    public async Task CreateAsync_clamps_a_non_positive_expiry_to_the_server_minimum()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var dto = await new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, adminId,
            new CreateExternalShareLinkRequest(RandomBytes(32), ExpiresInMinutes: -10));

        Assert.True(dto.ExpiresAt >= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task CreateAsync_by_a_non_owner_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        using var ctx = CreateContext(Tenant(tenantId, strangerId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, strangerId,
                new CreateExternalShareLinkRequest(RandomBytes(32), 60)));
    }

    [Fact]
    public async Task CreateAsync_for_a_deleted_item_throws_InvalidOperationException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new VaultItemService(ctx).SoftDeleteAsync(vaultId, itemId, adminId);
        }

        using var ctx2 = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new ExternalShareLinkService(ctx2).CreateAsync(vaultId, itemId, adminId,
                new CreateExternalShareLinkRequest(RandomBytes(32), 60)));
    }

    [Fact]
    public async Task CreateAsync_by_a_ReadOnly_org_vault_member_throws_InsufficientVaultPermissionException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var readerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());
        var (orgVault, _) = await CreateOrgVaultAsync(tenantId, adminId, "Team");
        var itemId = await CreateItemAsync(orgVault, adminId);
        await InviteMemberAsync(orgVault, adminId, tenantId, readerId, VaultPermission.Read);

        using var ctx = CreateContext(Tenant(tenantId, readerId));
        await Assert.ThrowsAsync<InsufficientVaultPermissionException>(() =>
            new ExternalShareLinkService(ctx).CreateAsync(orgVault, itemId, readerId,
                new CreateExternalShareLinkRequest(RandomBytes(32), 60)));
    }

    // ---- GetByTokenAsync ----------------------------------------------------------------------

    [Fact]
    public async Task GetByTokenAsync_returns_the_content_for_a_valid_token_with_no_resolved_tenant()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);
        var payload = RandomBytes(32);

        string token;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var dto = await new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, adminId,
                new CreateExternalShareLinkRequest(payload, 60));
            token = dto.Token;
        }

        // The anonymous read path resolves no tenant at all.
        using var anon = CreateContext(Unresolved());
        var content = await new ExternalShareLinkService(anon).GetByTokenAsync(token);

        Assert.NotNull(content);
        Assert.Equal(payload, content!.EncryptedPayload);
    }

    [Fact]
    public async Task GetByTokenAsync_for_an_unknown_token_returns_null()
    {
        using var ctx = CreateContext(Unresolved());
        var content = await new ExternalShareLinkService(ctx).GetByTokenAsync("this-token-does-not-exist");
        Assert.Null(content);
    }

    [Fact]
    public async Task GetByTokenAsync_for_an_expired_token_returns_null_and_deletes_the_row()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);
        string token = await SeedLinkAsync(tenantId, itemId, adminId, DateTimeOffset.UtcNow.AddMinutes(-5));

        using var ctx = CreateContext(Unresolved());
        var content = await new ExternalShareLinkService(ctx).GetByTokenAsync(token);
        Assert.Null(content);

        using var verify = CreateContext(SuperAdmin());
        Assert.False(await verify.ExternalShareLinks.IgnoreQueryFilters().AnyAsync(l => l.Token == token));
    }

    [Fact]
    public async Task GetByTokenAsync_for_a_revoked_token_returns_null()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);

        ExternalShareLinkDto dto;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            dto = await new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, adminId,
                new CreateExternalShareLinkRequest(RandomBytes(32), 60));
            await new ExternalShareLinkService(ctx).RevokeAsync(vaultId, itemId, dto.Id, adminId);
        }

        using var anon = CreateContext(Unresolved());
        var content = await new ExternalShareLinkService(anon).GetByTokenAsync(dto.Token);
        Assert.Null(content);
    }

    // ---- RevokeAsync --------------------------------------------------------------------------

    [Fact]
    public async Task RevokeAsync_marks_the_link_revoked_and_writes_audit()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);

        Guid linkId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var dto = await new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, adminId,
                new CreateExternalShareLinkRequest(RandomBytes(32), 60));
            linkId = dto.Id;
            await new ExternalShareLinkService(ctx).RevokeAsync(vaultId, itemId, linkId, adminId);
        }

        using var verify = CreateContext(SuperAdmin());
        var link = await verify.ExternalShareLinks.IgnoreQueryFilters().SingleAsync(l => l.Id == linkId);
        Assert.NotNull(link.RevokedAt);
        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.TenantId == tenantId && a.UserId == adminId && a.Action == AuditAction.ExternalShareLinkRevoked));
    }

    [Fact]
    public async Task RevokeAsync_by_a_non_owner_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        Guid linkId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var dto = await new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, adminId,
                new CreateExternalShareLinkRequest(RandomBytes(32), 60));
            linkId = dto.Id;
        }

        using var ctx2 = CreateContext(Tenant(tenantId, strangerId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new ExternalShareLinkService(ctx2).RevokeAsync(vaultId, itemId, linkId, strangerId));
    }

    [Fact]
    public async Task RevokeAsync_for_a_nonexistent_link_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new ExternalShareLinkService(ctx).RevokeAsync(vaultId, itemId, Guid.NewGuid(), adminId));
    }

    // ---- ListForItemAsync ---------------------------------------------------------------------

    [Fact]
    public async Task ListForItemAsync_returns_only_active_unexpired_links()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);

        Guid activeLinkId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var active = await new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, adminId,
                new CreateExternalShareLinkRequest(RandomBytes(32), 60));
            activeLinkId = active.Id;

            var toRevoke = await new ExternalShareLinkService(ctx).CreateAsync(vaultId, itemId, adminId,
                new CreateExternalShareLinkRequest(RandomBytes(32), 60));
            await new ExternalShareLinkService(ctx).RevokeAsync(vaultId, itemId, toRevoke.Id, adminId);
        }

        await SeedLinkAsync(tenantId, itemId, adminId, DateTimeOffset.UtcNow.AddMinutes(-1));

        using var ctx2 = CreateContext(Tenant(tenantId, adminId));
        var links = await new ExternalShareLinkService(ctx2).ListForItemAsync(vaultId, itemId, adminId);

        Assert.Single(links);
        Assert.Equal(activeLinkId, links[0].Id);
    }

    [Fact]
    public async Task ListForItemAsync_by_a_non_owner_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        var itemId = await CreateItemAsync(vaultId, adminId);
        var strangerId = await RegisterUserAsync(tenantId, adminId, UniqueEmail());

        using var ctx = CreateContext(Tenant(tenantId, strangerId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new ExternalShareLinkService(ctx).ListForItemAsync(vaultId, itemId, strangerId));
    }

    // ---- Helpers ------------------------------------------------------------------------------

    private CffVaultManagerDbContext CreateContext(ITenantContext tenantContext)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlite(_connection)
            .Options;
        return new CffVaultManagerDbContext(options, tenantContext);
    }

    private async Task<(Guid TenantId, Guid AdminId, Guid VaultId)> ProvisionAsync(
        string slug = "acme", string adminEmail = "admin@x.com")
    {
        ProvisionTenantResult result;
        using (var ctx = CreateContext(Unresolved()))
        {
            var service = new ProvisionTenantService(ctx, _authHashHasher);
            result = await service.ProvisionAsync(NewProvisionRequest(slug, adminEmail));
        }

        using var verify = CreateContext(SuperAdmin());
        var vaultId = (await verify.Vaults.IgnoreQueryFilters().SingleAsync(v => v.OwnerUserId == result.AdminUserId)).Id;
        return (result.TenantId, result.AdminUserId, vaultId);
    }

    private async Task<Guid> RegisterUserAsync(Guid tenantId, Guid adminId, string email)
    {
        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new UserRegistrationService(ctx, _authHashHasher);
        return await service.RegisterInTenantAsync(
            NewRegisterRequest(email, UserRole.Operator), adminId, UserRole.Admin, tenantId);
    }

    private async Task<(Guid VaultId, Guid TenantId)> CreateOrgVaultAsync(Guid tenantId, Guid callerId, string name)
    {
        using var ctx = CreateContext(Tenant(tenantId, callerId));
        var (wrapped, ephemeral) = RealWrappedDek();
        var dto = await new VaultService(ctx).CreateOrganizationVaultAsync(
            callerId, tenantId, new CreateOrganizationVaultRequest(name, wrapped, ephemeral));
        return (dto.Id, tenantId);
    }

    private async Task InviteMemberAsync(Guid vaultId, Guid callerId, Guid tenantId, Guid userId, VaultPermission permission)
    {
        using var ctx = CreateContext(Tenant(tenantId, callerId));
        await new VaultMembershipService(ctx).InviteAsync(vaultId, callerId, tenantId,
            new CreateMembershipRequest(userId, permission, RandomBytes(48), RandomBytes(CryptoConstants.X25519KeyLengthBytes)));
    }

    private async Task<Guid> CreateItemAsync(Guid vaultId, Guid callerId)
    {
        using var ctx = CreateContext(await TenantContextForAsync(vaultId, callerId));
        var dto = await new VaultItemService(ctx)
            .CreateAsync(vaultId, callerId, new CreateVaultItemRequest(VaultItemType.Password, Payload));
        return dto.Id;
    }

    private async Task<ITenantContext> TenantContextForAsync(Guid vaultId, Guid callerId)
    {
        using var ctx = CreateContext(SuperAdmin());
        var vault = await ctx.Vaults.IgnoreQueryFilters().SingleAsync(v => v.Id == vaultId);
        return Tenant(vault.TenantId, callerId);
    }

    /// <summary>Directly seeds an already-expired/near-expiry link, bypassing the service's clamping — used to test expiry handling without waiting in real time.</summary>
    private async Task<string> SeedLinkAsync(Guid tenantId, Guid itemId, Guid createdByUserId, DateTimeOffset expiresAt)
    {
        using var ctx = CreateContext(SuperAdmin());
        string token = Convert.ToBase64String(RandomBytes(32));
        ctx.ExternalShareLinks.Add(new ExternalShareLink(
            Guid.NewGuid(), tenantId, itemId, createdByUserId, token, RandomBytes(32), expiresAt));
        await ctx.SaveChangesAsync();
        return token;
    }

    private static (byte[] Wrapped, byte[] Ephemeral) RealWrappedDek()
    {
        var (publicKey, _) = KeyExchange.GenerateKeyPair();
        var dek = RandomNumberGenerator.GetBytes(CryptoConstants.KeyLengthBytes);
        var (ephemeral, wrapped) = KeyExchange.WrapKey(publicKey, dek);
        return (wrapped.ToBytes(), ephemeral);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    private static string UniqueEmail() => $"u{Guid.NewGuid():N}@x.com";

    private static ProvisionTenantRequest NewProvisionRequest(string slug, string adminEmail) => new(
        TenantName: slug,
        TenantSlug: slug,
        AdminEmail: adminEmail,
        AuthHash: RandomAuthHash(),
        EncryptedDek: Dek,
        MasterPasswordSalt: Salt,
        KdfMemoryKb: 65536,
        KdfIterations: 3,
        KdfVersion: 1);

    private static RegisterUserRequest NewRegisterRequest(string email, UserRole role) => new(
        Email: email,
        Role: role,
        AuthHash: RandomAuthHash(),
        EncryptedDek: Dek,
        MasterPasswordSalt: Salt,
        KdfMemoryKb: 65536,
        KdfIterations: 3,
        KdfVersion: 1);

    private static byte[] RandomAuthHash() => RandomNumberGenerator.GetBytes(32);

    private static ITenantContext Unresolved() => new TenantContext();

    private static ITenantContext Tenant(Guid tenantId, Guid userId)
    {
        var c = new TenantContext();
        c.SetTenant(tenantId, userId);
        return c;
    }

    private static ITenantContext SuperAdmin()
    {
        var c = new TenantContext();
        c.SetSuperAdmin(Guid.NewGuid());
        return c;
    }
}
