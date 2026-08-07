using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Crypto;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>Coverage for inviting a new user into an existing tenant (see docs/features/roles-permissions.md "Invito di nuovi utenti").</summary>
public sealed class UserInvitationServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;
    private readonly FakeEmailSender _emailSender = new();
    private static readonly IConfiguration EmptyConfig = new ConfigurationBuilder().Build();
    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);
    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    public UserInvitationServiceTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using (var ctx = CreateContext(Unresolved()))
        {
            ctx.Database.EnsureCreated();
        }

        _authHashHasher = new ServerAuthHashHasher(new Argon2KeyDerivationService(), CheapKdf);
    }

    public void Dispose() => _connection.Dispose();

    [Fact]
    public async Task InviteAsync_createsAPendingInvitation_andSendsAnEmail()
    {
        var (tenantId, adminId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var invitation = await new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig)
            .InviteAsync("newbie@acme.test", UserRole.Operator, adminId, tenantId);

        Assert.Equal("newbie@acme.test", invitation.Email);
        Assert.Equal(UserRole.Operator, invitation.Role);
        Assert.Equal(1, _emailSender.SendCount);
        Assert.Equal("newbie@acme.test", _emailSender.LastToEmail);
        Assert.Contains("/invite/", _emailSender.LastBody);
    }

    [Fact]
    public async Task InviteAsync_withAnEmailAlreadyUsedByAnyUser_throwsInvalidOperationException()
    {
        var (tenantId, adminId) = await ProvisionAsync();
        var (_, otherAdminId) = await ProvisionAsync("other", "other-admin@x.test");

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig)
                .InviteAsync("other-admin@x.test", UserRole.Operator, adminId, tenantId));
    }

    [Fact]
    public async Task InviteAsync_asSuperAdminRole_throwsArgumentException()
    {
        var (tenantId, adminId) = await ProvisionAsync();

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig)
                .InviteAsync("newbie@acme.test", UserRole.SuperAdmin, adminId, tenantId));
    }

    [Fact]
    public async Task ListPendingAsync_isScopedToTheCallersOwnTenant()
    {
        var (tenantA, adminA) = await ProvisionAsync("acme-a", "admin-a@x.test");
        var (tenantB, adminB) = await ProvisionAsync("acme-b", "admin-b@x.test");

        using (var ctx = CreateContext(Tenant(tenantA, adminA)))
        {
            await new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig)
                .InviteAsync("newbie-a@x.test", UserRole.Operator, adminA, tenantA);
        }

        using var read = CreateContext(Tenant(tenantB, adminB));
        var pendingForB = await new UserInvitationService(read, _authHashHasher, _emailSender, EmptyConfig)
            .ListPendingAsync(tenantB);

        Assert.Empty(pendingForB);
    }

    [Fact]
    public async Task GetPreviewAsync_forAnUnknownToken_returnsNull()
    {
        using var ctx = CreateContext(Unresolved());
        var preview = await new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig).GetPreviewAsync("no-such-token");

        Assert.Null(preview);
    }

    [Fact]
    public async Task GetPreviewAsync_forARevokedInvitation_returnsNull()
    {
        var (tenantId, adminId) = await ProvisionAsync();
        string token;

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var service = new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig);
            await service.InviteAsync("newbie@acme.test", UserRole.Operator, adminId, tenantId);
            var pending = await service.ListPendingAsync(tenantId);
            token = await ExtractTokenAsync(ctx, pending[0].Id);
            await service.RevokeAsync(pending[0].Id, tenantId);
        }

        using var read = CreateContext(Unresolved());
        var preview = await new UserInvitationService(read, _authHashHasher, _emailSender, EmptyConfig).GetPreviewAsync(token);

        Assert.Null(preview);
    }

    [Fact]
    public async Task AcceptAsync_withAValidToken_createsUserAndPersonalVault_andConsumesTheInvitation()
    {
        var (tenantId, adminId) = await ProvisionAsync();
        string token;
        Guid invitationId;

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var service = new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig);
            var invitation = await service.InviteAsync("newbie@acme.test", UserRole.Operator, adminId, tenantId);
            invitationId = invitation.Id;
            token = await ExtractTokenAsync(ctx, invitation.Id);
        }

        using (var ctx = CreateContext(Unresolved()))
        {
            var userId = await new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig)
                .AcceptAsync(token, RandomAuthHash(), Dek, Salt, 65536, 3, 1);

            Assert.NotNull(userId);

            var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
            Assert.Equal(tenantId, user.TenantId);
            Assert.Equal(UserRole.Operator, user.Role);
            Assert.Equal("newbie@acme.test", user.Email);

            Assert.True(await ctx.Vaults.IgnoreQueryFilters().AnyAsync(v => v.OwnerUserId == userId && !v.IsOrganizationVault));
            Assert.Equal(0, await ctx.UserInvitations.IgnoreQueryFilters().CountAsync(i => i.Id == invitationId));
        }
    }

    [Fact]
    public async Task AcceptAsync_withAnExpiredToken_returnsNull_andCreatesNothing()
    {
        var (tenantId, adminId) = await ProvisionAsync();
        var expired = new UserInvitation(Guid.NewGuid(), tenantId, "newbie@acme.test", UserRole.Operator, adminId, "expired-token", DateTimeOffset.UtcNow.AddDays(-1));

        using (var ctx = CreateContext(Unresolved()))
        {
            ctx.UserInvitations.Add(expired);
            await ctx.SaveChangesAsync();
        }

        using var read = CreateContext(Unresolved());
        var userId = await new UserInvitationService(read, _authHashHasher, _emailSender, EmptyConfig)
            .AcceptAsync("expired-token", RandomAuthHash(), Dek, Salt, 65536, 3, 1);

        Assert.Null(userId);
        Assert.Equal(0, await read.Users.IgnoreQueryFilters().CountAsync(u => u.Email == "newbie@acme.test"));
    }

    [Fact]
    public async Task RevokeAsync_preventsASubsequentAccept()
    {
        var (tenantId, adminId) = await ProvisionAsync();
        string token;

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var service = new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig);
            var invitation = await service.InviteAsync("newbie@acme.test", UserRole.Operator, adminId, tenantId);
            token = await ExtractTokenAsync(ctx, invitation.Id);
            await service.RevokeAsync(invitation.Id, tenantId);
        }

        using var read = CreateContext(Unresolved());
        var userId = await new UserInvitationService(read, _authHashHasher, _emailSender, EmptyConfig)
            .AcceptAsync(token, RandomAuthHash(), Dek, Salt, 65536, 3, 1);

        Assert.Null(userId);
    }

    [Fact]
    public async Task PurgeExpiredAsync_removesOnlyExpiredInvitations()
    {
        var (tenantId, adminId) = await ProvisionAsync();
        var expired = new UserInvitation(Guid.NewGuid(), tenantId, "old@acme.test", UserRole.Operator, adminId, "old-token", DateTimeOffset.UtcNow.AddDays(-1));

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new UserInvitationService(ctx, _authHashHasher, _emailSender, EmptyConfig);
        var fresh = await service.InviteAsync("newbie@acme.test", UserRole.Operator, adminId, tenantId);
        ctx.UserInvitations.Add(expired);
        await ctx.SaveChangesAsync();

        int purged = await service.PurgeExpiredAsync();

        Assert.Equal(1, purged);
        var remaining = await ctx.UserInvitations.SingleAsync();
        Assert.Equal(fresh.Id, remaining.Id);
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private CffVaultManagerDbContext CreateContext(ITenantContext tenantContext)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>().UseSqlite(_connection).Options;
        return new CffVaultManagerDbContext(options, tenantContext);
    }

    private async Task<(Guid TenantId, Guid AdminId)> ProvisionAsync(string slug = "acme", string email = "admin@acme.test")
    {
        using var ctx = CreateContext(Unresolved());
        var service = new ProvisionTenantService(ctx, _authHashHasher);
        var result = await service.ProvisionAsync(new ProvisionTenantRequest(
            slug, slug, email, RandomAuthHash(), Dek, Salt, 65536, 3, 1));
        return (result.TenantId, result.AdminUserId);
    }

    private static async Task<string> ExtractTokenAsync(CffVaultManagerDbContext ctx, Guid invitationId) =>
        (await ctx.UserInvitations.IgnoreQueryFilters().SingleAsync(i => i.Id == invitationId)).Token;

    private static byte[] RandomAuthHash() => RandomNumberGenerator.GetBytes(32);

    private static ITenantContext Unresolved() => new TenantContext();

    private static ITenantContext Tenant(Guid tenantId, Guid userId)
    {
        var c = new TenantContext();
        c.SetTenant(tenantId, userId);
        return c;
    }

    private sealed class FakeEmailSender : IEmailSender
    {
        public string? LastToEmail;
        public string? LastBody;
        public int SendCount;

        public Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
        {
            LastToEmail = toEmail;
            LastBody = body;
            SendCount++;
            return Task.CompletedTask;
        }
    }
}
