using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Audit;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Crypto;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Audit;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using CffVaultManager.Infrastructure.VaultCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Coverage for audit-trail writes (vault-item CRUD, MFA activation) and reads
/// (<see cref="AuditLogService"/> role-based visibility/filters), per docs/features/audit-log.md.
/// </summary>
public sealed class AuditLogTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;
    private readonly ITotpService _totp;
    private readonly ISecretProtector _secretProtector;

    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);

    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    private static readonly byte[] Payload = { 9, 8, 7, 6 };

    public AuditLogTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            ctx.Database.EnsureCreated();
        }

        _authHashHasher = new ServerAuthHashHasher(new Argon2KeyDerivationService(), CheapKdf);
        _totp = new TotpService();

        var dataProtection = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider()
            .GetRequiredService<IDataProtectionProvider>();
        _secretProtector = new SecretProtector(dataProtection);
    }

    public void Dispose() => _connection.Dispose();

    // ---- VaultItemService writes ------------------------------------------------------------

    [Fact]
    public async Task CreateAsync_writes_a_Created_audit_entry()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();

        VaultItemDto item;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            item = await new VaultItemService(ctx).CreateAsync(vaultId, adminId, NewItemRequest());
        }

        var entry = await SingleEntryAsync(item.Id, AuditAction.Created);
        Assert.Equal(adminId, entry.UserId);
        Assert.Equal(tenantId, entry.TenantId);
    }

    [Fact]
    public async Task GetAsync_writes_a_Viewed_audit_entry()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        Guid itemId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            itemId = (await new VaultItemService(ctx).CreateAsync(vaultId, adminId, NewItemRequest())).Id;
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new VaultItemService(ctx).GetAsync(vaultId, itemId, adminId);
        }

        await SingleEntryAsync(itemId, AuditAction.Viewed);
    }

    [Fact]
    public async Task UpdateAsync_writes_an_Updated_audit_entry()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        Guid itemId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            itemId = (await new VaultItemService(ctx).CreateAsync(vaultId, adminId, NewItemRequest())).Id;
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var update = new UpdateVaultItemRequest(VaultItemType.SecureNote, Payload, FolderId: null, IsFavorite: true);
            await new VaultItemService(ctx).UpdateAsync(vaultId, itemId, adminId, update);
        }

        await SingleEntryAsync(itemId, AuditAction.Updated);
    }

    [Fact]
    public async Task SoftDeleteAsync_writes_a_Deleted_audit_entry()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        Guid itemId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            itemId = (await new VaultItemService(ctx).CreateAsync(vaultId, adminId, NewItemRequest())).Id;
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new VaultItemService(ctx).SoftDeleteAsync(vaultId, itemId, adminId);
        }

        await SingleEntryAsync(itemId, AuditAction.Deleted);
    }

    [Fact]
    public async Task RecordRevealAsync_writes_a_Revealed_audit_entry_referencing_the_item()
    {
        var (tenantId, adminId, vaultId) = await ProvisionAsync();
        Guid itemId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            itemId = (await new VaultItemService(ctx).CreateAsync(vaultId, adminId, NewItemRequest())).Id;
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new VaultItemService(ctx).RecordRevealAsync(vaultId, itemId, adminId);
        }

        await SingleEntryAsync(itemId, AuditAction.Revealed);
    }

    [Fact]
    public async Task RecordRevealAsync_for_a_vault_the_caller_does_not_own_throws_KeyNotFoundException()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var (_, _, otherVaultId) = (tenantId, adminId, await OtherUsersVaultAsync(tenantId, adminId));

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new VaultItemService(ctx).RecordRevealAsync(otherVaultId, Guid.NewGuid(), adminId));
    }

    [Fact]
    public async Task MfaSetupService_ConfirmTotpAsync_writes_an_MfaEnabled_audit_entry()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        byte[] secret = _totp.GenerateSecret();

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var user = await ctx.Users.SingleAsync(u => u.Id == adminId);
            user.MfaSecret = _secretProtector.Protect(secret);
            await ctx.SaveChangesAsync();
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            string code = new OtpNet.Totp(secret).ComputeTotp();
            bool confirmed = await new MfaSetupService(ctx, _totp, _secretProtector).ConfirmTotpAsync(adminId, code);
            Assert.True(confirmed);
        }

        using var verify = CreateContext(SuperAdmin());
        var entry = await verify.AuditLogEntries.IgnoreQueryFilters()
            .SingleAsync(a => a.UserId == adminId && a.Action == AuditAction.MfaEnabled);
        Assert.Equal(tenantId, entry.TenantId);
    }

    // ---- AuditLogService reads --------------------------------------------------------------

    [Fact]
    public async Task ListAsync_as_Admin_sees_every_users_entries_in_the_tenant()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, "op@x.com");

        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed);
        await SeedEntryAsync(tenantId, operatorId, AuditAction.Viewed);

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var entries = await new AuditLogService(ctx)
            .ListAsync(adminId, UserRole.Admin, new AuditLogQuery(Action: AuditAction.Viewed));

        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => e.UserId == adminId);
        Assert.Contains(entries, e => e.UserId == operatorId);
    }

    [Fact]
    public async Task ListAsync_as_Operator_sees_only_their_own_entries()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        var operatorId = await RegisterUserAsync(tenantId, adminId, "op@x.com");

        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed);
        await SeedEntryAsync(tenantId, operatorId, AuditAction.Viewed);

        using var ctx = CreateContext(Tenant(tenantId, operatorId));
        var entries = await new AuditLogService(ctx)
            .ListAsync(operatorId, UserRole.Operator, new AuditLogQuery(Action: AuditAction.Viewed));

        Assert.Single(entries);
        Assert.Equal(operatorId, entries[0].UserId);
    }

    [Fact]
    public async Task ListAsync_filters_by_time_range()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();

        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed, DateTimeOffset.UtcNow.AddDays(-10));
        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed, DateTimeOffset.UtcNow);

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var entries = await new AuditLogService(ctx).ListAsync(adminId, UserRole.Admin,
            new AuditLogQuery(Action: AuditAction.Viewed, From: DateTimeOffset.UtcNow.AddDays(-1)));

        Assert.Single(entries);
    }

    [Fact]
    public async Task ListAsync_orders_newest_first_and_respects_skip_and_take()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();

        var t1 = DateTimeOffset.UtcNow.AddMinutes(-3);
        var t2 = DateTimeOffset.UtcNow.AddMinutes(-2);
        var t3 = DateTimeOffset.UtcNow.AddMinutes(-1);
        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed, t1);
        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed, t2);
        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed, t3);

        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new AuditLogService(ctx);

        var page1 = await service.ListAsync(adminId, UserRole.Admin, new AuditLogQuery(Action: AuditAction.Viewed, Take: 1));
        var page2 = await service.ListAsync(adminId, UserRole.Admin, new AuditLogQuery(Action: AuditAction.Viewed, Skip: 1, Take: 1));

        Assert.Equal(t3, page1[0].Timestamp);
        Assert.Equal(t2, page2[0].Timestamp);
    }

    // ---- AuditLogRetentionService -------------------------------------------------------------

    [Fact]
    public async Task PurgeExpiredEntriesAsync_deletes_entries_older_than_the_retention_window()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed, DateTimeOffset.UtcNow.AddDays(-91));

        using var ctx = CreateContext(SuperAdmin());
        int purged = await new AuditLogRetentionService(ctx, RetentionConfig(90)).PurgeExpiredEntriesAsync();

        Assert.Equal(1, purged);
        Assert.Empty(await ctx.AuditLogEntries.IgnoreQueryFilters().Where(a => a.Action == AuditAction.Viewed).ToListAsync());
    }

    [Fact]
    public async Task PurgeExpiredEntriesAsync_keeps_entries_within_the_retention_window()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed, DateTimeOffset.UtcNow.AddDays(-89));

        using var ctx = CreateContext(SuperAdmin());
        int purged = await new AuditLogRetentionService(ctx, RetentionConfig(90)).PurgeExpiredEntriesAsync();

        Assert.Equal(0, purged);
        Assert.Single(await ctx.AuditLogEntries.IgnoreQueryFilters().Where(a => a.Action == AuditAction.Viewed).ToListAsync());
    }

    [Fact]
    public async Task PurgeExpiredEntriesAsync_honors_a_configured_retention_window()
    {
        var (tenantId, adminId, _) = await ProvisionAsync();
        await SeedEntryAsync(tenantId, adminId, AuditAction.Viewed, DateTimeOffset.UtcNow.AddDays(-10));

        using var ctx = CreateContext(SuperAdmin());
        int purged = await new AuditLogRetentionService(ctx, RetentionConfig(7)).PurgeExpiredEntriesAsync();

        Assert.Equal(1, purged);
    }

    [Fact]
    public async Task PurgeExpiredEntriesAsync_purges_entries_across_every_tenant()
    {
        var (tenant1Id, admin1Id, _) = await ProvisionAsync("acme1", "admin1@x.com");
        var (tenant2Id, admin2Id, _) = await ProvisionAsync("acme2", "admin2@x.com");
        await SeedEntryAsync(tenant1Id, admin1Id, AuditAction.Viewed, DateTimeOffset.UtcNow.AddDays(-91));
        await SeedEntryAsync(tenant2Id, admin2Id, AuditAction.Viewed, DateTimeOffset.UtcNow.AddDays(-91));

        using var ctx = CreateContext(SuperAdmin());
        int purged = await new AuditLogRetentionService(ctx, RetentionConfig(90)).PurgeExpiredEntriesAsync();

        Assert.Equal(2, purged);
    }

    private static IConfiguration RetentionConfig(int retentionDays) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["AuditLog:RetentionDays"] = retentionDays.ToString(),
        })
        .Build();

    // ---- Helpers -----------------------------------------------------------------------------

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

    private async Task<Guid> OtherUsersVaultAsync(Guid tenantId, Guid adminId)
    {
        var otherUserId = await RegisterUserAsync(tenantId, adminId, "other@x.com");
        using var ctx = CreateContext(SuperAdmin());
        return (await ctx.Vaults.IgnoreQueryFilters().SingleAsync(v => v.OwnerUserId == otherUserId)).Id;
    }

    private async Task SeedEntryAsync(Guid tenantId, Guid userId, AuditAction action, DateTimeOffset? timestamp = null)
    {
        using var ctx = CreateContext(SuperAdmin());
        ctx.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), tenantId, userId, action, timestamp: timestamp));
        await ctx.SaveChangesAsync();
    }

    private async Task<AuditLogEntry> SingleEntryAsync(Guid vaultItemId, AuditAction action)
    {
        using var verify = CreateContext(SuperAdmin());
        return await verify.AuditLogEntries.IgnoreQueryFilters()
            .SingleAsync(a => a.VaultItemId == vaultItemId && a.Action == action);
    }

    private static CreateVaultItemRequest NewItemRequest() => new(VaultItemType.SecureNote, Payload);

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

    private static byte[] RandomAuthHash() => System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

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
