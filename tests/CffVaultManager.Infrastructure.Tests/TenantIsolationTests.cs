using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure;
using CffVaultManager.Infrastructure.Administration;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Exercises the EF Core global query filters against a real (in-memory SQLite) database so the
/// generated SQL — not just the model — enforces tenant isolation. Each test keeps its own
/// connection open for its lifetime and builds the schema from the model with EnsureCreated.
/// </summary>
public sealed class TenantIsolationTests : IDisposable
{
    private readonly SqliteConnection _connection;

    private static readonly byte[] Dek = new byte[] { 1, 2, 3, 4 };
    private static readonly byte[] Payload = new byte[] { 9, 8, 7, 6 };

    public TenantIsolationTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        // Build the schema once; the tenant context used here is irrelevant to writes.
        using var ctx = CreateContext(SuperAdmin(Guid.NewGuid()));
        ctx.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private CffVaultManagerDbContext CreateContext(ITenantContext tenantContext)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlite(_connection)
            .Options;
        return new CffVaultManagerDbContext(options, tenantContext);
    }

    private static ITenantContext Tenant(Guid tenantId, Guid userId)
    {
        var c = new TenantContext();
        c.SetTenant(tenantId, userId);
        return c;
    }

    private static ITenantContext SuperAdmin(Guid userId)
    {
        var c = new TenantContext();
        c.SetSuperAdmin(userId);
        return c;
    }

    [Fact]
    public void Vault_query_returns_only_current_tenants_vaults()
    {
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var vaultA = Guid.NewGuid();
        var vaultB = Guid.NewGuid();
        var userA = Guid.NewGuid();

        using (var seed = CreateContext(SuperAdmin(Guid.NewGuid())))
        {
            seed.Tenants.AddRange(NewTenant(tenantA), NewTenant(tenantB));
            seed.Vaults.Add(new Vault(vaultA, tenantA, "A vault", isOrganizationVault: true, ownerUserId: null));
            seed.Vaults.Add(new Vault(vaultB, tenantB, "B vault", isOrganizationVault: true, ownerUserId: null));
            seed.SaveChanges();
        }

        using var ctx = CreateContext(Tenant(tenantA, userA));
        var vaults = ctx.Vaults.ToList();

        Assert.Single(vaults);
        Assert.Equal(vaultA, vaults[0].Id);
    }

    [Fact]
    public void VaultItem_lookup_by_known_id_across_tenant_returns_null()
    {
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var vaultB = Guid.NewGuid();
        var itemB = Guid.NewGuid();

        using (var seed = CreateContext(SuperAdmin(Guid.NewGuid())))
        {
            seed.Tenants.AddRange(NewTenant(tenantA), NewTenant(tenantB));
            seed.Vaults.Add(new Vault(vaultB, tenantB, "B vault", isOrganizationVault: true, ownerUserId: null));
            seed.VaultItems.Add(new VaultItem(itemB, tenantB, vaultB, VaultItemType.Password, Payload));
            seed.SaveChanges();
        }

        using var ctx = CreateContext(Tenant(tenantA, Guid.NewGuid()));

        // Even an exact-id lookup (classic IDOR) must not leak another tenant's item.
        var found = ctx.VaultItems.FirstOrDefault(i => i.Id == itemB);
        Assert.Null(found);
    }

    [Fact]
    public void User_filter_isolates_tenants_and_hides_tenant_users_from_superadmin()
    {
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var userA = Guid.NewGuid();
        var userB = Guid.NewGuid();
        var otherSuperAdmin = Guid.NewGuid();

        using (var seed = CreateContext(SuperAdmin(Guid.NewGuid())))
        {
            seed.Tenants.AddRange(NewTenant(tenantA), NewTenant(tenantB));
            seed.Users.Add(User.CreateTenantUser(userA, tenantA, "a@x.com", UserRole.Admin, Dek));
            seed.Users.Add(User.CreateTenantUser(userB, tenantB, "b@x.com", UserRole.Admin, Dek));
            seed.Users.Add(User.CreateSuperAdmin(otherSuperAdmin, "root@x.com", Dek));
            seed.SaveChanges();
        }

        using (var ctxA = CreateContext(Tenant(tenantA, userA)))
        {
            var users = ctxA.Users.Select(u => u.Id).ToList();
            Assert.Contains(userA, users);
            Assert.DoesNotContain(userB, users);
            Assert.DoesNotContain(otherSuperAdmin, users);
        }

        using (var ctxSuper = CreateContext(SuperAdmin(Guid.NewGuid())))
        {
            var users = ctxSuper.Users.Select(u => u.Id).ToList();
            // A SuperAdmin sees only other tenant-less SuperAdmins, never any tenant's users.
            Assert.Contains(otherSuperAdmin, users);
            Assert.DoesNotContain(userA, users);
            Assert.DoesNotContain(userB, users);
        }
    }

    [Fact]
    public void AuditLogEntry_platform_events_visible_only_to_superadmin()
    {
        var tenantA = Guid.NewGuid();
        var userA = Guid.NewGuid();
        var superAdminId = Guid.NewGuid();
        var platformEntryId = Guid.NewGuid();
        var tenantEntryId = Guid.NewGuid();

        using (var seed = CreateContext(SuperAdmin(Guid.NewGuid())))
        {
            seed.Tenants.Add(NewTenant(tenantA));
            seed.Users.Add(User.CreateTenantUser(userA, tenantA, "a@x.com", UserRole.Admin, Dek));
            seed.Users.Add(User.CreateSuperAdmin(superAdminId, "root@x.com", Dek));
            seed.AuditLogEntries.Add(new AuditLogEntry(platformEntryId, tenantId: null, superAdminId, AuditAction.TenantProvisioned));
            seed.AuditLogEntries.Add(new AuditLogEntry(tenantEntryId, tenantA, userA, AuditAction.LoginSuccess));
            seed.SaveChanges();
        }

        using (var ctxA = CreateContext(Tenant(tenantA, userA)))
        {
            var ids = ctxA.AuditLogEntries.Select(a => a.Id).ToList();
            Assert.Contains(tenantEntryId, ids);
            Assert.DoesNotContain(platformEntryId, ids);
        }

        using (var ctxSuper = CreateContext(SuperAdmin(superAdminId)))
        {
            var ids = ctxSuper.AuditLogEntries.Select(a => a.Id).ToList();
            Assert.Contains(platformEntryId, ids);
            Assert.DoesNotContain(tenantEntryId, ids);
        }
    }

    [Fact]
    public void VaultItemTag_join_row_is_isolated_by_its_vault_items_tenant()
    {
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var vaultA = Guid.NewGuid();
        var itemA = Guid.NewGuid();
        var tagA = Guid.NewGuid();

        using (var seed = CreateContext(SuperAdmin(Guid.NewGuid())))
        {
            seed.Tenants.AddRange(NewTenant(tenantA), NewTenant(tenantB));
            seed.Vaults.Add(new Vault(vaultA, tenantA, "A vault", isOrganizationVault: true, ownerUserId: null));
            seed.VaultItems.Add(new VaultItem(itemA, tenantA, vaultA, VaultItemType.Password, Payload));
            seed.Tags.Add(new Tag(tagA, tenantA, vaultA, "tag"));
            seed.VaultItemTags.Add(new VaultItemTag(itemA, tagA));
            seed.SaveChanges();
        }

        using var ctxB = CreateContext(Tenant(tenantB, Guid.NewGuid()));
        Assert.Empty(ctxB.VaultItemTags.ToList());
    }

    [Fact]
    public void Unresolved_context_is_fail_closed_and_returns_empty_sets()
    {
        var tenantA = Guid.NewGuid();
        var vaultA = Guid.NewGuid();

        using (var seed = CreateContext(SuperAdmin(Guid.NewGuid())))
        {
            seed.Tenants.Add(NewTenant(tenantA));
            seed.Vaults.Add(new Vault(vaultA, tenantA, "A vault", isOrganizationVault: true, ownerUserId: null));
            seed.VaultItems.Add(new VaultItem(Guid.NewGuid(), tenantA, vaultA, VaultItemType.Password, Payload));
            seed.SaveChanges();
        }

        var unresolved = new TenantContext();
        Assert.False(unresolved.IsResolved);

        using var ctx = CreateContext(unresolved);
        Assert.Empty(ctx.Vaults.ToList());
        Assert.Empty(ctx.VaultItems.ToList());
        Assert.Empty(ctx.Users.ToList());
    }

    [Fact]
    public async Task Admin_service_reports_correct_cross_tenant_usage()
    {
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var vaultA = Guid.NewGuid();
        var login = DateTimeOffset.UtcNow.AddMinutes(-5);

        using (var seed = CreateContext(SuperAdmin(Guid.NewGuid())))
        {
            seed.Tenants.AddRange(NewTenant(tenantA, "Tenant A", "tenant-a"), NewTenant(tenantB, "Tenant B", "tenant-b"));

            var user1 = User.CreateTenantUser(Guid.NewGuid(), tenantA, "u1@x.com", UserRole.Admin, Dek);
            user1.LastLoginAt = login;
            var user2 = User.CreateTenantUser(Guid.NewGuid(), tenantA, "u2@x.com", UserRole.Operator, Dek);
            seed.Users.AddRange(user1, user2);
            seed.Users.Add(User.CreateTenantUser(Guid.NewGuid(), tenantB, "u3@x.com", UserRole.Admin, Dek));

            seed.Vaults.Add(new Vault(vaultA, tenantA, "A vault", isOrganizationVault: true, ownerUserId: null));
            seed.VaultItems.Add(new VaultItem(Guid.NewGuid(), tenantA, vaultA, VaultItemType.Password, Payload));
            seed.VaultItems.Add(new VaultItem(Guid.NewGuid(), tenantA, vaultA, VaultItemType.SecureNote, Payload));
            seed.SaveChanges();
        }

        // A tenant-scoped context proves the service bypasses the filters internally.
        using var ctx = CreateContext(Tenant(tenantB, Guid.NewGuid()));
        var service = new TenantAdministrationService(ctx);

        var usage = await service.GetTenantUsageAsync(tenantA);

        Assert.NotNull(usage);
        Assert.Equal(2, usage!.UserCount);
        Assert.Equal(1, usage.VaultCount);
        Assert.Equal(2, usage.VaultItemCount);
        Assert.Equal(login, usage.LastUserLoginAt);

        var all = await service.GetAllTenantsAsync();
        Assert.Equal(2, all.Count);
    }

    private static Tenant NewTenant(Guid id, string? name = null, string? slug = null) =>
        new(id, name ?? $"Tenant {id:N}", slug ?? id.ToString("N"), TenantStatus.Active);
}
