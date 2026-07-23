using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Crypto;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Coverage of <see cref="NotificationService"/> — the in-app counterpart to the security-alert
/// emails (see docs/features/notifications.md) — against an in-memory SQLite database. The link to
/// the three trigger points (new-IP login, master password change, MFA factor disabled) is covered
/// in <c>AuthenticationTests.cs</c> alongside their existing email assertions.
/// </summary>
public sealed class NotificationServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;

    public NotificationServiceTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            ctx.Database.EnsureCreated();
        }

        _authHashHasher = new ServerAuthHashHasher(new Argon2KeyDerivationService(), new Argon2Parameters(memoryKb: 1024, iterations: 1));
    }

    public void Dispose() => _connection.Dispose();

    [Fact]
    public async Task CreateAsync_then_ListAsync_returns_it_newest_first()
    {
        var (tenantId, adminId) = await ProvisionAsync();

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var service = new NotificationService(ctx);
            await service.CreateAsync(tenantId, adminId, NotificationType.MasterPasswordChanged, "La tua master password è stata cambiata.");
            await service.CreateAsync(tenantId, adminId, NotificationType.MfaFactorDisabled, "Il fattore \"Email OTP\" è stato disattivato.");
        }

        using var verify = CreateContext(Tenant(tenantId, adminId));
        var notifications = await new NotificationService(verify).ListAsync(adminId);

        Assert.Equal(2, notifications.Count);
        Assert.Equal(NotificationType.MfaFactorDisabled, notifications[0].Type);
        Assert.Equal(NotificationType.MasterPasswordChanged, notifications[1].Type);
        Assert.All(notifications, n => Assert.Null(n.ReadAt));
    }

    [Fact]
    public async Task ListAsync_never_returns_another_users_notifications()
    {
        var (tenantId, adminId) = await ProvisionAsync();
        var operatorId = await RegisterOperatorAsync(tenantId, adminId);

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new NotificationService(ctx).CreateAsync(tenantId, adminId, NotificationType.MasterPasswordChanged, "admin's notification");
        }

        using var ctx2 = CreateContext(Tenant(tenantId, operatorId));
        var notifications = await new NotificationService(ctx2).ListAsync(operatorId);

        Assert.Empty(notifications);
    }

    [Fact]
    public async Task CountUnreadAsync_reflects_read_state()
    {
        var (tenantId, adminId) = await ProvisionAsync();

        Guid notificationId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var service = new NotificationService(ctx);
            await service.CreateAsync(tenantId, adminId, NotificationType.MasterPasswordChanged, "one");
            await service.CreateAsync(tenantId, adminId, NotificationType.MfaFactorDisabled, "two");
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            notificationId = (await new NotificationService(ctx).ListAsync(adminId)).First().Id;
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            Assert.Equal(2, await new NotificationService(ctx).CountUnreadAsync(adminId));
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new NotificationService(ctx).MarkAsReadAsync(notificationId, adminId);
        }

        using var verify = CreateContext(Tenant(tenantId, adminId));
        Assert.Equal(1, await new NotificationService(verify).CountUnreadAsync(adminId));
    }

    [Fact]
    public async Task MarkAsReadAsync_for_another_users_notification_throws_KeyNotFoundException()
    {
        var (tenantId, adminId) = await ProvisionAsync();
        var operatorId = await RegisterOperatorAsync(tenantId, adminId);

        Guid notificationId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new NotificationService(ctx).CreateAsync(tenantId, adminId, NotificationType.MasterPasswordChanged, "admin's notification");
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            notificationId = (await new NotificationService(ctx).ListAsync(adminId)).Single().Id;
        }

        using var ctx2 = CreateContext(Tenant(tenantId, operatorId));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            new NotificationService(ctx2).MarkAsReadAsync(notificationId, operatorId));
    }

    [Fact]
    public async Task MarkAllAsReadAsync_marks_every_unread_notification_for_the_caller()
    {
        var (tenantId, adminId) = await ProvisionAsync();

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var service = new NotificationService(ctx);
            await service.CreateAsync(tenantId, adminId, NotificationType.MasterPasswordChanged, "one");
            await service.CreateAsync(tenantId, adminId, NotificationType.MfaFactorDisabled, "two");
        }

        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            await new NotificationService(ctx).MarkAllAsReadAsync(adminId);
        }

        using var verify = CreateContext(Tenant(tenantId, adminId));
        Assert.Equal(0, await new NotificationService(verify).CountUnreadAsync(adminId));
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private CffVaultManagerDbContext CreateContext(ITenantContext tenantContext)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlite(_connection)
            .Options;
        return new CffVaultManagerDbContext(options, tenantContext);
    }

    private async Task<(Guid TenantId, Guid AdminId)> ProvisionAsync()
    {
        using var ctx = CreateContext(Unresolved());
        var service = new ProvisionTenantService(ctx, _authHashHasher);
        var result = await service.ProvisionAsync(new ProvisionTenantRequest(
            TenantName: "Acme",
            TenantSlug: "acme",
            AdminEmail: "admin@x.com",
            AuthHash: RandomBytes(32),
            EncryptedDek: RandomBytes(4),
            MasterPasswordSalt: RandomBytes(16),
            KdfMemoryKb: 65536,
            KdfIterations: 3,
            KdfVersion: 1));
        return (result.TenantId, result.AdminUserId);
    }

    private async Task<Guid> RegisterOperatorAsync(Guid tenantId, Guid adminId)
    {
        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new UserRegistrationService(ctx, _authHashHasher);
        return await service.RegisterInTenantAsync(
            new RegisterUserRequest(
                Email: "operator@x.com",
                Role: UserRole.Operator,
                AuthHash: RandomBytes(32),
                EncryptedDek: RandomBytes(4),
                MasterPasswordSalt: RandomBytes(16),
                KdfMemoryKb: 65536,
                KdfIterations: 3,
                KdfVersion: 1),
            adminId, UserRole.Admin, tenantId);
    }

    private static byte[] RandomBytes(int length) => System.Security.Cryptography.RandomNumberGenerator.GetBytes(length);

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
