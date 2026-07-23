using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Notifications;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <inheritdoc cref="INotificationService"/>
internal sealed class NotificationService : INotificationService
{
    private readonly CffVaultManagerDbContext _db;

    public NotificationService(CffVaultManagerDbContext db) => _db = db;

    public async Task CreateAsync(Guid tenantId, Guid userId, NotificationType type, string message, CancellationToken ct = default)
    {
        var notification = new Notification(Guid.NewGuid(), tenantId, userId, type, message);
        _db.Notifications.Add(notification);
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch
        {
            // The scoped DbContext is shared with the rest of the request (e.g. RefreshTokenService
            // issuing the session right after a login-notification attempt) — leaving a failed insert
            // tracked would poison every later SaveChangesAsync call on it, turning a best-effort
            // notification failure into a failure of the operation that triggered it.
            _db.Entry(notification).State = EntityState.Detached;
            throw;
        }
    }

    public async Task<IReadOnlyList<NotificationDto>> ListAsync(Guid callerId, CancellationToken ct = default)
    {
        // Ordered client-side after materializing: EF Core's SQLite provider (used in tests)
        // cannot translate ORDER BY on a DateTimeOffset column — same fix as elsewhere in this
        // project (VaultItemService.ListAsync, AuditLogService.ListAsync).
        var notifications = await _db.Notifications
            .Where(n => n.UserId == callerId)
            .Select(n => new NotificationDto(n.Id, n.Type, n.Message, n.CreatedAt, n.ReadAt))
            .ToListAsync(ct);

        return notifications.OrderByDescending(n => n.CreatedAt).ToList();
    }

    public Task<int> CountUnreadAsync(Guid callerId, CancellationToken ct = default) =>
        _db.Notifications.CountAsync(n => n.UserId == callerId && n.ReadAt == null, ct);

    public async Task MarkAsReadAsync(Guid notificationId, Guid callerId, CancellationToken ct = default)
    {
        var notification = await _db.Notifications.FirstOrDefaultAsync(n => n.Id == notificationId && n.UserId == callerId, ct)
            ?? throw new KeyNotFoundException("Notification not found.");

        notification.MarkAsRead();
        await _db.SaveChangesAsync(ct);
    }

    public async Task MarkAllAsReadAsync(Guid callerId, CancellationToken ct = default)
    {
        var unread = await _db.Notifications.Where(n => n.UserId == callerId && n.ReadAt == null).ToListAsync(ct);
        foreach (var notification in unread)
        {
            notification.MarkAsRead();
        }

        await _db.SaveChangesAsync(ct);
    }
}
