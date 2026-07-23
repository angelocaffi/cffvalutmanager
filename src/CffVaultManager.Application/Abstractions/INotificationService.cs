using CffVaultManager.Application.Dtos.Notifications;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// In-app notifications for a single user (see docs/features/notifications.md) — the in-app
/// counterpart to the email alerts sent by <see cref="ISecurityNotificationService"/>, created at
/// the same three trigger points. Every read here is already scoped to the caller: there is no
/// cross-user visibility, unlike the tenant-wide audit log.
/// </summary>
public interface INotificationService
{
    /// <summary>Called by <see cref="ISecurityNotificationService"/>, never directly by an endpoint.</summary>
    Task CreateAsync(Guid tenantId, Guid userId, NotificationType type, string message, CancellationToken ct = default);

    Task<IReadOnlyList<NotificationDto>> ListAsync(Guid callerId, CancellationToken ct = default);

    Task<int> CountUnreadAsync(Guid callerId, CancellationToken ct = default);

    Task MarkAsReadAsync(Guid notificationId, Guid callerId, CancellationToken ct = default);

    Task MarkAllAsReadAsync(Guid callerId, CancellationToken ct = default);
}
