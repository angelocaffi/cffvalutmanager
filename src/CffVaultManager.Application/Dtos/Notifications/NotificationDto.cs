using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Notifications;

/// <summary>
/// An in-app notification as returned to the client. Never carries secret content — only a short
/// human-readable description of the event, per docs/features/notifications.md.
/// </summary>
public sealed record NotificationDto(
    Guid Id,
    NotificationType Type,
    string Message,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ReadAt);
