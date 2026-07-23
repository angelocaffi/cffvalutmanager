using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// In-app notification surfaced to a single user (see docs/features/notifications.md) — created by
/// <c>SecurityNotificationService</c> alongside the equivalent security-alert email, at the same
/// three trigger points. Never carries secret content, only a short human-readable description of
/// the event (same discipline already used for the email alerts).
/// </summary>
public class Notification
{
    private Notification()
    {
        // Parameterless constructor for EF Core / serialization.
        Message = null!;
    }

    public Notification(
        Guid id,
        Guid tenantId,
        Guid userId,
        NotificationType type,
        string message,
        DateTimeOffset? createdAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
        UserId = Guard.AgainstEmptyGuid(userId);
        Type = type;
        Message = Guard.AgainstNullOrWhiteSpace(message);
        CreatedAt = createdAt ?? DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Guid UserId { get; private set; }

    public User? User { get; set; }

    public NotificationType Type { get; private set; }

    public string Message { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? ReadAt { get; private set; }

    /// <summary>Idempotent: marking an already-read notification again is a no-op.</summary>
    public void MarkAsRead() => ReadAt ??= DateTimeOffset.UtcNow;
}
