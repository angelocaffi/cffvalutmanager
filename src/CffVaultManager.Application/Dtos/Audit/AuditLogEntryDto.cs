using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Audit;

/// <summary>
/// An audit trail entry as returned to the client. Never carries secret content — only a
/// reference to the affected item, per docs/features/audit-log.md.
/// </summary>
public sealed record AuditLogEntryDto(
    Guid Id,
    Guid UserId,
    Guid? VaultItemId,
    AuditAction Action,
    DateTimeOffset Timestamp,
    string? IpAddress,
    string? UserAgent);

/// <summary>
/// Filter/pagination criteria for listing the audit trail. <see cref="Take"/> is clamped to a
/// maximum page size by the service.
/// </summary>
public sealed record AuditLogQuery(
    AuditAction? Action = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int Skip = 0,
    int Take = 50);
