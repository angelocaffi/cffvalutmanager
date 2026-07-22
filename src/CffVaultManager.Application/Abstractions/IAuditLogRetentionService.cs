namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Purges audit log entries older than the configured retention window (see
/// docs/features/audit-log.md "Conservazione configurabile"). Runs across every tenant, including
/// platform-level entries with a null TenantId: retention is an operational/storage concern, not a
/// per-tenant policy choice.
/// </summary>
public interface IAuditLogRetentionService
{
    /// <summary>Deletes every entry older than the retention window. Returns the number purged.</summary>
    Task<int> PurgeExpiredEntriesAsync(CancellationToken ct = default);
}
