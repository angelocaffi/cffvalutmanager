using CffVaultManager.Application.Abstractions;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace CffVaultManager.Infrastructure.Audit;

/// <inheritdoc cref="IAuditLogRetentionService"/>
internal sealed class AuditLogRetentionService : IAuditLogRetentionService
{
    private readonly CffVaultManagerDbContext _db;
    private readonly int _retentionDays;

    public AuditLogRetentionService(CffVaultManagerDbContext db, IConfiguration configuration)
    {
        _db = db;
        _retentionDays = configuration.GetValue("AuditLog:RetentionDays", 90);
    }

    public async Task<int> PurgeExpiredEntriesAsync(CancellationToken ct = default)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-_retentionDays);

        // Materialized before filtering: EF Core's SQLite provider (used in tests) cannot
        // translate relational comparisons on a DateTimeOffset column to SQL — same fix as
        // AuditLogService.ListAsync and EmailVerificationService.ResendAsync.
        var all = await _db.AuditLogEntries.IgnoreQueryFilters().ToListAsync(ct);
        var expired = all.Where(a => a.Timestamp < cutoff).ToList();
        if (expired.Count == 0)
        {
            return 0;
        }

        _db.AuditLogEntries.RemoveRange(expired);
        await _db.SaveChangesAsync(ct);
        return expired.Count;
    }
}
