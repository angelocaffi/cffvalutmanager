using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Audit;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Audit;

/// <inheritdoc cref="IAuditLogService"/>
internal sealed class AuditLogService : IAuditLogService
{
    private const int MaxPageSize = 200;

    private readonly CffVaultManagerDbContext _db;

    public AuditLogService(CffVaultManagerDbContext db) => _db = db;

    public async Task<IReadOnlyList<AuditLogEntryDto>> ListAsync(
        Guid callerId, UserRole callerRole, AuditLogQuery query, CancellationToken ct = default)
    {
        // The tenant query filter already scopes this to the caller's own tenant; an Operator is
        // further restricted to their own actions (see docs/features/roles-permissions.md).
        IQueryable<AuditLogEntry> q = _db.AuditLogEntries;

        if (callerRole != UserRole.Admin)
        {
            q = q.Where(a => a.UserId == callerId);
        }

        if (query.Action is not null)
        {
            q = q.Where(a => a.Action == query.Action);
        }

        // From/To/ordering/paging all happen client-side after materializing the filtered set:
        // EF Core's SQLite provider (used in tests) cannot translate relational comparisons or
        // ORDER BY on a DateTimeOffset column — see the same issue/fix in
        // VaultItemService.ListAsync. Callers are expected to narrow with From/To for large
        // histories; unbounded retention/archival is a separate, not-yet-built concern (see
        // docs/features/audit-log.md).
        var entries = await q
            .Select(a => new AuditLogEntryDto(a.Id, a.UserId, a.VaultItemId, a.Action, a.Timestamp, a.IpAddress, a.UserAgent))
            .ToListAsync(ct);

        IEnumerable<AuditLogEntryDto> filtered = entries;
        if (query.From is not null)
        {
            filtered = filtered.Where(a => a.Timestamp >= query.From);
        }

        if (query.To is not null)
        {
            filtered = filtered.Where(a => a.Timestamp <= query.To);
        }

        int skip = Math.Max(query.Skip, 0);
        int take = Math.Clamp(query.Take, 1, MaxPageSize);

        return filtered
            .OrderByDescending(a => a.Timestamp)
            .Skip(skip)
            .Take(take)
            .ToList();
    }
}
