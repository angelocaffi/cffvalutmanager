using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Administration;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Administration;

/// <summary>
/// Platform-administration queries that bypass the tenant global query filters via
/// <see cref="EntityFrameworkQueryableExtensions.IgnoreQueryFilters{TEntity}"/>. Results are
/// always projected into metadata-only DTOs so no entity (and no secret-bearing column) escapes.
/// </summary>
internal sealed class TenantAdministrationService : ITenantAdministrationService
{
    private readonly CffVaultManagerDbContext _db;

    public TenantAdministrationService(CffVaultManagerDbContext db) => _db = db;

    public async Task<IReadOnlyList<TenantSummaryDto>> GetAllTenantsAsync(CancellationToken ct = default)
    {
        return await _db.Tenants
            .IgnoreQueryFilters()
            .OrderBy(t => t.Name)
            .Select(t => new TenantSummaryDto(
                t.Id,
                t.Name,
                t.Slug,
                t.Status,
                t.PlanName,
                _db.Users.IgnoreQueryFilters().Count(u => u.TenantId == t.Id),
                _db.Vaults.IgnoreQueryFilters().Count(v => v.TenantId == t.Id),
                t.CreatedAt))
            .ToListAsync(ct);
    }

    public async Task<TenantUsageSummaryDto?> GetTenantUsageAsync(Guid tenantId, CancellationToken ct = default)
    {
        var tenant = await _db.Tenants
            .IgnoreQueryFilters()
            .Where(t => t.Id == tenantId)
            .Select(t => new { t.Id, t.Name, t.Slug, t.Status })
            .FirstOrDefaultAsync(ct);

        if (tenant is null)
        {
            return null;
        }

        var userCount = await _db.Users.IgnoreQueryFilters().CountAsync(u => u.TenantId == tenantId, ct);
        var vaultCount = await _db.Vaults.IgnoreQueryFilters().CountAsync(v => v.TenantId == tenantId, ct);
        var vaultItemCount = await _db.VaultItems.IgnoreQueryFilters().CountAsync(i => i.TenantId == tenantId, ct);

        // Max is computed client-side over the tenant's bounded set of login timestamps: the
        // SQLite test provider supports neither aggregate Max nor ORDER BY over DateTimeOffset.
        var logins = await _db.Users
            .IgnoreQueryFilters()
            .Where(u => u.TenantId == tenantId && u.LastLoginAt != null)
            .Select(u => u.LastLoginAt)
            .ToListAsync(ct);

        var lastLogin = logins.Count == 0 ? null : logins.Max();

        return new TenantUsageSummaryDto(
            tenant.Id,
            tenant.Name,
            tenant.Slug,
            tenant.Status,
            userCount,
            vaultCount,
            vaultItemCount,
            lastLogin);
    }
}
