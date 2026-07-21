using CffVaultManager.Application.Dtos.Administration;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Platform-administrator surface that deliberately bypasses tenant query filters.
/// Every method projects into metadata-only DTOs; no <see cref="IQueryable{T}"/> over
/// entities and no secret-bearing fields ever cross this boundary.
/// </summary>
public interface ITenantAdministrationService
{
    Task<IReadOnlyList<TenantSummaryDto>> GetAllTenantsAsync(CancellationToken ct = default);

    Task<TenantUsageSummaryDto?> GetTenantUsageAsync(Guid tenantId, CancellationToken ct = default);
}
