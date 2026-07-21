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

    /// <summary>
    /// Suspends a tenant: its users can no longer log in or refresh an existing session (see
    /// <see cref="IAuthenticationService"/>), but no data is touched. Throws
    /// <see cref="KeyNotFoundException"/> if the tenant does not exist.
    /// </summary>
    Task SuspendTenantAsync(Guid tenantId, Guid callerId, CancellationToken ct = default);

    /// <summary>Reverses <see cref="SuspendTenantAsync"/>. Throws <see cref="KeyNotFoundException"/> if the tenant does not exist.</summary>
    Task ReactivateTenantAsync(Guid tenantId, Guid callerId, CancellationToken ct = default);
}
