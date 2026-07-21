using CffVaultManager.Application.Dtos.Authentication;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Provisions a new tenant together with its first Admin user in a single transaction.
/// Intended to be called by a platform SuperAdmin.
/// </summary>
public interface IProvisionTenantService
{
    Task<ProvisionTenantResult> ProvisionAsync(ProvisionTenantRequest request, CancellationToken ct = default);
}

/// <summary>Identifiers of the freshly provisioned tenant and its first Admin user.</summary>
public sealed record ProvisionTenantResult(Guid TenantId, Guid AdminUserId);
