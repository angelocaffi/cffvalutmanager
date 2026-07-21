using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Lists the personal vaults owned by the caller. Only the caller's own personal vaults are
/// returned; organization vaults are never surfaced here (a separate authorization model applies).
/// </summary>
public interface IVaultService
{
    Task<IReadOnlyList<VaultDto>> ListOwnedVaultsAsync(Guid callerId, CancellationToken ct = default);

    /// <summary>
    /// Lists the organization vaults the caller has an active (non-revoked) membership in. Personal
    /// vaults are never returned here (see docs/features/sharing-access-control.md).
    /// </summary>
    Task<IReadOnlyList<VaultDto>> ListAccessibleOrgVaultsAsync(Guid callerId, CancellationToken ct = default);

    /// <summary>
    /// Creates a new organization vault in the caller's tenant and immediately grants the caller
    /// (its creator) <see cref="Domain.Enums.VaultPermission.ReadWrite"/> membership, storing the
    /// client-provided wrapped DEK exactly like any other member (see
    /// docs/features/sharing-access-control.md — the creator is not a special case).
    /// </summary>
    Task<VaultDto> CreateOrganizationVaultAsync(
        Guid callerId, Guid callerTenantId, CreateOrganizationVaultRequest request, CancellationToken ct = default);
}
