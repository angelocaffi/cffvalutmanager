using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Lists the personal vaults owned by the caller. Only the caller's own personal vaults are
/// returned; organization vaults are never surfaced here (a separate authorization model applies).
/// </summary>
public interface IVaultService
{
    Task<IReadOnlyList<VaultDto>> ListOwnedVaultsAsync(Guid callerId, CancellationToken ct = default);
}
