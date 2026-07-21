using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Lists the personal vaults owned by the caller. Organization vaults are never returned.
/// </summary>
internal sealed class VaultService : IVaultService
{
    private readonly CffVaultManagerDbContext _db;

    public VaultService(CffVaultManagerDbContext db) => _db = db;

    public async Task<IReadOnlyList<VaultDto>> ListOwnedVaultsAsync(Guid callerId, CancellationToken ct = default)
    {
        return await _db.Vaults
            .Where(v => !v.IsOrganizationVault && v.OwnerUserId == callerId)
            .OrderBy(v => v.Name)
            .Select(v => new VaultDto(v.Id, v.Name, v.IsOrganizationVault))
            .ToListAsync(ct);
    }
}
