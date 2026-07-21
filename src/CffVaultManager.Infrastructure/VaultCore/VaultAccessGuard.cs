using CffVaultManager.Domain.Entities;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Loads a personal vault and enforces strict owner-only access — tenant membership or an Admin
/// role never implies access to another user's vault (see docs/multi-tenancy.md "Admin e vault
/// personali"). An organization vault is treated identically to "not found": org-vault access
/// control is a separate, not-yet-implemented authorization model.
/// </summary>
internal static class VaultAccessGuard
{
    public static async Task<Vault> GetOwnedPersonalVaultAsync(
        CffVaultManagerDbContext db, Guid vaultId, Guid callerId, CancellationToken ct)
    {
        var vault = await db.Vaults.FirstOrDefaultAsync(v => v.Id == vaultId, ct);
        if (vault is null || vault.IsOrganizationVault || vault.OwnerUserId != callerId)
        {
            throw new KeyNotFoundException("Vault not found.");
        }

        return vault;
    }
}
