using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Resolves whether the caller may access a vault — personal or organizational — and, for
/// personal vaults, enforces strict owner-only access: tenant membership or an Admin role never
/// implies access to another user's vault (see docs/multi-tenancy.md "Admin e vault personali").
/// </summary>
internal static class VaultAccessGuard
{
    /// <summary>
    /// Legacy personal-vault-only guard, kept for callers that never need org-vault awareness
    /// (e.g. <see cref="IVaultService.ListOwnedVaultsAsync"/>). Treats any organization vault
    /// identically to "not found." New call sites that should also support organization vaults
    /// must use <see cref="GetAccessibleVaultAsync"/> instead.
    /// </summary>
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

    /// <summary>
    /// Resolves the caller's access to a vault whether personal or organizational, returning the
    /// effective <see cref="VaultPermission"/>. A personal vault is owner-only (ReadWrite for the
    /// owner, "not found" otherwise); an organization vault requires an active (non-revoked)
    /// <see cref="VaultMembership"/> and yields that membership's permission. Any lack of access is
    /// reported as "not found", never forbidden, so vault existence is not leaked
    /// (see docs/features/sharing-access-control.md).
    /// </summary>
    public static async Task<(Vault Vault, VaultPermission Permission)> GetAccessibleVaultAsync(
        CffVaultManagerDbContext db, Guid vaultId, Guid callerId, CancellationToken ct)
    {
        var vault = await db.Vaults.FirstOrDefaultAsync(v => v.Id == vaultId, ct);
        if (vault is null) throw new KeyNotFoundException("Vault not found.");

        if (!vault.IsOrganizationVault)
        {
            if (vault.OwnerUserId != callerId) throw new KeyNotFoundException("Vault not found.");
            return (vault, VaultPermission.ReadWrite);
        }

        var membership = await db.VaultMemberships.FirstOrDefaultAsync(
            m => m.VaultId == vaultId && m.UserId == callerId && m.RevokedAt == null, ct);
        if (membership is null) throw new KeyNotFoundException("Vault not found.");

        return (vault, membership.Permission);
    }
}
