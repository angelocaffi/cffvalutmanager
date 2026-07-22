using CffVaultManager.Domain.Entities;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Resolves whether the caller has an active <see cref="ItemMembership"/> on a specific item —
/// entirely independent of vault-level access (see docs/features/sharing-access-control.md
/// "Condivisione live di singola voce"). Deliberately does not fall back to vault access: a fellow
/// ReadWrite vault member who was never invited to this item's sharing has no special standing
/// here, and a share recipient may not have vault access at all. Any lack of access is reported as
/// "not found", never forbidden, mirroring <see cref="VaultAccessGuard"/>.
/// </summary>
internal static class ItemAccessGuard
{
    public static async Task<(VaultItem Item, ItemMembership Membership)> GetSharedItemAsync(
        CffVaultManagerDbContext db, Guid itemId, Guid callerId, CancellationToken ct)
    {
        var item = await db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId, ct);
        if (item is null)
        {
            throw new KeyNotFoundException("Item not found.");
        }

        var membership = await db.ItemMemberships.FirstOrDefaultAsync(
            m => m.VaultItemId == itemId && m.UserId == callerId && m.RevokedAt == null, ct);
        if (membership is null)
        {
            throw new KeyNotFoundException("Item not found.");
        }

        return (item, membership);
    }
}
