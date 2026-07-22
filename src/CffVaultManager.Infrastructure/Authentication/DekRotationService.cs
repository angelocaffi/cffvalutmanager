using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <inheritdoc cref="IDekRotationService"/>
internal sealed class DekRotationService : IDekRotationService
{
    private readonly CffVaultManagerDbContext _db;

    public DekRotationService(CffVaultManagerDbContext db) => _db = db;

    public async Task RotateDekAsync(Guid userId, RotateDekRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.NewEncryptedDek is null || request.NewEncryptedDek.Length == 0)
        {
            throw new ArgumentException("NewEncryptedDek must not be empty.", nameof(request));
        }

        // Runs post-authentication, so the tenant query filter is resolved and correctly scopes
        // this to the caller's own user record (mirrors ChangeMasterPasswordService).
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        // Only the caller's own personal vaults: an organization vault's items use that vault's
        // own DEK (see VaultMembership), never the personal one, so they're never in scope here.
        var ownedVaultIds = await _db.Vaults
            .Where(v => !v.IsOrganizationVault && v.OwnerUserId == userId)
            .Select(v => v.Id)
            .ToListAsync(ct);

        var currentItems = await _db.VaultItems
            .Where(i => ownedVaultIds.Contains(i.VaultId) && !i.IsDeleted)
            .ToListAsync(ct);
        var currentItemIds = currentItems.Select(i => i.Id).ToList();

        // An already-shared item is encrypted with its own dedicated key (see ItemMembership),
        // not the personal DEK — rotating the personal DEK doesn't touch it.
        var sharedItemIds = await _db.ItemMemberships
            .Where(m => currentItemIds.Contains(m.VaultItemId) && m.RevokedAt == null)
            .Select(m => m.VaultItemId)
            .ToListAsync(ct);
        var sharedItemIdSet = sharedItemIds.ToHashSet();

        var rotatableItems = currentItems.Where(i => !sharedItemIdSet.Contains(i.Id)).ToList();
        var requiredItemIds = rotatableItems.Select(i => i.Id).ToHashSet();

        var providedItemIds = request.ReencryptedItems.Select(r => r.ItemId).ToList();
        if (providedItemIds.Count != requiredItemIds.Count || !requiredItemIds.SetEquals(providedItemIds))
        {
            throw new InvalidOperationException("Re-encrypted items must cover exactly the caller's current, non-shared personal-vault items.");
        }

        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        var itemsById = rotatableItems.ToDictionary(i => i.Id);
        var now = DateTimeOffset.UtcNow;
        foreach (var reencrypted in request.ReencryptedItems)
        {
            var item = itemsById[reencrypted.ItemId];
            item.EncryptedPayload = reencrypted.EncryptedPayload;
            item.UpdatedAt = now;
        }

        user.EncryptedDek = request.NewEncryptedDek;
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.DekRotated));

        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }
}
