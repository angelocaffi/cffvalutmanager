using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Vault-item management (including the soft-delete trash lifecycle) scoped to a caller-owned
/// personal vault. Ownership is enforced through <see cref="VaultAccessGuard"/>; the encrypted
/// payload is stored and returned verbatim and is never decrypted server-side.
/// </summary>
internal sealed class VaultItemService : IVaultItemService
{
    private readonly CffVaultManagerDbContext _db;

    public VaultItemService(CffVaultManagerDbContext db) => _db = db;

    public async Task<VaultItemDto> CreateAsync(Guid vaultId, Guid callerId, CreateVaultItemRequest request, CancellationToken ct = default)
    {
        var vault = await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        if (request.FolderId is not null &&
            !await _db.Folders.AnyAsync(f => f.Id == request.FolderId && f.VaultId == vaultId, ct))
        {
            throw new KeyNotFoundException("Folder not found.");
        }

        var item = new VaultItem(
            Guid.NewGuid(), vault.TenantId, vaultId, request.Type, request.EncryptedPayload, request.FolderId, request.IsFavorite);
        _db.VaultItems.Add(item);
        WriteAudit(vault.TenantId, callerId, AuditAction.Created, item.Id);
        await _db.SaveChangesAsync(ct);

        return ToDto(item, Array.Empty<Guid>());
    }

    public async Task<VaultItemDto> GetAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default)
    {
        var vault = await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var item = await _db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId && i.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Item not found.");

        item.LastAccessedAt = DateTimeOffset.UtcNow;
        WriteAudit(vault.TenantId, callerId, AuditAction.Viewed, item.Id);
        await _db.SaveChangesAsync(ct);

        var tagIds = await _db.VaultItemTags.Where(t => t.VaultItemId == itemId).Select(t => t.TagId).ToListAsync(ct);
        return ToDto(item, tagIds);
    }

    public async Task<IReadOnlyList<VaultItemDto>> ListAsync(Guid vaultId, Guid callerId, VaultItemListQuery query, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        IQueryable<VaultItem> q = _db.VaultItems.Where(i => i.VaultId == vaultId && !i.IsDeleted);

        if (query.FolderId is not null)
        {
            q = q.Where(i => i.FolderId == query.FolderId);
        }

        if (query.TagId is not null)
        {
            q = q.Where(i => i.VaultItemTags.Any(t => t.TagId == query.TagId.Value));
        }

        if (query.Type is not null)
        {
            q = q.Where(i => i.Type == query.Type);
        }

        if (query.Favorite is not null)
        {
            q = q.Where(i => i.IsFavorite == query.Favorite);
        }

        // Sorted client-side: SQL Server can order DateTimeOffset columns fine, but ordering
        // in-memory keeps this portable across providers and personal vaults are small enough
        // that this is not a performance concern.
        var items = await q.Select(i => new VaultItemDto(
            i.Id, i.Type, i.EncryptedPayload, i.FolderId, i.IsFavorite,
            i.VaultItemTags.Select(t => t.TagId).ToList(),
            i.CreatedAt, i.UpdatedAt, i.LastAccessedAt, i.IsDeleted, i.DeletedAt))
            .ToListAsync(ct);

        IEnumerable<VaultItemDto> ordered = (query.SortBy, query.Direction) switch
        {
            (VaultItemSortBy.CreatedAt, SortDirection.Ascending) => items.OrderBy(i => i.CreatedAt),
            (VaultItemSortBy.CreatedAt, SortDirection.Descending) => items.OrderByDescending(i => i.CreatedAt),
            (VaultItemSortBy.LastAccessedAt, SortDirection.Ascending) => items.OrderBy(i => i.LastAccessedAt),
            (VaultItemSortBy.LastAccessedAt, SortDirection.Descending) => items.OrderByDescending(i => i.LastAccessedAt),
            (VaultItemSortBy.UpdatedAt, SortDirection.Ascending) => items.OrderBy(i => i.UpdatedAt),
            _ => items.OrderByDescending(i => i.UpdatedAt),
        };

        return ordered.ToList();
    }

    public async Task<IReadOnlyList<VaultItemDto>> ListTrashAsync(Guid vaultId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var items = await _db.VaultItems
            .Where(i => i.VaultId == vaultId && i.IsDeleted)
            .Select(i => new VaultItemDto(
                i.Id, i.Type, i.EncryptedPayload, i.FolderId, i.IsFavorite,
                i.VaultItemTags.Select(t => t.TagId).ToList(),
                i.CreatedAt, i.UpdatedAt, i.LastAccessedAt, i.IsDeleted, i.DeletedAt))
            .ToListAsync(ct);

        return items.OrderByDescending(i => i.DeletedAt).ToList();
    }

    public async Task<VaultItemDto> UpdateAsync(Guid vaultId, Guid itemId, Guid callerId, UpdateVaultItemRequest request, CancellationToken ct = default)
    {
        var vault = await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var item = await _db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId && i.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Item not found.");

        if (item.IsDeleted)
        {
            throw new InvalidOperationException("Cannot update a deleted item; restore it first.");
        }

        if (request.FolderId is not null && request.FolderId != item.FolderId &&
            !await _db.Folders.AnyAsync(f => f.Id == request.FolderId && f.VaultId == vaultId, ct))
        {
            throw new KeyNotFoundException("Folder not found.");
        }

        item.Type = request.Type;
        item.EncryptedPayload = request.EncryptedPayload;
        item.FolderId = request.FolderId;
        item.IsFavorite = request.IsFavorite;
        item.UpdatedAt = DateTimeOffset.UtcNow;
        WriteAudit(vault.TenantId, callerId, AuditAction.Updated, item.Id);
        await _db.SaveChangesAsync(ct);

        var tagIds = await _db.VaultItemTags.Where(t => t.VaultItemId == itemId).Select(t => t.TagId).ToListAsync(ct);
        return ToDto(item, tagIds);
    }

    public async Task SoftDeleteAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default)
    {
        var vault = await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var item = await _db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId && i.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Item not found.");

        item.SoftDelete();
        WriteAudit(vault.TenantId, callerId, AuditAction.Deleted, item.Id);
        await _db.SaveChangesAsync(ct);
    }

    public async Task RestoreAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var item = await _db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId && i.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Item not found.");

        item.Restore();
        await _db.SaveChangesAsync(ct);
    }

    public async Task PermanentlyDeleteAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var item = await _db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId && i.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Item not found.");

        if (!item.IsDeleted)
        {
            throw new InvalidOperationException("Item must be moved to trash before permanent deletion.");
        }

        _db.VaultItems.Remove(item);
        await _db.SaveChangesAsync(ct);
    }

    public async Task AssignTagAsync(Guid vaultId, Guid itemId, Guid tagId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        if (!await _db.VaultItems.AnyAsync(i => i.Id == itemId && i.VaultId == vaultId, ct))
        {
            throw new KeyNotFoundException("Item not found.");
        }

        if (!await _db.Tags.AnyAsync(t => t.Id == tagId && t.VaultId == vaultId, ct))
        {
            throw new KeyNotFoundException("Tag not found.");
        }

        if (!await _db.VaultItemTags.AnyAsync(t => t.VaultItemId == itemId && t.TagId == tagId, ct))
        {
            _db.VaultItemTags.Add(new VaultItemTag(itemId, tagId));
            await _db.SaveChangesAsync(ct);
        }
    }

    public async Task RemoveTagAsync(Guid vaultId, Guid itemId, Guid tagId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        if (!await _db.VaultItems.AnyAsync(i => i.Id == itemId && i.VaultId == vaultId, ct))
        {
            throw new KeyNotFoundException("Item not found.");
        }

        var link = await _db.VaultItemTags.FirstOrDefaultAsync(t => t.VaultItemId == itemId && t.TagId == tagId, ct);
        if (link is not null)
        {
            _db.VaultItemTags.Remove(link);
            await _db.SaveChangesAsync(ct);
        }
    }

    public async Task RecordRevealAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default)
    {
        var vault = await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        if (!await _db.VaultItems.AnyAsync(i => i.Id == itemId && i.VaultId == vaultId, ct))
        {
            throw new KeyNotFoundException("Item not found.");
        }

        WriteAudit(vault.TenantId, callerId, AuditAction.Revealed, itemId);
        await _db.SaveChangesAsync(ct);
    }

    private void WriteAudit(Guid tenantId, Guid callerId, AuditAction action, Guid vaultItemId) =>
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), tenantId, callerId, action, vaultItemId));

    private static VaultItemDto ToDto(VaultItem item, IReadOnlyList<Guid> tagIds) => new(
        item.Id, item.Type, item.EncryptedPayload, item.FolderId, item.IsFavorite, tagIds,
        item.CreatedAt, item.UpdatedAt, item.LastAccessedAt, item.IsDeleted, item.DeletedAt);
}
