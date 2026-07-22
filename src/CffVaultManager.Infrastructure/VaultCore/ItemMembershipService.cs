using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Live sharing of a single vault item (see docs/features/sharing-access-control.md "Condivisione
/// live di singola voce"). Every wrapped-key value is produced client-side and stored verbatim: this
/// service performs no cryptography and never sees a private key or an unwrapped item key.
/// </summary>
internal sealed class ItemMembershipService : IItemMembershipService
{
    private readonly CffVaultManagerDbContext _db;

    public ItemMembershipService(CffVaultManagerDbContext db) => _db = db;

    public async Task<ItemMembershipDto> ShareAsync(
        Guid vaultId, Guid itemId, Guid callerId, Guid callerTenantId, ShareItemRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var (vault, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);
        if (!permission.CanWrite())
        {
            throw new InsufficientVaultPermissionException();
        }

        var item = await _db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId && i.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Item not found.");

        if (item.IsDeleted)
        {
            throw new InvalidOperationException("Cannot share a deleted item; restore it first.");
        }

        if (await _db.ItemMemberships.AnyAsync(m => m.VaultItemId == itemId && m.RevokedAt == null, ct))
        {
            throw new InvalidOperationException("This item is already shared.");
        }

        var recipient = await _db.Users.FirstOrDefaultAsync(u => u.Email == request.RecipientEmail, ct);
        if (recipient is null || recipient.TenantId != callerTenantId)
        {
            // Do not distinguish "no such user" from "other tenant": that would leak tenant membership.
            throw new KeyNotFoundException("User not found.");
        }

        if (recipient.Id == callerId)
        {
            throw new InvalidOperationException("Cannot share an item with yourself.");
        }

        if (recipient.PublicKey is null)
        {
            throw new InvalidOperationException("The recipient has not generated a key pair yet.");
        }

        item.EncryptedPayload = request.ReencryptedPayload;
        item.UpdatedAt = DateTimeOffset.UtcNow;

        var ownerMembership = new ItemMembership(
            Guid.NewGuid(), vault.TenantId, itemId, callerId, ItemSharePermission.Owner,
            request.OwnerWrappedItemKey, request.OwnerEphemeralPublicKey, invitedByUserId: callerId);
        var recipientMembership = new ItemMembership(
            Guid.NewGuid(), vault.TenantId, itemId, recipient.Id, request.RecipientPermission,
            request.RecipientWrappedItemKey, request.RecipientEphemeralPublicKey, invitedByUserId: callerId);

        _db.ItemMemberships.Add(ownerMembership);
        _db.ItemMemberships.Add(recipientMembership);
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), vault.TenantId, callerId, AuditAction.ItemMembershipGranted, itemId));
        await _db.SaveChangesAsync(ct);

        return ToDto(recipientMembership);
    }

    public async Task<ItemMembershipDto> AddMemberAsync(
        Guid itemId, Guid callerId, Guid callerTenantId, AddItemMemberRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var (item, callerMembership) = await ItemAccessGuard.GetSharedItemAsync(_db, itemId, callerId, ct);
        if (callerMembership.Permission != ItemSharePermission.Owner)
        {
            throw new InsufficientVaultPermissionException();
        }

        if (request.Permission == ItemSharePermission.Owner)
        {
            throw new InvalidOperationException("Only one owner can exist per item.");
        }

        var recipient = await _db.Users.FirstOrDefaultAsync(u => u.Email == request.RecipientEmail, ct);
        if (recipient is null || recipient.TenantId != callerTenantId)
        {
            throw new KeyNotFoundException("User not found.");
        }

        if (recipient.PublicKey is null)
        {
            throw new InvalidOperationException("The recipient has not generated a key pair yet.");
        }

        if (await _db.ItemMemberships.AnyAsync(m => m.VaultItemId == itemId && m.UserId == recipient.Id && m.RevokedAt == null, ct))
        {
            throw new InvalidOperationException("This user already has access to this item.");
        }

        var membership = new ItemMembership(
            Guid.NewGuid(), item.TenantId, itemId, recipient.Id, request.Permission,
            request.WrappedItemKey, request.EphemeralPublicKey, invitedByUserId: callerId);

        _db.ItemMemberships.Add(membership);
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), item.TenantId, callerId, AuditAction.ItemMembershipGranted, itemId));
        await _db.SaveChangesAsync(ct);

        return ToDto(membership);
    }

    public async Task RevokeAsync(Guid itemId, Guid callerId, RevokeItemMemberRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var (item, callerMembership) = await ItemAccessGuard.GetSharedItemAsync(_db, itemId, callerId, ct);
        if (callerMembership.Permission != ItemSharePermission.Owner)
        {
            throw new InsufficientVaultPermissionException();
        }

        if (request.RevokedUserId == callerId)
        {
            throw new InvalidOperationException("The owner cannot revoke their own access.");
        }

        var activeMemberships = await _db.ItemMemberships
            .Where(m => m.VaultItemId == itemId && m.RevokedAt == null)
            .ToListAsync(ct);

        var target = activeMemberships.FirstOrDefault(m => m.UserId == request.RevokedUserId)
            ?? throw new KeyNotFoundException("Membership not found.");

        var remainingMemberIds = activeMemberships
            .Where(m => m.UserId != request.RevokedUserId)
            .Select(m => m.UserId)
            .ToHashSet();

        var providedMemberIds = request.NewMemberships.Select(n => n.UserId).ToList();
        if (providedMemberIds.Count != remainingMemberIds.Count || !remainingMemberIds.SetEquals(providedMemberIds))
        {
            throw new InvalidOperationException("New memberships must cover exactly the remaining active members.");
        }

        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        item.EncryptedPayload = request.ReencryptedPayload;
        item.UpdatedAt = DateTimeOffset.UtcNow;

        var membershipsByUserId = activeMemberships.ToDictionary(m => m.UserId);
        foreach (var newMembership in request.NewMemberships)
        {
            membershipsByUserId[newMembership.UserId].UpdateWrappedItemKey(newMembership.WrappedItemKey, newMembership.EphemeralPublicKey);
        }

        target.Revoke();
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), item.TenantId, callerId, AuditAction.ItemMembershipRevoked, itemId));

        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public async Task<IReadOnlyList<ItemMembershipDto>> ListMembersAsync(Guid itemId, Guid callerId, CancellationToken ct = default)
    {
        await ItemAccessGuard.GetSharedItemAsync(_db, itemId, callerId, ct);

        // Ordered client-side after materializing: EF Core's SQLite provider (used in tests)
        // cannot translate ORDER BY on a DateTimeOffset column — see the same issue/fix in
        // VaultMembershipService.ListMembersAsync.
        var memberships = await _db.ItemMemberships
            .Where(m => m.VaultItemId == itemId && m.RevokedAt == null)
            .Select(m => new ItemMembershipDto(m.Id, m.VaultItemId, m.UserId, m.Permission, m.CreatedAt))
            .ToListAsync(ct);

        return memberships.OrderBy(m => m.CreatedAt).ToList();
    }

    public async Task<IReadOnlyList<SharedItemDto>> GetSharedWithMeAsync(Guid callerId, CancellationToken ct = default)
    {
        // Owner rows are excluded: those items already appear in the caller's own vault listing —
        // this feed is only for access granted by someone else.
        var memberships = await _db.ItemMemberships
            .Where(m => m.UserId == callerId && m.RevokedAt == null && m.Permission != ItemSharePermission.Owner)
            .Select(m => new { m.VaultItemId, m.Permission, m.WrappedItemKey, m.EphemeralPublicKey, m.InvitedByUserId, m.CreatedAt })
            .ToListAsync(ct);

        if (memberships.Count == 0)
        {
            return [];
        }

        var itemIds = memberships.Select(m => m.VaultItemId).ToList();
        var items = await _db.VaultItems.Where(i => itemIds.Contains(i.Id)).ToDictionaryAsync(i => i.Id, ct);

        var result = new List<SharedItemDto>();
        foreach (var m in memberships)
        {
            if (items.TryGetValue(m.VaultItemId, out var item))
            {
                result.Add(new SharedItemDto(
                    item.Id, item.Type, item.EncryptedPayload, m.Permission, m.WrappedItemKey, m.EphemeralPublicKey, m.InvitedByUserId, m.CreatedAt));
            }
        }

        return result.OrderByDescending(s => s.CreatedAt).ToList();
    }

    public async Task<SharedItemDto> GetSharedItemAsync(Guid itemId, Guid callerId, CancellationToken ct = default)
    {
        var (item, membership) = await ItemAccessGuard.GetSharedItemAsync(_db, itemId, callerId, ct);
        return new SharedItemDto(
            item.Id, item.Type, item.EncryptedPayload, membership.Permission, membership.WrappedItemKey, membership.EphemeralPublicKey,
            membership.InvitedByUserId, membership.CreatedAt);
    }

    public async Task UpdateSharedItemAsync(Guid itemId, Guid callerId, UpdateSharedItemRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var (item, membership) = await ItemAccessGuard.GetSharedItemAsync(_db, itemId, callerId, ct);
        if (membership.Permission == ItemSharePermission.Viewer)
        {
            throw new InsufficientVaultPermissionException();
        }

        item.EncryptedPayload = request.EncryptedPayload;
        item.UpdatedAt = DateTimeOffset.UtcNow;
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), item.TenantId, callerId, AuditAction.Updated, itemId));
        await _db.SaveChangesAsync(ct);
    }

    private static ItemMembershipDto ToDto(ItemMembership m) => new(m.Id, m.VaultItemId, m.UserId, m.Permission, m.CreatedAt);
}
