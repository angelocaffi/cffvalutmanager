using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Organization-vault membership management (see docs/features/sharing-access-control.md). Every
/// wrapped-key value is produced client-side and stored verbatim: this service performs no
/// cryptography and never sees a private key or an unwrapped DEK. Cross-tenant references are
/// rejected as "not found" so tenant membership is never leaked. <see cref="InviteAsync"/> and
/// <see cref="RevokeAsync"/> require the caller to be an active <see cref="VaultPermission.Owner"/>
/// member of the target vault (checked via <see cref="VaultAccessGuard.GetAccessibleVaultAsync"/>) —
/// authority over a vault's membership is entirely vault-scoped, decoupled from the caller's
/// tenant-wide role: a tenant Admin with only <see cref="VaultPermission.ReadWrite"/> on this vault
/// cannot invite/revoke, and a non-Admin who is this vault's Owner can. This mirrors the same
/// Owner-only discipline already used for per-item sharing (<c>ItemMembershipService</c>).
/// </summary>
internal sealed class VaultMembershipService : IVaultMembershipService
{
    private readonly CffVaultManagerDbContext _db;

    public VaultMembershipService(CffVaultManagerDbContext db) => _db = db;

    public async Task<PublicKeyDto> GetPublicKeyAsync(Guid targetUserId, Guid callerId, Guid callerTenantId, CancellationToken ct = default)
    {
        var target = await _db.Users.FirstOrDefaultAsync(u => u.Id == targetUserId, ct);
        if (target is null || target.TenantId != callerTenantId)
        {
            // Do not distinguish "no such user" from "other tenant": that would leak tenant membership.
            throw new KeyNotFoundException("User not found.");
        }

        if (target.PublicKey is null)
        {
            throw new InvalidOperationException("User has not generated a key pair yet.");
        }

        return new PublicKeyDto(target.PublicKey, target.Id);
    }

    public async Task<PublicKeyDto> GetPublicKeyByEmailAsync(string email, Guid callerTenantId, CancellationToken ct = default)
    {
        var target = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (target is null || target.TenantId != callerTenantId)
        {
            throw new KeyNotFoundException("User not found.");
        }

        if (target.PublicKey is null)
        {
            throw new InvalidOperationException("User has not generated a key pair yet.");
        }

        return new PublicKeyDto(target.PublicKey, target.Id);
    }

    public async Task<VaultMembershipDto> InviteAsync(Guid vaultId, Guid callerId, Guid callerTenantId, CreateMembershipRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var (vault, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);
        if (!vault.IsOrganizationVault)
        {
            throw new KeyNotFoundException("Vault not found.");
        }

        if (permission != VaultPermission.Owner)
        {
            throw new InsufficientVaultPermissionException();
        }

        var target = await _db.Users.FirstOrDefaultAsync(u => u.Id == request.UserId, ct);
        if (target is null || target.TenantId != callerTenantId)
        {
            throw new KeyNotFoundException("User not found.");
        }

        if (await _db.VaultMemberships.AnyAsync(m => m.VaultId == vaultId && m.UserId == request.UserId && m.RevokedAt == null, ct))
        {
            throw new InvalidOperationException("This user already has access to this vault.");
        }

        var membership = new VaultMembership(
            Guid.NewGuid(),
            vault.TenantId,
            vaultId,
            request.UserId,
            request.Permission,
            request.WrappedVaultDek,
            request.EphemeralPublicKey,
            invitedByUserId: callerId);

        _db.VaultMemberships.Add(membership);
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), vault.TenantId, callerId, AuditAction.Shared));
        await _db.SaveChangesAsync(ct);

        return ToDto(membership);
    }

    public async Task RevokeAsync(Guid vaultId, Guid callerId, Guid callerTenantId, RevokeMembershipRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var (vault, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);
        if (!vault.IsOrganizationVault)
        {
            throw new KeyNotFoundException("Vault not found.");
        }

        if (permission != VaultPermission.Owner)
        {
            throw new InsufficientVaultPermissionException();
        }

        var activeMemberships = await _db.VaultMemberships
            .Where(m => m.VaultId == vaultId && m.RevokedAt == null)
            .ToListAsync(ct);

        var target = activeMemberships.FirstOrDefault(m => m.UserId == request.RevokedUserId)
            ?? throw new KeyNotFoundException("Membership not found.");

        // The remaining active members after this revoke — must match the rewrapped set exactly.
        var remainingMemberIds = activeMemberships
            .Where(m => m.UserId != request.RevokedUserId)
            .Select(m => m.UserId)
            .ToHashSet();

        var providedMemberIds = request.NewMemberships.Select(n => n.UserId).ToList();
        if (providedMemberIds.Count != remainingMemberIds.Count ||
            !remainingMemberIds.SetEquals(providedMemberIds))
        {
            throw new InvalidOperationException("New memberships must cover exactly the remaining active members.");
        }

        // The vault's current (non-deleted) items — must match the re-encrypted set exactly.
        var currentItems = await _db.VaultItems
            .Where(i => i.VaultId == vaultId && !i.IsDeleted)
            .ToListAsync(ct);

        var currentItemIds = currentItems.Select(i => i.Id).ToHashSet();
        var providedItemIds = request.ReencryptedItems.Select(r => r.ItemId).ToList();
        if (providedItemIds.Count != currentItemIds.Count ||
            !currentItemIds.SetEquals(providedItemIds))
        {
            throw new InvalidOperationException("Re-encrypted items must cover exactly the vault's current items.");
        }

        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        var itemsById = currentItems.ToDictionary(i => i.Id);
        var now = DateTimeOffset.UtcNow;
        foreach (var reencrypted in request.ReencryptedItems)
        {
            var item = itemsById[reencrypted.ItemId];
            item.EncryptedPayload = reencrypted.EncryptedPayload;
            item.UpdatedAt = now;
        }

        var membershipsByUserId = activeMemberships.ToDictionary(m => m.UserId);
        foreach (var newMembership in request.NewMemberships)
        {
            membershipsByUserId[newMembership.UserId].UpdateWrappedDek(newMembership.WrappedVaultDek, newMembership.EphemeralPublicKey);
        }

        target.Revoke();
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), vault.TenantId, callerId, AuditAction.Revoked));

        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public async Task<IReadOnlyList<VaultMembershipDto>> ListMembersAsync(Guid vaultId, Guid callerId, Guid callerTenantId, CancellationToken ct = default)
    {
        // Any active member (Read, ReadWrite, or Owner) may see who else has access; access is verified first.
        await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);

        // Ordered client-side after materializing: EF Core's SQLite provider (used in tests)
        // cannot translate ORDER BY on a DateTimeOffset column — see the same issue/fix in
        // VaultItemService.ListAsync and AuditLogService.ListAsync.
        var memberships = await _db.VaultMemberships
            .Where(m => m.VaultId == vaultId && m.RevokedAt == null)
            .Select(m => new VaultMembershipDto(m.Id, m.VaultId, m.UserId, m.Permission, m.CreatedAt))
            .ToListAsync(ct);

        return memberships.OrderBy(m => m.CreatedAt).ToList();
    }

    public async Task<MyVaultMembershipDto> GetMyMembershipAsync(Guid vaultId, Guid callerId, Guid callerTenantId, CancellationToken ct = default)
    {
        var membership = await _db.VaultMemberships.FirstOrDefaultAsync(
            m => m.VaultId == vaultId && m.UserId == callerId && m.RevokedAt == null, ct)
            ?? throw new KeyNotFoundException("Vault not found.");

        return new MyVaultMembershipDto(membership.Id, membership.VaultId, membership.Permission, membership.WrappedVaultDek, membership.EphemeralPublicKey, membership.CreatedAt);
    }

    private static VaultMembershipDto ToDto(VaultMembership m) =>
        new(m.Id, m.VaultId, m.UserId, m.Permission, m.CreatedAt);
}
