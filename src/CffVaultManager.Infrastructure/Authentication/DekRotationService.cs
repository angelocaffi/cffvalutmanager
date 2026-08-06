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
    private readonly ISecurityNotificationService? _securityNotifications;

    // securityNotifications is optional so DI resolves it to the real service in production; tests
    // that don't care about it can omit it, same convenience-default pattern as
    // ChangeMasterPasswordService/ProvisionTenantService's own optional dependencies.
    public DekRotationService(CffVaultManagerDbContext db, ISecurityNotificationService? securityNotifications = null)
    {
        _db = db;
        _securityNotifications = securityNotifications;
    }

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

        // A recovery kit (see docs/security-model.md#recovery-kit) wraps the DEK directly — a new
        // DEK means the old kit silently stops working. The Recovery Key is never persisted
        // client-side after first display, so it can't be used to re-wrap here; the kit must be
        // invalidated instead. RecoveryKitGeneratedAt is deliberately left untouched (not cleared
        // like RecoveryEncryptedDek/RecoveryKeyHash) so /security can show "invalidated, regenerate"
        // rather than "never had one" — see User.RecoveryKitGeneratedAt's own doc comment.
        bool kitExisted = user.RecoveryEncryptedDek is not null;
        if (kitExisted)
        {
            user.RecoveryEncryptedDek = null;
            user.RecoveryKeyHash = null;
            _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.RecoveryKitInvalidated));
        }

        // Same reasoning as the recovery kit above: a passkey's wrapped DEK copy (see
        // WebAuthnCredential.PrfWrappedDek) is tied to the DEK that just got replaced, and the PRF
        // output that produced it isn't re-derivable server-side — only a fresh ceremony on that
        // exact device could re-wrap it, which can't happen here. Clear every copy, not just one.
        var passwordlessCredentials = await _db.WebAuthnCredentials
            .Where(c => c.UserId == userId && c.PrfWrappedDek != null)
            .ToListAsync(ct);
        bool hadPasswordlessCredentials = passwordlessCredentials.Count > 0;
        foreach (var credential in passwordlessCredentials)
        {
            credential.PrfWrappedDek = null;
        }

        if (hadPasswordlessCredentials)
        {
            _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.PasskeyLoginInvalidatedByRotation));
        }

        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        if (kitExisted && _securityNotifications is not null)
        {
            await _securityNotifications.NotifyRecoveryKitInvalidatedAsync(user.Id, ct);
        }

        if (hadPasswordlessCredentials && _securityNotifications is not null)
        {
            await _securityNotifications.NotifyPasskeyLoginInvalidatedAsync(user.Id, ct);
        }
    }
}
