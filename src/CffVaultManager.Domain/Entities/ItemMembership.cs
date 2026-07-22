using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// Grants a user access to a single shared <see cref="VaultItem"/> — independent of whatever vault
/// the item lives in (see docs/features/sharing-access-control.md "Condivisione live di singola
/// voce"). Mirrors <see cref="VaultMembership"/>'s ECIES-style X25519 wrapping exactly, just scoped
/// to a per-item key instead of a vault DEK: the first share "promotes" the item from being
/// encrypted with its vault's DEK to a dedicated item key, wrapped independently for every member —
/// including the original owner, who gets their own row here too. <see cref="WrappedItemKey"/> and
/// <see cref="EphemeralPublicKey"/> are opaque to the server. A revoked membership keeps its row for
/// audit but sets <see cref="RevokedAt"/>; access is granted only while that is null.
/// </summary>
public class ItemMembership
{
    private ItemMembership()
    {
        // Parameterless constructor for EF Core / serialization.
        WrappedItemKey = null!;
        EphemeralPublicKey = null!;
    }

    public ItemMembership(
        Guid id,
        Guid tenantId,
        Guid vaultItemId,
        Guid userId,
        ItemSharePermission permission,
        byte[] wrappedItemKey,
        byte[] ephemeralPublicKey,
        Guid invitedByUserId,
        DateTimeOffset? createdAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
        VaultItemId = Guard.AgainstEmptyGuid(vaultItemId);
        UserId = Guard.AgainstEmptyGuid(userId);
        Permission = permission;
        WrappedItemKey = Guard.AgainstNullOrEmpty(wrappedItemKey);
        EphemeralPublicKey = Guard.AgainstNullOrEmpty(ephemeralPublicKey);
        InvitedByUserId = Guard.AgainstEmptyGuid(invitedByUserId);
        CreatedAt = createdAt ?? DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Guid VaultItemId { get; private set; }

    public VaultItem? VaultItem { get; set; }

    public Guid UserId { get; private set; }

    public User? User { get; set; }

    public ItemSharePermission Permission { get; private set; }

    /// <summary>The item's dedicated key, wrapped for this member's public key. Opaque to the server.</summary>
    public byte[] WrappedItemKey { get; private set; }

    /// <summary>The sender's ephemeral X25519 public key used for this specific wrapping. Opaque to the server.</summary>
    public byte[] EphemeralPublicKey { get; private set; }

    public Guid InvitedByUserId { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>Marks this membership revoked; the row is retained for audit.</summary>
    public void Revoke() => RevokedAt = DateTimeOffset.UtcNow;

    /// <summary>
    /// Replaces the wrapped item-key material for a remaining member after a key rotation (on
    /// revoke — see docs/features/sharing-access-control.md). The new bytes are computed
    /// client-side; the server only stores them.
    /// </summary>
    public void UpdateWrappedItemKey(byte[] wrappedItemKey, byte[] ephemeralPublicKey)
    {
        WrappedItemKey = Guard.AgainstNullOrEmpty(wrappedItemKey);
        EphemeralPublicKey = Guard.AgainstNullOrEmpty(ephemeralPublicKey);
    }
}
