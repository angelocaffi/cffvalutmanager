using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.VaultCore;

/// <summary>A member's access to a shared item. Carries no wrapped-key material — only metadata.</summary>
public sealed record ItemMembershipDto(Guid Id, Guid VaultItemId, Guid UserId, ItemSharePermission Permission, DateTimeOffset CreatedAt);

/// <summary>
/// The first share of an item: promotes it from vault-DEK encryption to a dedicated per-item key.
/// Everything is computed client-side — a fresh item key, the payload re-encrypted with it, that
/// key wrapped both for the caller (who needs their own wrap from this point on) and for the
/// recipient (looked up by email, must be same-tenant and have a keypair).
/// </summary>
public sealed record ShareItemRequest(
    string RecipientEmail,
    ItemSharePermission RecipientPermission,
    byte[] ReencryptedPayload,
    byte[] OwnerWrappedItemKey,
    byte[] OwnerEphemeralPublicKey,
    byte[] RecipientWrappedItemKey,
    byte[] RecipientEphemeralPublicKey);

/// <summary>Adds another member to an already-shared item — the item key itself doesn't change, only owner-only.</summary>
public sealed record AddItemMemberRequest(string RecipientEmail, ItemSharePermission Permission, byte[] WrappedItemKey, byte[] EphemeralPublicKey);

/// <summary>The rewrapped item key for a remaining member after a revoke-triggered rotation. Opaque to the server.</summary>
public sealed record NewItemMembership(Guid UserId, byte[] WrappedItemKey, byte[] EphemeralPublicKey);

/// <summary>
/// Revokes a member and rotates the item key in one operation: <see cref="NewMemberships"/> must
/// cover exactly the remaining active members (owner included) — see
/// docs/features/sharing-access-control.md.
/// </summary>
public sealed record RevokeItemMemberRequest(Guid RevokedUserId, byte[] ReencryptedPayload, IReadOnlyList<NewItemMembership> NewMemberships);

/// <summary>
/// A shared item as seen through the recipient's own membership — enough to decrypt without ever
/// knowing which vault it lives in.
/// </summary>
public sealed record SharedItemDto(
    Guid Id,
    VaultItemType Type,
    byte[] EncryptedPayload,
    ItemSharePermission MyPermission,
    byte[] MyWrappedItemKey,
    byte[] MyEphemeralPublicKey,
    Guid SharedByUserId,
    DateTimeOffset CreatedAt);

public sealed record UpdateSharedItemRequest(byte[] EncryptedPayload);
