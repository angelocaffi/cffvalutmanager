using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.VaultCore;

/// <summary>
/// A vault item as returned to the client. <see cref="EncryptedPayload"/> is opaque ciphertext:
/// the server never sees the plaintext (see docs/security-model.md).
/// </summary>
public sealed record VaultItemDto(
    Guid Id,
    VaultItemType Type,
    byte[] EncryptedPayload,
    Guid? FolderId,
    bool IsFavorite,
    IReadOnlyList<Guid> TagIds,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? LastAccessedAt,
    bool IsDeleted,
    DateTimeOffset? DeletedAt,
    /// <summary>
    /// Non-null only once this item has been shared (see docs/features/sharing-access-control.md
    /// "Condivisione live di singola voce"): from that point on the item is encrypted with a
    /// dedicated per-item key, not the vault's DEK, so the caller — including the item's own
    /// owner — must unwrap this to know which key to decrypt/encrypt with.
    /// </summary>
    SharedAccessDto? MySharedAccess = null);

/// <summary>The caller's own wrap of a shared item's dedicated key. Opaque to the server.</summary>
public sealed record SharedAccessDto(ItemSharePermission Permission, byte[] WrappedItemKey, byte[] EphemeralPublicKey);

public sealed record CreateVaultItemRequest(
    VaultItemType Type,
    byte[] EncryptedPayload,
    Guid? FolderId = null,
    bool IsFavorite = false);

public sealed record UpdateVaultItemRequest(
    VaultItemType Type,
    byte[] EncryptedPayload,
    Guid? FolderId,
    bool IsFavorite);

/// <summary>
/// Moves an item to a different vault. <see cref="EncryptedPayload"/> is the item re-encrypted for
/// the destination (client-side): unchanged if the item is already promoted to a dedicated per-item
/// key (see <see cref="VaultItemDto.MySharedAccess"/>), otherwise re-wrapped with the destination
/// vault's DEK. The server stores it verbatim either way.
/// </summary>
public sealed record MoveVaultItemRequest(Guid DestinationVaultId, byte[] EncryptedPayload);

public enum VaultItemSortBy
{
    CreatedAt,
    UpdatedAt,
    LastAccessedAt,
}

public enum SortDirection
{
    Ascending,
    Descending,
}

/// <summary>
/// Server-side filter/sort criteria for listing vault items. Content search is client-side only
/// (see docs/data-model.md); the server only offers metadata filtering and sorting.
/// </summary>
public sealed record VaultItemListQuery(
    Guid? FolderId = null,
    Guid? TagId = null,
    VaultItemType? Type = null,
    bool? Favorite = null,
    VaultItemSortBy SortBy = VaultItemSortBy.UpdatedAt,
    SortDirection Direction = SortDirection.Descending);
