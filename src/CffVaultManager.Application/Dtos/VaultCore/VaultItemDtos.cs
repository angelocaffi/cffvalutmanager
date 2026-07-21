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
    DateTimeOffset? DeletedAt);

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
