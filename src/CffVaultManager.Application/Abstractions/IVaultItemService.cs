using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Manages the encrypted items inside a caller-owned personal vault, including the soft-delete
/// trash lifecycle. Access is strictly owner-only: a vault the caller does not own (or an
/// organization vault) — and any folder/tag/item not belonging to it — is reported as not found,
/// never as forbidden. Tag assignment/removal is idempotent. The server never sees item plaintext.
/// </summary>
public interface IVaultItemService
{
    Task<VaultItemDto> CreateAsync(Guid vaultId, Guid callerId, CreateVaultItemRequest request, CancellationToken ct = default);

    Task<VaultItemDto> GetAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default);

    Task<IReadOnlyList<VaultItemDto>> ListAsync(Guid vaultId, Guid callerId, VaultItemListQuery query, CancellationToken ct = default);

    Task<IReadOnlyList<VaultItemDto>> ListTrashAsync(Guid vaultId, Guid callerId, CancellationToken ct = default);

    Task<VaultItemDto> UpdateAsync(Guid vaultId, Guid itemId, Guid callerId, UpdateVaultItemRequest request, CancellationToken ct = default);

    Task SoftDeleteAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default);

    Task RestoreAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default);

    Task PermanentlyDeleteAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default);

    Task AssignTagAsync(Guid vaultId, Guid itemId, Guid tagId, Guid callerId, CancellationToken ct = default);

    Task RemoveTagAsync(Guid vaultId, Guid itemId, Guid tagId, Guid callerId, CancellationToken ct = default);
}
