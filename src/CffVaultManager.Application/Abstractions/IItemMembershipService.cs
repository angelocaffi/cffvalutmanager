using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Live sharing of a single vault item with another user in the same tenant (see
/// docs/features/sharing-access-control.md "Condivisione live di singola voce") — independent of
/// which vault the item lives in. All wrapped-key material arrives precomputed from the client and
/// is stored opaquely: the server never performs any cryptography on it and never sees a private
/// key or an unwrapped item key. A cross-tenant reference is reported as not found, never as
/// forbidden, so tenant membership is not leaked.
/// </summary>
public interface IItemMembershipService
{
    /// <summary>
    /// First share of an item: requires the caller to hold ReadWrite on the item's containing
    /// vault (it isn't shared yet, so there is no <c>ItemMembership</c> to check). Creates the
    /// caller's own Owner membership alongside the recipient's.
    /// </summary>
    Task<ItemMembershipDto> ShareAsync(Guid vaultId, Guid itemId, Guid callerId, Guid callerTenantId, ShareItemRequest request, CancellationToken ct = default);

    /// <summary>Adds another member to an already-shared item. Owner-only.</summary>
    Task<ItemMembershipDto> AddMemberAsync(Guid itemId, Guid callerId, Guid callerTenantId, AddItemMemberRequest request, CancellationToken ct = default);

    /// <summary>Revokes a member and rotates the item key atomically. Owner-only.</summary>
    Task RevokeAsync(Guid itemId, Guid callerId, RevokeItemMemberRequest request, CancellationToken ct = default);

    /// <summary>Lists the active members of a shared item the caller can access.</summary>
    Task<IReadOnlyList<ItemMembershipDto>> ListMembersAsync(Guid itemId, Guid callerId, CancellationToken ct = default);

    /// <summary>Items shared with the caller by someone else (excludes items the caller owns — those already appear in their own vault).</summary>
    Task<IReadOnlyList<SharedItemDto>> GetSharedWithMeAsync(Guid callerId, CancellationToken ct = default);

    /// <summary>A single shared item, resolved purely through the caller's own membership — no vault id needed or exposed.</summary>
    Task<SharedItemDto> GetSharedItemAsync(Guid itemId, Guid callerId, CancellationToken ct = default);

    /// <summary>Updates a shared item's ciphertext in place — same key, no rotation. Editor or Owner only.</summary>
    Task UpdateSharedItemAsync(Guid itemId, Guid callerId, UpdateSharedItemRequest request, CancellationToken ct = default);
}
