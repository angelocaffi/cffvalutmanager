using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// A single encrypted secret (password, card, note, generic secret).
/// The plaintext payload is serialized, encrypted, and stored in
/// <see cref="EncryptedPayload"/>. That buffer already contains the nonce as
/// part of the <c>EncryptedBlob</c> format (<c>[version][nonce][ciphertext][tag]</c>),
/// so there is no separate nonce column.
/// </summary>
public class VaultItem
{
    private VaultItem()
    {
        // Parameterless constructor for EF Core / serialization.
        EncryptedPayload = null!;
    }

    public VaultItem(
        Guid id,
        Guid tenantId,
        Guid vaultId,
        VaultItemType type,
        byte[] encryptedPayload,
        Guid? folderId = null,
        bool isFavorite = false,
        DateTimeOffset? createdAt = null,
        DateTimeOffset? updatedAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
        VaultId = Guard.AgainstEmptyGuid(vaultId);
        Type = type;
        EncryptedPayload = Guard.AgainstNullOrEmpty(encryptedPayload);
        FolderId = folderId;
        IsFavorite = isFavorite;
        CreatedAt = createdAt ?? DateTimeOffset.UtcNow;
        UpdatedAt = updatedAt ?? CreatedAt;
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Guid VaultId { get; private set; }

    public Vault? Vault { get; set; }

    public VaultItemType Type { get; set; }

    /// <summary>
    /// The encrypted secret, serialized in the <c>EncryptedBlob</c> format which
    /// already embeds the per-record nonce (<c>[version][nonce][ciphertext][tag]</c>).
    /// </summary>
    public byte[] EncryptedPayload { get; set; }

    public Guid? FolderId { get; set; }

    public Folder? Folder { get; set; }

    public bool IsFavorite { get; set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public DateTimeOffset? LastAccessedAt { get; set; }

    public bool IsDeleted { get; private set; }

    public DateTimeOffset? DeletedAt { get; private set; }

    public ICollection<VaultItemTag> VaultItemTags { get; } = new List<VaultItemTag>();

    /// <summary>
    /// Moves the item to the trash (soft delete). Throws if it is already deleted.
    /// </summary>
    public void SoftDelete(DateTimeOffset? deletedAt = null)
    {
        if (IsDeleted)
        {
            throw new InvalidOperationException("Item is already deleted.");
        }

        IsDeleted = true;
        DeletedAt = deletedAt ?? DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Restores the item from the trash. Throws if it is not currently deleted.
    /// </summary>
    public void Restore()
    {
        if (!IsDeleted)
        {
            throw new InvalidOperationException("Item is not deleted.");
        }

        IsDeleted = false;
        DeletedAt = null;
    }
}
