namespace CffVaultManager.Domain.Enums;

/// <summary>
/// Access level on a shared <see cref="Entities.VaultItem"/> (see
/// docs/features/sharing-access-control.md "Condivisione live di singola voce"). Distinct from
/// <see cref="VaultPermission"/>, which governs whole-vault access — an item's own owner is not
/// implicit here the way a personal vault's owner is in <see cref="VaultPermission"/>: once an item
/// is shared, even its original creator holds their access through an explicit
/// <see cref="Entities.ItemMembership"/> row, because the item stops being encrypted with the vault's
/// DEK at that point.
/// </summary>
public enum ItemSharePermission
{
    Viewer,
    Editor,
    Owner,
}
