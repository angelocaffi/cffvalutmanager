namespace CffVaultManager.Domain.Entities;

/// <summary>
/// Explicit join entity linking a <see cref="VaultItem"/> to a <see cref="Tag"/>.
/// </summary>
public class VaultItemTag
{
    private VaultItemTag()
    {
        // Parameterless constructor for EF Core / serialization.
    }

    public VaultItemTag(Guid vaultItemId, Guid tagId)
    {
        VaultItemId = Guard.AgainstEmptyGuid(vaultItemId);
        TagId = Guard.AgainstEmptyGuid(tagId);
    }

    public Guid VaultItemId { get; private set; }

    public VaultItem? VaultItem { get; set; }

    public Guid TagId { get; private set; }

    public Tag? Tag { get; set; }
}
