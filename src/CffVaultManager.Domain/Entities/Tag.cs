namespace CffVaultManager.Domain.Entities;

/// <summary>
/// Organizational tag within a vault. The name is plaintext metadata.
/// </summary>
public class Tag
{
    private Tag()
    {
        // Parameterless constructor for EF Core / serialization.
        Name = null!;
    }

    public Tag(Guid id, Guid tenantId, Guid vaultId, string name)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
        VaultId = Guard.AgainstEmptyGuid(vaultId);
        Name = Guard.AgainstNullOrWhiteSpace(name);
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Guid VaultId { get; private set; }

    public Vault? Vault { get; set; }

    public string Name { get; set; }

    public ICollection<VaultItemTag> VaultItemTags { get; } = new List<VaultItemTag>();
}
