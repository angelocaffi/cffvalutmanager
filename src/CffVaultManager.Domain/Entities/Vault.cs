namespace CffVaultManager.Domain.Entities;

/// <summary>
/// A logical container of secrets: either a user's personal vault or a
/// shared organization vault.
/// </summary>
public class Vault
{
    private Vault()
    {
        // Parameterless constructor for EF Core / serialization.
        Name = null!;
    }

    public Vault(
        Guid id,
        Guid tenantId,
        string name,
        bool isOrganizationVault,
        Guid? ownerUserId)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
        Name = Guard.AgainstNullOrWhiteSpace(name);
        IsOrganizationVault = isOrganizationVault;

        if (!isOrganizationVault && (ownerUserId is null || ownerUserId == Guid.Empty))
        {
            throw new ArgumentException("A personal vault must have an owner.", nameof(ownerUserId));
        }

        OwnerUserId = ownerUserId;
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Tenant? Tenant { get; set; }

    public Guid? OwnerUserId { get; set; }

    public User? OwnerUser { get; set; }

    public bool IsOrganizationVault { get; private set; }

    public string Name { get; set; }

    public ICollection<VaultItem> Items { get; } = new List<VaultItem>();

    public ICollection<Folder> Folders { get; } = new List<Folder>();

    public ICollection<Tag> Tags { get; } = new List<Tag>();
}
