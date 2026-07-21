using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// An organization (tenant). Root of the tenant-scoped object graph.
/// </summary>
public class Tenant
{
    private Tenant()
    {
        // Parameterless constructor for EF Core / serialization.
        Name = null!;
        Slug = null!;
    }

    public Tenant(
        Guid id,
        string name,
        string slug,
        TenantStatus status = TenantStatus.PendingSetup,
        string? planName = null,
        int? maxUsers = null,
        long? maxStorageBytes = null,
        DateTimeOffset? createdAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        Name = Guard.AgainstNullOrWhiteSpace(name);
        Slug = Guard.AgainstNullOrWhiteSpace(slug);
        Status = status;
        PlanName = planName;
        MaxUsers = maxUsers;
        MaxStorageBytes = maxStorageBytes;
        CreatedAt = createdAt ?? DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }

    public string Name { get; set; }

    public string Slug { get; set; }

    public TenantStatus Status { get; set; }

    public string? PlanName { get; set; }

    public int? MaxUsers { get; set; }

    public long? MaxStorageBytes { get; set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public ICollection<User> Users { get; } = new List<User>();

    public ICollection<Vault> Vaults { get; } = new List<Vault>();

    public ICollection<AuditLogEntry> AuditLogEntries { get; } = new List<AuditLogEntry>();
}
