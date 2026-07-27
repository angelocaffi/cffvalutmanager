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
        DateTimeOffset? createdAt = null,
        DateTimeOffset? trialEndsAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        Name = Guard.AgainstNullOrWhiteSpace(name);
        Slug = Guard.AgainstNullOrWhiteSpace(slug);
        Status = status;
        PlanName = planName;
        MaxUsers = maxUsers;
        MaxStorageBytes = maxStorageBytes;
        var created = createdAt ?? DateTimeOffset.UtcNow;
        CreatedAt = created;
        // 30-day free trial from provisioning — see docs/features/billing.md. Explicit override
        // exists only for the existing-tenant migration backfill (CreatedAt + 30 days computed
        // there instead of "now" + 30 days).
        TrialEndsAt = trialEndsAt ?? created.AddDays(30);
    }

    public Guid Id { get; private set; }

    public string Name { get; set; }

    public string Slug { get; set; }

    public TenantStatus Status { get; set; }

    public string? PlanName { get; set; }

    public int? MaxUsers { get; set; }

    public long? MaxStorageBytes { get; set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset TrialEndsAt { get; private set; }

    /// <summary>Null until the first PayPal payment is ever captured (see docs/features/billing.md).</summary>
    public DateTimeOffset? PlanExpiresAt { get; private set; }

    public ICollection<User> Users { get; } = new List<User>();

    public ICollection<Vault> Vaults { get; } = new List<Vault>();

    public ICollection<AuditLogEntry> AuditLogEntries { get; } = new List<AuditLogEntry>();

    /// <summary>
    /// True once the trial has ended and there is no active (or no) paid plan. SuperAdmin callers
    /// never reach this check (they have no TenantId) — see the JWT-claim enforcement design.
    /// </summary>
    public bool IsReadOnly(DateTimeOffset now) => now > TrialEndsAt && (PlanExpiresAt is null || now > PlanExpiresAt);

    /// <summary>
    /// Extends the plan by <paramref name="duration"/> from whichever is later: the current
    /// expiry (if still in the future) or <paramref name="now"/>. Paying early adds to the
    /// remaining time instead of discarding it.
    /// </summary>
    public void ExtendPlan(DateTimeOffset now, TimeSpan duration) =>
        PlanExpiresAt = (PlanExpiresAt is { } current && current > now ? current : now).Add(duration);
}
