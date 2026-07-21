using CffVaultManager.Application.Abstractions;

namespace CffVaultManager.Infrastructure;

/// <inheritdoc cref="ITenantContext"/>
public sealed class TenantContext : ITenantContext
{
    public Guid? TenantId { get; private set; }

    public bool IsSuperAdmin { get; private set; }

    public Guid? UserId { get; private set; }

    public bool IsResolved { get; private set; }

    public void SetTenant(Guid tenantId, Guid userId)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("TenantId must not be empty.", nameof(tenantId));
        }

        if (userId == Guid.Empty)
        {
            throw new ArgumentException("UserId must not be empty.", nameof(userId));
        }

        TenantId = tenantId;
        UserId = userId;
        IsSuperAdmin = false;
        IsResolved = true;
    }

    public void SetSuperAdmin(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("UserId must not be empty.", nameof(userId));
        }

        TenantId = null;
        UserId = userId;
        IsSuperAdmin = true;
        IsResolved = true;
    }
}
