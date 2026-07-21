namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Ambient, request-scoped identity of the caller used to drive the EF Core
/// global query filters. State can only be populated through <see cref="SetTenant"/>
/// or <see cref="SetSuperAdmin"/> so that an incoherent combination
/// (e.g. <see cref="IsSuperAdmin"/> together with a non-null <see cref="TenantId"/>)
/// is unrepresentable.
/// </summary>
public interface ITenantContext
{
    Guid? TenantId { get; }

    bool IsSuperAdmin { get; }

    Guid? UserId { get; }

    /// <summary>
    /// True once <see cref="SetTenant"/> or <see cref="SetSuperAdmin"/> has been called.
    /// While false the context is fail-closed: every tenant-scoped query filter matches no rows.
    /// </summary>
    bool IsResolved { get; }

    void SetTenant(Guid tenantId, Guid userId);

    void SetSuperAdmin(Guid userId);
}
