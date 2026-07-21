using CffVaultManager.Application.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace CffVaultManager.Infrastructure.Persistence;

/// <summary>
/// Design-time factory used by the EF Core tools (migrations). It builds the context with a
/// placeholder connection string and an unresolved tenant context; neither is used to touch a
/// live database during model/migration generation.
/// </summary>
public sealed class CffVaultManagerDbContextFactory : IDesignTimeDbContextFactory<CffVaultManagerDbContext>
{
    public CffVaultManagerDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlServer("Server=(local);Database=CffVaultManager;Trusted_Connection=True;TrustServerCertificate=True;")
            .Options;

        return new CffVaultManagerDbContext(options, new DesignTimeTenantContext());
    }

    private sealed class DesignTimeTenantContext : ITenantContext
    {
        public Guid? TenantId => null;

        public bool IsSuperAdmin => false;

        public Guid? UserId => null;

        public bool IsResolved => false;

        public void SetTenant(Guid tenantId, Guid userId) => throw new NotSupportedException();

        public void SetSuperAdmin(Guid userId) => throw new NotSupportedException();
    }
}
