using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class VaultConfiguration : IEntityTypeConfiguration<Vault>
{
    private readonly CffVaultManagerDbContext _context;

    public VaultConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<Vault> builder)
    {
        builder.HasKey(v => v.Id);

        builder.Property(v => v.Name).IsRequired().HasMaxLength(200);

        builder.HasOne(v => v.Tenant)
            .WithMany(t => t.Vaults)
            .HasForeignKey(v => v.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(v => v.OwnerUser)
            .WithMany(u => u.OwnedVaults)
            .HasForeignKey(v => v.OwnerUserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasIndex(v => new { v.TenantId, v.Id });
        builder.HasIndex(v => new { v.TenantId, v.OwnerUserId });

        builder.HasQueryFilter(v => v.TenantId == _context.TenantContext.TenantId);
    }
}
