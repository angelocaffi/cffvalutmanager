using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class FolderConfiguration : IEntityTypeConfiguration<Folder>
{
    private readonly CffVaultManagerDbContext _context;

    public FolderConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<Folder> builder)
    {
        builder.HasKey(f => f.Id);

        builder.Property(f => f.Name).IsRequired().HasMaxLength(200);

        builder.HasOne<Tenant>()
            .WithMany()
            .HasForeignKey(f => f.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(f => f.Vault)
            .WithMany(v => v.Folders)
            .HasForeignKey(f => f.VaultId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(f => new { f.TenantId, f.VaultId });
        builder.HasIndex(f => new { f.VaultId, f.Name }).IsUnique();

        builder.HasQueryFilter(f => f.TenantId == _context.TenantContext.TenantId);
    }
}
