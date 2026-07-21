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

        // Restrict, not Cascade: SQL Server refuses to create this schema otherwise — a Vault
        // delete would reach VaultItems through two competing paths (directly, via
        // VaultItemConfiguration's own Cascade; and indirectly through this Folder cascade
        // combined with VaultItem.FolderId's SetNull) — "multiple cascade paths" (this was never
        // caught because the whole test suite runs against SQLite, which doesn't enforce this;
        // it only surfaced when first pointing the Api at a real SQL Server instance). No vault
        // deletion feature exists yet anyway; when one is added, folder cleanup belongs in that
        // service, same as this codebase already does for other business-meaningful cleanup.
        builder.HasOne(f => f.Vault)
            .WithMany(v => v.Folders)
            .HasForeignKey(f => f.VaultId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasIndex(f => new { f.TenantId, f.VaultId });
        builder.HasIndex(f => new { f.VaultId, f.Name }).IsUnique();

        builder.HasQueryFilter(f => f.TenantId == _context.TenantContext.TenantId);
    }
}
