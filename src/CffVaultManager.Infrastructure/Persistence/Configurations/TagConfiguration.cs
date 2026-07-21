using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class TagConfiguration : IEntityTypeConfiguration<Tag>
{
    private readonly CffVaultManagerDbContext _context;

    public TagConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<Tag> builder)
    {
        builder.HasKey(t => t.Id);

        builder.Property(t => t.Name).IsRequired().HasMaxLength(100);

        builder.HasOne<Tenant>()
            .WithMany()
            .HasForeignKey(t => t.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        // Restrict, not Cascade — same reasoning as FolderConfiguration's Vault relationship:
        // SQL Server refuses this schema otherwise, since a Vault delete would reach
        // VaultItemTags through two competing cascade paths (via Tag and via VaultItem, both
        // Cascade). No vault deletion feature exists yet; when one is added, cleanup belongs
        // there, same as this codebase already does for other business-meaningful cleanup.
        builder.HasOne(t => t.Vault)
            .WithMany(v => v.Tags)
            .HasForeignKey(t => t.VaultId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasIndex(t => new { t.TenantId, t.VaultId });
        builder.HasIndex(t => new { t.VaultId, t.Name }).IsUnique();

        builder.HasQueryFilter(t => t.TenantId == _context.TenantContext.TenantId);
    }
}
