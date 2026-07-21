using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class VaultItemTagConfiguration : IEntityTypeConfiguration<VaultItemTag>
{
    private readonly CffVaultManagerDbContext _context;

    public VaultItemTagConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<VaultItemTag> builder)
    {
        builder.HasKey(vt => new { vt.VaultItemId, vt.TagId });

        builder.HasOne(vt => vt.VaultItem)
            .WithMany(i => i.VaultItemTags)
            .HasForeignKey(vt => vt.VaultItemId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(vt => vt.Tag)
            .WithMany(t => t.VaultItemTags)
            .HasForeignKey(vt => vt.TagId)
            .OnDelete(DeleteBehavior.Cascade);

        // The join row has no TenantId of its own; it inherits isolation from its VaultItem.
        builder.HasQueryFilter(vt => vt.VaultItem!.TenantId == _context.TenantContext.TenantId);
    }
}
