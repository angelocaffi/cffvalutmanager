using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class VaultItemConfiguration : IEntityTypeConfiguration<VaultItem>
{
    private readonly CffVaultManagerDbContext _context;

    public VaultItemConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<VaultItem> builder)
    {
        builder.HasKey(i => i.Id);

        builder.Property(i => i.Type).HasConversion<string>();
        builder.Property(i => i.EncryptedPayload).IsRequired();
        builder.Property(i => i.IsDeleted).IsRequired().HasDefaultValue(false);
        builder.Property(i => i.DeletedAt);

        builder.HasOne<Tenant>()
            .WithMany()
            .HasForeignKey(i => i.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(i => i.Vault)
            .WithMany(v => v.Items)
            .HasForeignKey(i => i.VaultId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(i => i.Folder)
            .WithMany(f => f.Items)
            .HasForeignKey(i => i.FolderId)
            .OnDelete(DeleteBehavior.SetNull);

        builder.HasIndex(i => new { i.TenantId, i.VaultId });
        builder.HasIndex(i => new { i.TenantId, i.FolderId, i.Type });
        builder.HasIndex(i => new { i.TenantId, i.VaultId, i.IsDeleted });

        builder.HasQueryFilter(i => i.TenantId == _context.TenantContext.TenantId);
    }
}
