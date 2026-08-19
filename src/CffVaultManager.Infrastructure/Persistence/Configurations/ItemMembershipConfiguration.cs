using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class ItemMembershipConfiguration : IEntityTypeConfiguration<ItemMembership>
{
    private readonly CffVaultManagerDbContext _context;

    public ItemMembershipConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<ItemMembership> builder)
    {
        builder.HasKey(m => m.Id);

        builder.Property(m => m.Permission).HasConversion<string>();
        builder.Property(m => m.WrappedItemKey).IsRequired();
        builder.Property(m => m.EphemeralPublicKey).IsRequired();

        builder.HasOne<Tenant>()
            .WithMany()
            .HasForeignKey(m => m.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(m => m.VaultItem)
            .WithMany()
            .HasForeignKey(m => m.VaultItemId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(m => m.User)
            .WithMany()
            .HasForeignKey(m => m.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        // At most one active membership per (tenant, item, user); revoked rows are retained for
        // audit and excluded from the constraint via the filtered index.
        builder.HasIndex(m => new { m.TenantId, m.VaultItemId, m.UserId })
            .IsUnique()
            .HasFilter("\"RevokedAt\" IS NULL");

        builder.HasIndex(m => new { m.TenantId, m.UserId });

        builder.HasQueryFilter(m => m.TenantId == _context.TenantContext.TenantId);
    }
}
