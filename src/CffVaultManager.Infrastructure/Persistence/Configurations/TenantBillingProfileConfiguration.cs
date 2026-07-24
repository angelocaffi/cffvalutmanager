using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class TenantBillingProfileConfiguration : IEntityTypeConfiguration<TenantBillingProfile>
{
    private readonly CffVaultManagerDbContext _context;

    public TenantBillingProfileConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<TenantBillingProfile> builder)
    {
        builder.HasKey(b => b.Id);

        builder.Property(b => b.LegalName).IsRequired().HasMaxLength(200);
        builder.Property(b => b.VatNumber).HasMaxLength(50);
        builder.Property(b => b.TaxCode).HasMaxLength(50);
        builder.Property(b => b.AddressLine).IsRequired().HasMaxLength(300);
        builder.Property(b => b.City).IsRequired().HasMaxLength(100);
        builder.Property(b => b.PostalCode).IsRequired().HasMaxLength(20);
        builder.Property(b => b.Province).IsRequired().HasMaxLength(100);
        builder.Property(b => b.Country).IsRequired().HasMaxLength(100);
        builder.Property(b => b.SdiCode).HasMaxLength(10);
        builder.Property(b => b.PecAddress).HasMaxLength(320);
        builder.Property(b => b.Phone).HasMaxLength(50);

        builder.HasOne(b => b.Tenant)
            .WithOne()
            .HasForeignKey<TenantBillingProfile>(b => b.TenantId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(b => b.TenantId).IsUnique();

        builder.HasQueryFilter(b => b.TenantId == _context.TenantContext.TenantId);
    }
}
