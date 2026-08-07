using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

// Intentionally no global query filter and no FK to Tenant: platform-wide pricing is not
// tenant-scoped data, same reasoning as TenantProvisioningRequestConfiguration.
internal sealed class BillingPricingConfiguration : IEntityTypeConfiguration<BillingPricing>
{
    public void Configure(EntityTypeBuilder<BillingPricing> builder)
    {
        builder.HasKey(p => p.Id);

        builder.Property(p => p.StandardAnnualPrice).HasColumnType("decimal(10,2)");
        builder.Property(p => p.DiscountedAnnualPrice).HasColumnType("decimal(10,2)");
        builder.Property(p => p.PromoMessage).HasMaxLength(280);

        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(p => p.UpdatedByUserId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
