using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

// Intentionally no global query filter and no FK to Tenant: the tenant does not exist yet while a
// row here is pending (see TenantProvisioningRequestService) — same reasoning as
// OneTimeCodeConfiguration before authentication existed.
internal sealed class TenantProvisioningRequestConfiguration : IEntityTypeConfiguration<TenantProvisioningRequest>
{
    public void Configure(EntityTypeBuilder<TenantProvisioningRequest> builder)
    {
        builder.HasKey(r => r.Id);

        builder.Property(r => r.TenantName).IsRequired().HasMaxLength(200);
        builder.Property(r => r.TenantSlug).IsRequired().HasMaxLength(100);
        builder.Property(r => r.AdminEmail).IsRequired();
        builder.Property(r => r.LegalName).IsRequired().HasMaxLength(200);
        builder.Property(r => r.VatNumber).HasMaxLength(50);
        builder.Property(r => r.TaxCode).HasMaxLength(50);
        builder.Property(r => r.AddressLine).IsRequired().HasMaxLength(300);
        builder.Property(r => r.City).IsRequired().HasMaxLength(100);
        builder.Property(r => r.PostalCode).IsRequired().HasMaxLength(20);
        builder.Property(r => r.Province).IsRequired().HasMaxLength(100);
        builder.Property(r => r.Country).IsRequired().HasMaxLength(100);
        builder.Property(r => r.SdiCode).HasMaxLength(10);
        builder.Property(r => r.PecAddress).HasMaxLength(320);
        builder.Property(r => r.Phone).HasMaxLength(50);
        builder.Property(r => r.IpAddress).HasMaxLength(45);
        builder.Property(r => r.UserAgent).HasMaxLength(512);

        // Fast lookup for the periodic purge of never-confirmed requests.
        builder.HasIndex(r => r.ExpiresAt);
    }
}
