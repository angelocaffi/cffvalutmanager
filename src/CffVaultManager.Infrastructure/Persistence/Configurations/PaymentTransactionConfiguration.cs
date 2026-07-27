using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class PaymentTransactionConfiguration : IEntityTypeConfiguration<PaymentTransaction>
{
    private readonly CffVaultManagerDbContext _context;

    public PaymentTransactionConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<PaymentTransaction> builder)
    {
        builder.HasKey(t => t.Id);

        builder.Property(t => t.PayPalOrderId).IsRequired().HasMaxLength(50);
        builder.Property(t => t.Currency).IsRequired().HasMaxLength(3);
        builder.Property(t => t.Amount).HasColumnType("decimal(10,2)");
        builder.Property(t => t.Status).HasConversion<string>();

        builder.HasOne<Tenant>()
            .WithMany()
            .HasForeignKey(t => t.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(t => t.CreatedByUserId)
            .OnDelete(DeleteBehavior.Restrict);

        // PayPal order ids are globally unique on PayPal's side too — this is the idempotency
        // guard for double-captures (see BillingService.CaptureCheckoutAsync).
        builder.HasIndex(t => t.PayPalOrderId).IsUnique();

        builder.HasIndex(t => new { t.TenantId, t.CreatedAt });

        builder.HasQueryFilter(t => t.TenantId == _context.TenantContext.TenantId);
    }
}
