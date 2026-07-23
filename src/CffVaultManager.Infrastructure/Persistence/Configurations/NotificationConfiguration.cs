using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class NotificationConfiguration : IEntityTypeConfiguration<Notification>
{
    private readonly CffVaultManagerDbContext _context;

    public NotificationConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<Notification> builder)
    {
        builder.HasKey(n => n.Id);

        builder.Property(n => n.Type).HasConversion<string>();
        builder.Property(n => n.Message).IsRequired();

        builder.HasOne<Tenant>()
            .WithMany()
            .HasForeignKey(n => n.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(n => n.User)
            .WithMany()
            .HasForeignKey(n => n.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        // Fast "unread count for this user" / "list this user's notifications" lookups.
        builder.HasIndex(n => new { n.TenantId, n.UserId, n.ReadAt });

        builder.HasQueryFilter(n => n.TenantId == _context.TenantContext.TenantId);
    }
}
