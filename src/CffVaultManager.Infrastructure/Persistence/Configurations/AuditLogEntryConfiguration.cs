using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class AuditLogEntryConfiguration : IEntityTypeConfiguration<AuditLogEntry>
{
    private readonly CffVaultManagerDbContext _context;

    public AuditLogEntryConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<AuditLogEntry> builder)
    {
        builder.HasKey(a => a.Id);

        builder.Property(a => a.Action).HasConversion<string>();
        builder.Property(a => a.IpAddress).HasMaxLength(45);
        builder.Property(a => a.UserAgent).HasMaxLength(512);

        builder.HasOne<Tenant>()
            .WithMany(t => t.AuditLogEntries)
            .HasForeignKey(a => a.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(a => a.User)
            .WithMany(u => u.AuditLogEntries)
            .HasForeignKey(a => a.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(a => a.VaultItem)
            .WithMany()
            .HasForeignKey(a => a.VaultItemId)
            .OnDelete(DeleteBehavior.SetNull);

        builder.HasIndex(a => new { a.TenantId, a.Timestamp });
        builder.HasIndex(a => new { a.UserId, a.Timestamp });

        // Same rule as User: a platform-level entry (TenantId == null) is visible only
        // to a SuperAdmin, never to a tenant-scoped caller.
        builder.HasQueryFilter(a =>
            a.TenantId == _context.TenantContext.TenantId
            || (_context.TenantContext.IsSuperAdmin && a.TenantId == null));
    }
}
