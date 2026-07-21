using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    private readonly CffVaultManagerDbContext _context;

    public UserConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasKey(u => u.Id);

        builder.Property(u => u.Email).IsRequired().HasMaxLength(320);
        builder.Property(u => u.Role).HasConversion<string>();

        builder.HasOne(u => u.Tenant)
            .WithMany(t => t.Users)
            .HasForeignKey(u => u.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasIndex(u => u.Email).IsUnique();
        builder.HasIndex(u => new { u.TenantId, u.Email });

        // A tenant user is visible to its own tenant; a SuperAdmin (TenantId == null)
        // is only visible to another SuperAdmin, never to tenant-scoped callers.
        builder.HasQueryFilter(u =>
            u.TenantId == _context.TenantContext.TenantId
            || (_context.TenantContext.IsSuperAdmin && u.TenantId == null));
    }
}
