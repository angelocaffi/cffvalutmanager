using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class ExternalShareLinkConfiguration : IEntityTypeConfiguration<ExternalShareLink>
{
    private readonly CffVaultManagerDbContext _context;

    public ExternalShareLinkConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<ExternalShareLink> builder)
    {
        builder.HasKey(l => l.Id);

        builder.Property(l => l.Token).IsRequired();
        builder.Property(l => l.EncryptedPayload).IsRequired();

        builder.HasIndex(l => l.Token).IsUnique();
        builder.HasIndex(l => new { l.TenantId, l.VaultItemId });

        builder.HasOne<Tenant>()
            .WithMany()
            .HasForeignKey(l => l.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(l => l.VaultItem)
            .WithMany()
            .HasForeignKey(l => l.VaultItemId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(l => l.CreatedByUser)
            .WithMany()
            .HasForeignKey(l => l.CreatedByUserId)
            .OnDelete(DeleteBehavior.Restrict);

        // The public read path (GET /api/share-links/{token}) resolves no ITenantContext at all —
        // it explicitly calls IgnoreQueryFilters() instead (see
        // ExternalShareLinkService.GetByTokenAsync), mirroring AuthenticationService's pre-auth
        // lookups. This filter still applies normally to every authenticated, owner-side query.
        builder.HasQueryFilter(l => l.TenantId == _context.TenantContext.TenantId);
    }
}
