using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

internal sealed class UserInvitationConfiguration : IEntityTypeConfiguration<UserInvitation>
{
    private readonly CffVaultManagerDbContext _context;

    public UserInvitationConfiguration(CffVaultManagerDbContext context) => _context = context;

    public void Configure(EntityTypeBuilder<UserInvitation> builder)
    {
        builder.HasKey(i => i.Id);

        builder.Property(i => i.Email).IsRequired();
        builder.Property(i => i.Token).IsRequired();
        builder.Property(i => i.Role).HasConversion<string>();

        builder.HasIndex(i => i.Token).IsUnique();
        builder.HasIndex(i => i.ExpiresAt);

        builder.HasOne(i => i.Tenant)
            .WithMany()
            .HasForeignKey(i => i.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(i => i.InvitedByUser)
            .WithMany()
            .HasForeignKey(i => i.InvitedByUserId)
            .OnDelete(DeleteBehavior.Restrict);

        // The public accept flow (GET/POST /api/tenant/users/invitations/{token}...) resolves no
        // ITenantContext — it explicitly calls IgnoreQueryFilters() instead (see
        // UserInvitationService.GetPreviewAsync/AcceptAsync), same pattern as
        // ExternalShareLinkConfiguration. This filter still applies normally to every
        // authenticated, Admin-side query (list/revoke).
        builder.HasQueryFilter(i => i.TenantId == _context.TenantContext.TenantId);
    }
}
