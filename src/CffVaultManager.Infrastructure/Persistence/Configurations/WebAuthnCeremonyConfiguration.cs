using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

// No global query filter: mirrors OneTimeCode — resolved by UserId directly by the service layer,
// including pre-authentication (the assertion ceremony runs before a session exists).
internal sealed class WebAuthnCeremonyConfiguration : IEntityTypeConfiguration<WebAuthnCeremony>
{
    public void Configure(EntityTypeBuilder<WebAuthnCeremony> builder)
    {
        builder.HasKey(c => c.Id);

        builder.Property(c => c.Purpose).HasConversion<string>();
        builder.Property(c => c.OptionsJson).IsRequired();

        builder.HasOne(c => c.User)
            .WithMany()
            .HasForeignKey(c => c.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(c => new { c.UserId, c.Purpose, c.ExpiresAt });
    }
}
