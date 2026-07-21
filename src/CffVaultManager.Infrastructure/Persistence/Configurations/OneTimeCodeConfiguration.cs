using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

// Intentionally no global query filter: isolating one-time codes by UserId belongs to the
// service layer once authentication exists. Adding an EF filter now would couple the model
// prematurely to an authentication story that has not been implemented yet.
internal sealed class OneTimeCodeConfiguration : IEntityTypeConfiguration<OneTimeCode>
{
    public void Configure(EntityTypeBuilder<OneTimeCode> builder)
    {
        builder.HasKey(o => o.Id);

        builder.Property(o => o.Purpose).HasConversion<string>();
        builder.Property(o => o.IpAddress).HasMaxLength(45);
        builder.Property(o => o.UserAgent).HasMaxLength(512);

        builder.HasOne(o => o.User)
            .WithMany(u => u.OneTimeCodes)
            .HasForeignKey(o => o.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(o => new { o.UserId, o.Purpose, o.ExpiresAt });
    }
}
