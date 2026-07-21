using CffVaultManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CffVaultManager.Infrastructure.Persistence.Configurations;

// No global query filter: like RefreshToken, a credential is looked up by its (public,
// non-secret) CredentialId during the pre-authentication assertion flow, before any tenant
// context is resolved. Scoping to the right user is enforced by the service layer.
internal sealed class WebAuthnCredentialConfiguration : IEntityTypeConfiguration<WebAuthnCredential>
{
    public void Configure(EntityTypeBuilder<WebAuthnCredential> builder)
    {
        builder.HasKey(c => c.Id);

        // Capped (not varbinary(max)): SQL Server can't build a unique index on an unbounded
        // column, and real credential IDs are comfortably smaller than this in practice.
        builder.Property(c => c.CredentialId).IsRequired().HasMaxLength(255);
        builder.Property(c => c.PublicKey).IsRequired();
        builder.Property(c => c.Nickname).HasMaxLength(100);
        builder.Property(c => c.Transports).HasMaxLength(100);

        builder.HasOne(c => c.User)
            .WithMany(u => u.WebAuthnCredentials)
            .HasForeignKey(c => c.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        // A given authenticator credential must never be registered twice, globally — not just
        // per-user (mirrors the WebAuthn spec's own uniqueness expectation).
        builder.HasIndex(c => c.CredentialId).IsUnique();
        builder.HasIndex(c => c.UserId);
    }
}
