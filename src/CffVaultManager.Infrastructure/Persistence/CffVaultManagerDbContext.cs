using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Infrastructure.Persistence.Configurations;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Persistence;

/// <summary>
/// The application's EF Core context. The injected <see cref="ITenantContext"/> is
/// consumed by the per-entity global query filters so that every ordinary query is
/// automatically scoped to the current tenant (fail-closed when unresolved).
/// </summary>
public class CffVaultManagerDbContext : DbContext
{
    internal ITenantContext TenantContext { get; }

    public CffVaultManagerDbContext(
        DbContextOptions<CffVaultManagerDbContext> options,
        ITenantContext tenantContext)
        : base(options)
    {
        TenantContext = tenantContext;
    }

    public DbSet<Tenant> Tenants => Set<Tenant>();

    public DbSet<User> Users => Set<User>();

    public DbSet<Vault> Vaults => Set<Vault>();

    public DbSet<VaultItem> VaultItems => Set<VaultItem>();

    public DbSet<VaultMembership> VaultMemberships => Set<VaultMembership>();

    public DbSet<Folder> Folders => Set<Folder>();

    public DbSet<Tag> Tags => Set<Tag>();

    public DbSet<VaultItemTag> VaultItemTags => Set<VaultItemTag>();

    public DbSet<AuditLogEntry> AuditLogEntries => Set<AuditLogEntry>();

    public DbSet<OneTimeCode> OneTimeCodes => Set<OneTimeCode>();

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    public DbSet<WebAuthnCredential> WebAuthnCredentials => Set<WebAuthnCredential>();

    public DbSet<WebAuthnCeremony> WebAuthnCeremonies => Set<WebAuthnCeremony>();

    public DbSet<ExternalShareLink> ExternalShareLinks => Set<ExternalShareLink>();

    public DbSet<ItemMembership> ItemMemberships => Set<ItemMembership>();

    public DbSet<Notification> Notifications => Set<Notification>();

    public DbSet<TenantBillingProfile> TenantBillingProfiles => Set<TenantBillingProfile>();

    public DbSet<TenantProvisioningRequest> TenantProvisioningRequests => Set<TenantProvisioningRequest>();

    public DbSet<PaymentTransaction> PaymentTransactions => Set<PaymentTransaction>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Configurations whose global query filter reads the current tenant take this
        // DbContext instance so EF re-parameterizes the tenant per query (the model is a
        // cached singleton; capturing the scoped ITenantContext directly would freeze the
        // first request's tenant into every subsequent query).
        modelBuilder.ApplyConfiguration(new TenantConfiguration());
        modelBuilder.ApplyConfiguration(new UserConfiguration(this));
        modelBuilder.ApplyConfiguration(new VaultConfiguration(this));
        modelBuilder.ApplyConfiguration(new VaultItemConfiguration(this));
        modelBuilder.ApplyConfiguration(new VaultMembershipConfiguration(this));
        modelBuilder.ApplyConfiguration(new FolderConfiguration(this));
        modelBuilder.ApplyConfiguration(new TagConfiguration(this));
        modelBuilder.ApplyConfiguration(new VaultItemTagConfiguration(this));
        modelBuilder.ApplyConfiguration(new AuditLogEntryConfiguration(this));
        modelBuilder.ApplyConfiguration(new OneTimeCodeConfiguration());
        modelBuilder.ApplyConfiguration(new RefreshTokenConfiguration());
        modelBuilder.ApplyConfiguration(new WebAuthnCredentialConfiguration());
        modelBuilder.ApplyConfiguration(new WebAuthnCeremonyConfiguration());
        modelBuilder.ApplyConfiguration(new ExternalShareLinkConfiguration(this));
        modelBuilder.ApplyConfiguration(new ItemMembershipConfiguration(this));
        modelBuilder.ApplyConfiguration(new NotificationConfiguration(this));
        modelBuilder.ApplyConfiguration(new TenantBillingProfileConfiguration(this));
        modelBuilder.ApplyConfiguration(new TenantProvisioningRequestConfiguration());
        modelBuilder.ApplyConfiguration(new PaymentTransactionConfiguration(this));
    }
}
