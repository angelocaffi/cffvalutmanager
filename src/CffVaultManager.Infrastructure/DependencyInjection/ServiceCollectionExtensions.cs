using CffVaultManager.Application.Abstractions;
using CffVaultManager.Crypto;
using CffVaultManager.Crypto.Abstractions;
using CffVaultManager.Infrastructure.Administration;
using CffVaultManager.Infrastructure.Audit;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using CffVaultManager.Infrastructure.VaultCore;
using Fido2NetLib;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CffVaultManager.Infrastructure.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddScoped<ITenantContext, TenantContext>();

        services.AddDbContext<CffVaultManagerDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("Default")));

        services.AddScoped<ITenantAdministrationService, TenantAdministrationService>();

        // Server-held key material for MFA-secret protection.
        services.AddDataProtection();

        // Stateless crypto/token helpers: safe as singletons.
        services.AddSingleton<IKeyDerivationService, Argon2KeyDerivationService>();
        services.AddSingleton<IAuthHashHasher, ServerAuthHashHasher>();
        services.AddSingleton<ITotpService, TotpService>();
        services.AddSingleton<ISecretProtector, SecretProtector>();
        services.AddSingleton<IJwtTokenService, JwtTokenService>();

        // Real SMTP delivery only when a host is actually configured — same "empty string = not
        // configured" convention already used for WebAuthn below, so local dev works out of the
        // box without requiring an SMTP account (see docs/features/notifications.md).
        string smtpHost = configuration["Email:SmtpHost"] ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(smtpHost))
        {
            services.AddSingleton<IEmailSender>(sp => new SmtpEmailSender(
                smtpHost,
                configuration.GetValue<int?>("Email:SmtpPort") ?? 587,
                configuration["Email:SmtpUsername"],
                configuration["Email:SmtpPassword"],
                configuration.GetValue<bool?>("Email:UseStartTls") ?? true,
                configuration["Email:FromAddress"] ?? string.Empty,
                configuration["Email:FromDisplayName"] ?? "CffVaultManager",
                sp.GetRequiredService<ILogger<SmtpEmailSender>>()));
        }
        else
        {
            services.AddSingleton<IEmailSender, LoggingEmailSender>();
        }

        // RP ID/origins must match the origin the browser's navigator.credentials call actually
        // runs from — the Web(.Client) host, not this Api (see docs/features/authentication.md).
        // No IMetadataService: this is a self-hosted single deployment, not an enterprise
        // authenticator allow-list scenario, so FIDO Metadata Service attestation checking is out
        // of scope.
        services.AddSingleton<IFido2>(sp =>
        {
            var config = sp.GetRequiredService<IConfiguration>();
            var origins = config.GetSection("WebAuthn:Origins").Get<string[]>() ?? [];
            var fido2Config = new Fido2Configuration
            {
                ServerDomain = config["WebAuthn:RelyingPartyId"] ?? "localhost",
                ServerName = config["WebAuthn:ServerName"] ?? "CffVaultManager",
                Origins = new HashSet<string>(origins),
            };
            return new Fido2(fido2Config, metadataService: null);
        });

        // Services that touch the (scoped) DbContext.
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();
        services.AddScoped<IProvisionTenantService, ProvisionTenantService>();
        services.AddScoped<IUserRegistrationService, UserRegistrationService>();
        services.AddScoped<IAuthenticationService, AuthenticationService>();
        services.AddScoped<IMfaSetupService, MfaSetupService>();
        services.AddScoped<IEmailOtpMfaService, EmailOtpMfaService>();
        services.AddScoped<IWebAuthnService, WebAuthnService>();
        services.AddScoped<IUserProfileService, UserProfileService>();
        services.AddScoped<IKeyPairService, KeyPairService>();
        services.AddScoped<IChangeMasterPasswordService, ChangeMasterPasswordService>();
        services.AddScoped<IDekRotationService, DekRotationService>();
        services.AddScoped<IEmailVerificationService, EmailVerificationService>();
        services.AddScoped<INotificationService, NotificationService>();
        services.AddScoped<ISecurityNotificationService, SecurityNotificationService>();
        services.AddScoped<IVaultService, VaultService>();
        services.AddScoped<IFolderService, FolderService>();
        services.AddScoped<ITagService, TagService>();
        services.AddScoped<IVaultItemService, VaultItemService>();
        services.AddScoped<IVaultMembershipService, VaultMembershipService>();
        services.AddScoped<IAuditLogService, AuditLogService>();
        services.AddScoped<IAuditLogRetentionService, AuditLogRetentionService>();
        services.AddHostedService<AuditLogRetentionHostedService>();
        services.AddScoped<IExternalShareLinkService, ExternalShareLinkService>();
        services.AddScoped<IItemMembershipService, ItemMembershipService>();

        return services;
    }
}
