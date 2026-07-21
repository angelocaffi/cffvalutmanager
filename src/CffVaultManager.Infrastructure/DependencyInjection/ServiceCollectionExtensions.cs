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
        services.AddSingleton<IEmailSender, LoggingEmailSender>();

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
        services.AddScoped<IChangeMasterPasswordService, ChangeMasterPasswordService>();
        services.AddScoped<IEmailVerificationService, EmailVerificationService>();
        services.AddScoped<IVaultService, VaultService>();
        services.AddScoped<IFolderService, FolderService>();
        services.AddScoped<ITagService, TagService>();
        services.AddScoped<IVaultItemService, VaultItemService>();
        services.AddScoped<IVaultMembershipService, VaultMembershipService>();
        services.AddScoped<IAuditLogService, AuditLogService>();

        return services;
    }
}
