using CffVaultManager.Application.Abstractions;
using CffVaultManager.Crypto;
using CffVaultManager.Crypto.Abstractions;
using CffVaultManager.Infrastructure.Administration;
using CffVaultManager.Infrastructure.Audit;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using CffVaultManager.Infrastructure.VaultCore;
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

        // Services that touch the (scoped) DbContext.
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();
        services.AddScoped<IProvisionTenantService, ProvisionTenantService>();
        services.AddScoped<IUserRegistrationService, UserRegistrationService>();
        services.AddScoped<IAuthenticationService, AuthenticationService>();
        services.AddScoped<IMfaSetupService, MfaSetupService>();
        services.AddScoped<IEmailOtpMfaService, EmailOtpMfaService>();
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
