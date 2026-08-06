using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace CffVaultManager.Infrastructure.Authentication;

/// <inheritdoc cref="ISecurityNotificationService" />
internal sealed class SecurityNotificationService : ISecurityNotificationService
{
    private readonly CffVaultManagerDbContext _db;
    private readonly IEmailSender _emailSender;
    private readonly INotificationService _notifications;
    private readonly ILogger<SecurityNotificationService> _logger;

    public SecurityNotificationService(
        CffVaultManagerDbContext db,
        IEmailSender emailSender,
        INotificationService notifications,
        ILogger<SecurityNotificationService> logger)
    {
        _db = db;
        _emailSender = emailSender;
        _notifications = notifications;
        _logger = logger;
    }

    public async Task NotifyLoginIfNewIpAsync(Guid userId, string? ip, string? userAgent, CancellationToken ct = default)
    {
        // No IP to compare (e.g. missing behind an unusual proxy setup): nothing meaningful to
        // call "new", so stay silent rather than alert on every single login.
        if (string.IsNullOrEmpty(ip))
        {
            return;
        }

        // Called mid-login (from AuthenticationService.IssueSessionAsync), before this request's
        // own LoginSuccess entry is written — so "any prior entry from this IP" correctly excludes
        // the login currently in progress. Runs before the tenant query filter is resolvable,
        // mirroring AuthenticationService's own pre-authentication lookups.
        bool seenBefore = await _db.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(e => e.UserId == userId && e.Action == AuditAction.LoginSuccess && e.IpAddress == ip, ct);
        if (seenBefore)
        {
            return;
        }

        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return;
        }

        await SendEmailAsync(
            user.Email,
            "Nuovo accesso da un indirizzo IP sconosciuto — CffVaultManager",
            $"Abbiamo rilevato un accesso al tuo account da un indirizzo IP mai visto prima.\n\n" +
            $"Indirizzo IP: {ip}\nDispositivo: {userAgent ?? "sconosciuto"}\n\n" +
            "Se sei stato tu, non devi fare nulla. Se non riconosci questo accesso, cambia subito " +
            "la tua master password e controlla le sessioni attive.",
            ct);

        await CreateInAppNotificationAsync(
            user.TenantId, userId, NotificationType.NewLoginFromUnknownIp,
            $"Nuovo accesso da un indirizzo IP mai visto prima ({ip}).", ct);
    }

    public async Task NotifyMasterPasswordChangedAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return;
        }

        await SendEmailAsync(
            user.Email,
            "La tua master password è stata cambiata — CffVaultManager",
            "La master password del tuo account è stata cambiata e tutte le sessioni attive sono " +
            "state disconnesse. Se sei stato tu, non devi fare nulla. Se non riconosci questa " +
            "modifica, contatta subito il tuo amministratore.",
            ct);

        await CreateInAppNotificationAsync(
            user.TenantId, userId, NotificationType.MasterPasswordChanged,
            "La tua master password è stata cambiata.", ct);
    }

    public async Task NotifyMfaFactorDisabledAsync(Guid userId, string factorDescription, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return;
        }

        await SendEmailAsync(
            user.Email,
            "Un fattore di autenticazione è stato disattivato — CffVaultManager",
            $"Il fattore di autenticazione a due passaggi \"{factorDescription}\" è stato disattivato " +
            "sul tuo account. Se sei stato tu, non devi fare nulla. Se non riconosci questa modifica, " +
            "riattivalo e cambia subito la tua master password.",
            ct);

        await CreateInAppNotificationAsync(
            user.TenantId, userId, NotificationType.MfaFactorDisabled,
            $"Il fattore \"{factorDescription}\" è stato disattivato.", ct);
    }

    public async Task NotifyAccountRecoveredAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return;
        }

        await SendEmailAsync(
            user.Email,
            "Il tuo account è stato recuperato — CffVaultManager",
            "Il tuo account è stato recuperato tramite il kit di recupero: è stata impostata una " +
            "nuova master password e tutte le sessioni attive sono state disconnesse. Se sei stato " +
            "tu, non devi fare nulla. Se non riconosci questa operazione, contatta subito il tuo amministratore.",
            ct);

        await CreateInAppNotificationAsync(
            user.TenantId, userId, NotificationType.AccountRecovered,
            "Il tuo account è stato recuperato con il kit di recupero: nuova master password impostata.", ct);
    }

    public async Task NotifyRecoveryKitInvalidatedAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return;
        }

        await SendEmailAsync(
            user.Email,
            "Il tuo kit di recupero non è più valido — CffVaultManager",
            "Hai ruotato la chiave di cifratura del tuo vault: il kit di recupero generato in " +
            "precedenza non è più utilizzabile. Se vuoi ancora poter recuperare l'accesso senza la " +
            "master password, generane uno nuovo dalle impostazioni di sicurezza.",
            ct);

        await CreateInAppNotificationAsync(
            user.TenantId, userId, NotificationType.RecoveryKitInvalidated,
            "Il tuo kit di recupero non è più valido: generane uno nuovo se lo desideri ancora.", ct);
    }

    public async Task NotifyPasskeyLoginInvalidatedAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return;
        }

        await SendEmailAsync(
            user.Email,
            "Accesso senza password disattivato sui tuoi dispositivi — CffVaultManager",
            "Hai ruotato la chiave di cifratura del tuo vault: l'accesso senza password via passkey, " +
            "se lo avevi attivato su uno o più dispositivi, non è più utilizzabile. Le passkey restano " +
            "valide come fattore di sicurezza secondario; per tornare a usarle per l'accesso senza " +
            "password, riattivalo dalle impostazioni di sicurezza sul dispositivo interessato.",
            ct);

        await CreateInAppNotificationAsync(
            user.TenantId, userId, NotificationType.PasskeyLoginInvalidated,
            "L'accesso senza password via passkey non è più valido sui tuoi dispositivi: riattivalo se lo desideri ancora.", ct);
    }

    // Both channels below are deliberately best-effort: per ISecurityNotificationService, a
    // delivery failure here must never fail the underlying operation (login, master password
    // change, MFA disable) that already succeeded before this point.

    private async Task SendEmailAsync(string toEmail, string subject, string body, CancellationToken ct)
    {
        try
        {
            await _emailSender.SendAsync(toEmail, subject, body, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send a security notification email; the triggering operation already succeeded.");
        }
    }

    private async Task CreateInAppNotificationAsync(Guid? tenantId, Guid userId, NotificationType type, string message, CancellationToken ct)
    {
        // A SuperAdmin has no TenantId and no tenant-scoped Notification row can be created for
        // one; in practice none of the three triggers apply to a SuperAdmin account today.
        if (tenantId is null)
        {
            return;
        }

        try
        {
            await _notifications.CreateAsync(tenantId.Value, userId, type, message, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to create an in-app notification; the triggering operation already succeeded.");
        }
    }
}
