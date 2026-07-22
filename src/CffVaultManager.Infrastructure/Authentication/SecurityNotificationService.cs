using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <inheritdoc cref="ISecurityNotificationService" />
internal sealed class SecurityNotificationService : ISecurityNotificationService
{
    private readonly CffVaultManagerDbContext _db;
    private readonly IEmailSender _emailSender;

    public SecurityNotificationService(CffVaultManagerDbContext db, IEmailSender emailSender)
    {
        _db = db;
        _emailSender = emailSender;
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

        await _emailSender.SendAsync(
            user.Email,
            "Nuovo accesso da un indirizzo IP sconosciuto — CffVaultManager",
            $"Abbiamo rilevato un accesso al tuo account da un indirizzo IP mai visto prima.\n\n" +
            $"Indirizzo IP: {ip}\nDispositivo: {userAgent ?? "sconosciuto"}\n\n" +
            "Se sei stato tu, non devi fare nulla. Se non riconosci questo accesso, cambia subito " +
            "la tua master password e controlla le sessioni attive.",
            ct);
    }

    public async Task NotifyMasterPasswordChangedAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return;
        }

        await _emailSender.SendAsync(
            user.Email,
            "La tua master password è stata cambiata — CffVaultManager",
            "La master password del tuo account è stata cambiata e tutte le sessioni attive sono " +
            "state disconnesse. Se sei stato tu, non devi fare nulla. Se non riconosci questa " +
            "modifica, contatta subito il tuo amministratore.",
            ct);
    }

    public async Task NotifyMfaFactorDisabledAsync(Guid userId, string factorDescription, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return;
        }

        await _emailSender.SendAsync(
            user.Email,
            "Un fattore di autenticazione è stato disattivato — CffVaultManager",
            $"Il fattore di autenticazione a due passaggi \"{factorDescription}\" è stato disattivato " +
            "sul tuo account. Se sei stato tu, non devi fare nulla. Se non riconosci questa modifica, " +
            "riattivalo e cambia subito la tua master password.",
            ct);
    }
}
