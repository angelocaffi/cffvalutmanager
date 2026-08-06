using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// TOTP enrollment. The secret is stored encrypted immediately but MFA is only switched on after
/// the user proves possession by entering a valid first code, so a partial enrollment cannot lock
/// them out.
/// </summary>
internal sealed class MfaSetupService : IMfaSetupService
{
    private const string Issuer = "CffVaultManager";

    private readonly CffVaultManagerDbContext _db;
    private readonly ITotpService _totp;
    private readonly ISecretProtector _secretProtector;
    private readonly ISecurityNotificationService? _securityNotifications;

    public MfaSetupService(
        CffVaultManagerDbContext db,
        ITotpService totp,
        ISecretProtector secretProtector,
        ISecurityNotificationService? securityNotifications = null)
    {
        _db = db;
        _totp = totp;
        _secretProtector = secretProtector;
        _securityNotifications = securityNotifications;
    }

    public async Task<string> SetupTotpAsync(Guid userId, CancellationToken ct = default)
    {
        // Runs post-authentication, so the tenant query filter is resolved and correctly scopes
        // this to the caller's own user record.
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        byte[] secret = _totp.GenerateSecret();
        user.MfaSecret = _secretProtector.Protect(secret);
        user.MfaEnabled = false;
        await _db.SaveChangesAsync(ct);

        return _totp.GetProvisioningUri(secret, user.Email, Issuer);
    }

    public async Task<bool> ConfirmTotpAsync(Guid userId, string code, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || user.MfaSecret is null)
        {
            return false;
        }

        byte[] secret;
        try
        {
            secret = _secretProtector.Unprotect(user.MfaSecret);
        }
        catch (CryptographicException)
        {
            // The key ring that encrypted this secret is gone (see ServiceCollectionExtensions.cs
            // DataProtection:KeyPath) — the pending setup is unrecoverable, same as a wrong code:
            // the caller must call SetupTotpAsync again to get a fresh secret.
            return false;
        }

        if (!_totp.ValidateCode(secret, code))
        {
            return false;
        }

        user.MfaEnabled = true;
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.MfaEnabled));
        await _db.SaveChangesAsync(ct);
        return true;
    }

    public async Task DisableTotpAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        if (!user.MfaEnabled && user.MfaSecret is null)
        {
            return;
        }

        user.MfaEnabled = false;
        // Discarded, not kept around for a possible "re-enable": a stale secret from before a
        // Data Protection key-ring loss is exactly what caused the lockout this button exists to
        // let people recover from themselves — re-enabling always goes through SetupTotpAsync
        // again for a fresh secret and QR code.
        user.MfaSecret = null;
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.MfaDisabled));
        await _db.SaveChangesAsync(ct);

        if (_securityNotifications is not null)
        {
            await _securityNotifications.NotifyMfaFactorDisabledAsync(user.Id, "l'autenticatore TOTP", ct);
        }
    }
}
