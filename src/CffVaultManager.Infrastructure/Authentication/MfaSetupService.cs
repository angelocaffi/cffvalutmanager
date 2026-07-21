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

    public MfaSetupService(CffVaultManagerDbContext db, ITotpService totp, ISecretProtector secretProtector)
    {
        _db = db;
        _totp = totp;
        _secretProtector = secretProtector;
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

        byte[] secret = _secretProtector.Unprotect(user.MfaSecret);
        if (!_totp.ValidateCode(secret, code))
        {
            return false;
        }

        user.MfaEnabled = true;
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.MfaEnabled));
        await _db.SaveChangesAsync(ct);
        return true;
    }
}
