using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Email OTP as an MFA login factor (docs/features/authentication.md "Email OTP come fattore
/// MFA"). Reuses the <see cref="OneTimeCode"/> entity with <c>OtpPurpose.MfaLogin</c> and the same
/// hashing scheme as <see cref="EmailVerificationService"/> (see <see cref="OneTimeCodeHasher"/>),
/// but is otherwise a separate concern: confirming an account's email does not by itself enable
/// this factor, and enabling this factor does not touch <see cref="User.EmailVerifiedAt"/>.
/// </summary>
internal sealed class EmailOtpMfaService : IEmailOtpMfaService
{
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ResendCooldown = TimeSpan.FromSeconds(60);
    private const int MaxAttempts = 5;

    private readonly CffVaultManagerDbContext _db;
    private readonly IEmailSender _emailSender;

    public EmailOtpMfaService(CffVaultManagerDbContext db, IEmailSender emailSender)
    {
        _db = db;
        _emailSender = emailSender;
    }

    public async Task EnableAsync(Guid userId, CancellationToken ct = default)
    {
        // Runs post-authentication, so the tenant query filter is resolved and correctly scopes
        // this to the caller's own user record (mirrors MfaSetupService.SetupTotpAsync).
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        if (user.EmailVerifiedAt is null)
        {
            throw new InvalidOperationException("Email must be verified before enabling Email OTP as an MFA factor.");
        }

        user.MfaEmailOtpEnabled = true;
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.MfaEmailOtpEnabled));
        await _db.SaveChangesAsync(ct);
    }

    public async Task DisableAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        user.MfaEmailOtpEnabled = false;
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.MfaEmailOtpDisabled));
        await _db.SaveChangesAsync(ct);
    }

    public async Task SendChallengeCodeAsync(Guid userId, string? ip, string? userAgent, CancellationToken ct = default)
    {
        // Called mid-login, before the tenant query filter can be resolved (mirrors
        // AuthenticationService's own pre-authentication lookups).
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || !user.MfaEmailOtpEnabled)
        {
            return;
        }

        // Materialized before ordering — see EmailVerificationService.ResendAsync for why
        // (SQLite provider used in tests cannot translate DateTimeOffset ordering to SQL).
        var codes = await _db.OneTimeCodes
            .Where(o => o.UserId == user.Id && o.Purpose == OtpPurpose.MfaLogin)
            .ToListAsync(ct);
        var lastRequested = codes.OrderByDescending(o => o.CreatedAt).FirstOrDefault();
        if (lastRequested is not null && DateTimeOffset.UtcNow - lastRequested.CreatedAt < ResendCooldown)
        {
            return;
        }

        string code = OneTimeCodeHasher.GenerateNumericCode();
        var entry = new OneTimeCode(
            Guid.NewGuid(),
            user.Id,
            OtpPurpose.MfaLogin,
            OneTimeCodeHasher.Hash(code),
            DateTimeOffset.UtcNow.Add(CodeLifetime),
            MaxAttempts,
            ipAddress: ip,
            userAgent: userAgent);

        _db.OneTimeCodes.Add(entry);
        WriteAudit(user, AuditAction.EmailOtpRequested, ip, userAgent);
        await _db.SaveChangesAsync(ct);

        await _emailSender.SendAsync(
            user.Email,
            "Codice di accesso — CffVaultManager",
            $"Il tuo codice per completare l'accesso è: {code}\n\nScade tra {CodeLifetime.TotalMinutes:0} minuti. " +
            "Se non hai richiesto questo accesso, ignora questa email e valuta di cambiare la tua master password.",
            ct);
    }

    public async Task<bool> VerifyChallengeCodeAsync(Guid userId, string code, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || !user.MfaEmailOtpEnabled)
        {
            return false;
        }

        var codes = await _db.OneTimeCodes
            .Where(o => o.UserId == user.Id && o.Purpose == OtpPurpose.MfaLogin && o.ConsumedAt == null)
            .ToListAsync(ct);
        var current = codes.OrderByDescending(o => o.CreatedAt).FirstOrDefault();

        if (current is null || current.ExpiresAt <= DateTimeOffset.UtcNow || current.AttemptCount >= current.MaxAttempts)
        {
            WriteAudit(user, AuditAction.EmailOtpFailed, ip, userAgent);
            await _db.SaveChangesAsync(ct);
            return false;
        }

        current.AttemptCount++;

        if (!OneTimeCodeHasher.Verify(code, current.CodeHash))
        {
            WriteAudit(user, AuditAction.EmailOtpFailed, ip, userAgent);
            await _db.SaveChangesAsync(ct);
            return false;
        }

        current.ConsumedAt = DateTimeOffset.UtcNow;
        WriteAudit(user, AuditAction.EmailOtpVerified, ip, userAgent);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    private void WriteAudit(User user, AuditAction action, string? ip, string? userAgent) =>
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, action, ipAddress: ip, userAgent: userAgent));
}
