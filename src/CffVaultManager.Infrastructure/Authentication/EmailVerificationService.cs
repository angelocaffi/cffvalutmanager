using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Email-ownership verification via a short numeric one-time code, reusing the <see
/// cref="OneTimeCode"/> entity scaffolded since Fase 0 for this and the (not yet built) Email OTP
/// MFA factor. The code is hashed at rest with HMAC-SHA256 (not Argon2id): unlike an auth hash or
/// a refresh token, this is a short-lived, single-purpose 6-digit value — the real defenses
/// against brute force are the short expiry, the per-code attempt cap, and IP rate limiting on
/// the HTTP endpoints, not an expensive hash, which would only slow down legitimate retries for no
/// real benefit against an attacker who already has a copy of the hashed row.
/// </summary>
internal sealed class EmailVerificationService : IEmailVerificationService
{
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ResendCooldown = TimeSpan.FromSeconds(60);
    private const int MaxAttempts = 5;
    private const int SaltLength = 16;
    private const int DigestLength = 32;

    private readonly CffVaultManagerDbContext _db;
    private readonly IEmailSender _emailSender;

    public EmailVerificationService(CffVaultManagerDbContext db, IEmailSender emailSender)
    {
        _db = db;
        _emailSender = emailSender;
    }

    public async Task RequestAsync(Guid userId, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        await GenerateAndSendAsync(user, ip, userAgent, ct);
    }

    public async Task ResendAsync(string email, string? ip, string? userAgent, CancellationToken ct = default)
    {
        // The tenant is not known from an email address alone (mirrors AuthenticationService's
        // pre-authentication login lookup): this is a legitimate cross-tenant existence check.
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user is null || user.EmailVerifiedAt is not null)
        {
            return;
        }

        // Materialized before ordering: EF Core's SQLite provider (used in tests) cannot
        // translate ordering/relational comparisons on a DateTimeOffset column to SQL — same fix
        // as VaultItemService.ListAsync and RefreshTokenService.ListActiveSessionsAsync.
        var codes = await _db.OneTimeCodes
            .Where(o => o.UserId == user.Id && o.Purpose == OtpPurpose.EmailVerification)
            .ToListAsync(ct);
        var lastRequested = codes.OrderByDescending(o => o.CreatedAt).FirstOrDefault();
        if (lastRequested is not null && DateTimeOffset.UtcNow - lastRequested.CreatedAt < ResendCooldown)
        {
            return;
        }

        await GenerateAndSendAsync(user, ip, userAgent, ct);
    }

    public async Task<bool> ConfirmAsync(string email, string code, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user is null)
        {
            // Unknown email leaves no audit trace, mirroring AuthenticationService.LoginAsync.
            return false;
        }

        var codes = await _db.OneTimeCodes
            .Where(o => o.UserId == user.Id && o.Purpose == OtpPurpose.EmailVerification && o.ConsumedAt == null)
            .ToListAsync(ct);
        var current = codes.OrderByDescending(o => o.CreatedAt).FirstOrDefault();

        if (current is null || current.ExpiresAt <= DateTimeOffset.UtcNow || current.AttemptCount >= current.MaxAttempts)
        {
            WriteAudit(user, AuditAction.EmailOtpFailed, ip, userAgent);
            await _db.SaveChangesAsync(ct);
            return false;
        }

        current.AttemptCount++;

        if (!VerifyCode(code, current.CodeHash))
        {
            WriteAudit(user, AuditAction.EmailOtpFailed, ip, userAgent);
            await _db.SaveChangesAsync(ct);
            return false;
        }

        current.ConsumedAt = DateTimeOffset.UtcNow;
        user.EmailVerifiedAt = DateTimeOffset.UtcNow;
        WriteAudit(user, AuditAction.EmailOtpVerified, ip, userAgent);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    private async Task GenerateAndSendAsync(User user, string? ip, string? userAgent, CancellationToken ct)
    {
        string code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        var entry = new OneTimeCode(
            Guid.NewGuid(),
            user.Id,
            OtpPurpose.EmailVerification,
            BuildStoredHash(code),
            DateTimeOffset.UtcNow.Add(CodeLifetime),
            MaxAttempts,
            ipAddress: ip,
            userAgent: userAgent);

        _db.OneTimeCodes.Add(entry);
        WriteAudit(user, AuditAction.EmailOtpRequested, ip, userAgent);
        await _db.SaveChangesAsync(ct);

        // Best-effort: a real transport's delivery failure here should not undo the
        // already-persisted code — not a concern yet with the current logging-only IEmailSender,
        // but worth revisiting (retry/queue) once a real one is plugged in.
        await _emailSender.SendAsync(
            user.Email,
            "Verifica il tuo indirizzo email — CffVaultManager",
            $"Il tuo codice di verifica è: {code}\n\nScade tra {CodeLifetime.TotalMinutes:0} minuti. Se non hai richiesto questa email, ignorala.",
            ct);
    }

    private void WriteAudit(User user, AuditAction action, string? ip, string? userAgent) =>
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, action, ipAddress: ip, userAgent: userAgent));

    private static byte[] BuildStoredHash(string code)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
        byte[] digest = HMACSHA256.HashData(salt, Encoding.UTF8.GetBytes(code));

        byte[] stored = new byte[SaltLength + DigestLength];
        salt.CopyTo(stored, 0);
        digest.CopyTo(stored, SaltLength);
        return stored;
    }

    private static bool VerifyCode(string code, byte[] storedHash)
    {
        if (storedHash.Length != SaltLength + DigestLength)
        {
            return false;
        }

        byte[] salt = storedHash.AsSpan(0, SaltLength).ToArray();
        byte[] expected = storedHash.AsSpan(SaltLength, DigestLength).ToArray();
        byte[] actual = HMACSHA256.HashData(salt, Encoding.UTF8.GetBytes(code));
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
