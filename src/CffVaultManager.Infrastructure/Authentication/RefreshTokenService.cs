using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Issues and rotates opaque refresh tokens. The clear-text token is returned once and never
/// stored; only its SHA-256 hash is persisted, so a database leak yields no replayable token.
/// SHA-256 (not Argon2) is adequate here because the token is a full-entropy random value, not a
/// low-entropy secret vulnerable to brute force.
/// </summary>
internal sealed class RefreshTokenService : IRefreshTokenService
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromDays(14);
    private const int TokenLengthBytes = 32;

    private readonly CffVaultManagerDbContext _db;

    public RefreshTokenService(CffVaultManagerDbContext db) => _db = db;

    public async Task<IssuedRefreshToken> IssueAsync(Guid userId, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var (plain, entity) = CreateToken(userId, ip, userAgent);
        _db.RefreshTokens.Add(entity);
        await _db.SaveChangesAsync(ct);
        return new IssuedRefreshToken(plain, entity);
    }

    public async Task<IssuedRefreshToken?> ValidateAndRotateAsync(string plainToken, string? ip, string? userAgent, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(plainToken))
        {
            return null;
        }

        byte[] hash = Sha256(plainToken);
        var existing = await _db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == hash, ct);
        if (existing is null)
        {
            return null;
        }

        if (existing.RevokedAt is not null)
        {
            // Reuse of an already-rotated token: whoever presents it now is not the party that
            // legitimately rotated it earlier (a stolen token being replayed, most likely). Revoke
            // the entire descendant chain — including whatever token is currently active at its
            // end — so the compromise can't be used to keep a session alive; the real owner has to
            // log in again.
            await RevokeChainAsync(existing, ct);
            return null;
        }

        if (!existing.IsActive)
        {
            return null;
        }

        var (plain, replacement) = CreateToken(existing.UserId, ip, userAgent);

        // Revoke the presented token and link it to its successor so a later reuse of the same
        // token is detectable (the chain can be walked and invalidated).
        existing.RevokedAt = DateTimeOffset.UtcNow;
        existing.ReplacedByTokenId = replacement.Id;
        _db.RefreshTokens.Add(replacement);
        await _db.SaveChangesAsync(ct);

        return new IssuedRefreshToken(plain, replacement);
    }

    private async Task RevokeChainAsync(RefreshToken reusedToken, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        bool revokedAny = false;
        var current = reusedToken;
        while (current.ReplacedByTokenId is { } nextId)
        {
            var next = await _db.RefreshTokens.FirstOrDefaultAsync(t => t.Id == nextId, ct);
            if (next is null)
            {
                break;
            }

            if (next.RevokedAt is null)
            {
                next.RevokedAt = now;
                revokedAny = true;
            }

            current = next;
        }

        if (revokedAny)
        {
            // The caller isn't authenticated (a reused/stolen token, by definition), so the tenant
            // isn't known from context — looked up the same way AuthenticationService.LoginAsync
            // bypasses the tenant filter for its own pre-authentication user lookup.
            Guid? tenantId = await _db.Users.IgnoreQueryFilters()
                .Where(u => u.Id == reusedToken.UserId)
                .Select(u => (Guid?)u.TenantId)
                .FirstOrDefaultAsync(ct);

            _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), tenantId, reusedToken.UserId, AuditAction.SessionsRevoked));
        }

        await _db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ActiveSessionDto>> ListActiveSessionsAsync(Guid userId, CancellationToken ct = default)
    {
        // Materialized before filtering/ordering by ExpiresAt/CreatedAt: EF Core's SQLite provider
        // (used in tests) cannot translate relational comparisons or ORDER BY on a DateTimeOffset
        // column — see the same issue/fix in VaultItemService.ListAsync and AuditLogService.
        var tokens = await _db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ToListAsync(ct);

        var now = DateTimeOffset.UtcNow;
        return tokens
            .Where(t => t.ExpiresAt > now)
            .OrderByDescending(t => t.CreatedAt)
            .Select(t => new ActiveSessionDto(t.Id, t.CreatedAt, t.ExpiresAt, t.CreatedByIp, t.CreatedByUserAgent))
            .ToList();
    }

    public async Task RevokeSessionAsync(Guid userId, Guid? tenantId, Guid sessionId, CancellationToken ct = default)
    {
        var token = await _db.RefreshTokens.FirstOrDefaultAsync(t => t.Id == sessionId && t.UserId == userId, ct)
            ?? throw new KeyNotFoundException("Session not found.");

        if (!token.IsActive)
        {
            return;
        }

        token.RevokedAt = DateTimeOffset.UtcNow;
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), tenantId, userId, AuditAction.SessionsRevoked));
        await _db.SaveChangesAsync(ct);
    }

    public async Task RevokeAllSessionsAsync(Guid userId, Guid? tenantId, CancellationToken ct = default)
    {
        var tokens = await _db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ToListAsync(ct);

        if (tokens.Count == 0)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        foreach (var token in tokens)
        {
            token.RevokedAt = now;
        }

        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), tenantId, userId, AuditAction.SessionsRevoked));
        await _db.SaveChangesAsync(ct);
    }

    private static (string PlainToken, RefreshToken Entity) CreateToken(Guid userId, string? ip, string? userAgent)
    {
        byte[] raw = RandomNumberGenerator.GetBytes(TokenLengthBytes);
        string plain = Convert.ToHexString(raw);
        var entity = new RefreshToken(
            Guid.NewGuid(),
            userId,
            Sha256(plain),
            DateTimeOffset.UtcNow.Add(Lifetime),
            createdByIp: ip,
            createdByUserAgent: userAgent);

        return (plain, entity);
    }

    private static byte[] Sha256(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
}
