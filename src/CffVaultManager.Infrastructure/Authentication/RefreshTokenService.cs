using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
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
        if (existing is null || !existing.IsActive)
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
