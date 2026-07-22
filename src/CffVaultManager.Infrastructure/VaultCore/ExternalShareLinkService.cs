using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <inheritdoc cref="IExternalShareLinkService"/>
internal sealed class ExternalShareLinkService : IExternalShareLinkService
{
    private const int MinExpiresInMinutes = 1;
    private const int MaxExpiresInMinutes = 7 * 24 * 60; // 7 days

    private readonly CffVaultManagerDbContext _db;

    public ExternalShareLinkService(CffVaultManagerDbContext db) => _db = db;

    public async Task<ExternalShareLinkDto> CreateAsync(Guid vaultId, Guid itemId, Guid callerId, CreateExternalShareLinkRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var (vault, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);
        if (!permission.CanWrite())
        {
            throw new InsufficientVaultPermissionException();
        }

        var item = await _db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId && i.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Item not found.");

        if (item.IsDeleted)
        {
            throw new InvalidOperationException("Cannot share a deleted item; restore it first.");
        }

        int expiresInMinutes = Math.Clamp(request.ExpiresInMinutes, MinExpiresInMinutes, MaxExpiresInMinutes);

        var link = new ExternalShareLink(
            Guid.NewGuid(),
            vault.TenantId,
            itemId,
            callerId,
            GenerateToken(),
            request.EncryptedPayload,
            DateTimeOffset.UtcNow.AddMinutes(expiresInMinutes));

        _db.ExternalShareLinks.Add(link);
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), vault.TenantId, callerId, AuditAction.ExternalShareLinkCreated, itemId));
        await _db.SaveChangesAsync(ct);

        return ToDto(link);
    }

    public async Task<ExternalShareLinkContentDto?> GetByTokenAsync(string token, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        // No ITenantContext is resolved on this anonymous path — same legitimate bypass as
        // AuthenticationService.LoginAsync/PreloginAsync, looked up by a single globally-unique
        // random token, never a list/enumeration.
        var link = await _db.ExternalShareLinks.IgnoreQueryFilters().FirstOrDefaultAsync(l => l.Token == token, ct);
        if (link is null)
        {
            return null;
        }

        if (link.IsExpiredOrRevoked(DateTimeOffset.UtcNow))
        {
            // Self-cleaning, and never distinguish "expired"/"revoked" from "never existed" to the caller.
            _db.ExternalShareLinks.Remove(link);
            await _db.SaveChangesAsync(ct);
            return null;
        }

        return new ExternalShareLinkContentDto(link.EncryptedPayload, link.ExpiresAt);
    }

    public async Task RevokeAsync(Guid vaultId, Guid itemId, Guid linkId, Guid callerId, CancellationToken ct = default)
    {
        var (vault, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);
        if (!permission.CanWrite())
        {
            throw new InsufficientVaultPermissionException();
        }

        var link = await _db.ExternalShareLinks.FirstOrDefaultAsync(
            l => l.Id == linkId && l.VaultItemId == itemId && l.RevokedAt == null, ct)
            ?? throw new KeyNotFoundException("Share link not found.");

        link.Revoke();
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), vault.TenantId, callerId, AuditAction.ExternalShareLinkRevoked, itemId));
        await _db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ExternalShareLinkDto>> ListForItemAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);

        // Materialized before filtering/ordering by ExpiresAt: EF Core's SQLite provider (used in
        // tests) cannot translate relational comparisons on a DateTimeOffset column to SQL — same
        // fix as VaultItemService.ListAsync.
        var links = await _db.ExternalShareLinks
            .Where(l => l.VaultItemId == itemId && l.RevokedAt == null)
            .Select(l => new ExternalShareLinkDto(l.Id, l.VaultItemId, l.Token, l.ExpiresAt, l.CreatedAt))
            .ToListAsync(ct);

        return links.Where(l => l.ExpiresAt > DateTimeOffset.UtcNow).OrderByDescending(l => l.CreatedAt).ToList();
    }

    private static string GenerateToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static ExternalShareLinkDto ToDto(ExternalShareLink link) =>
        new(link.Id, link.VaultItemId, link.Token, link.ExpiresAt, link.CreatedAt);
}
