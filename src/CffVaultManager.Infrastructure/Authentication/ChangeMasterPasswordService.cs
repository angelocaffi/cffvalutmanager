using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Master-password change: re-encrypts only the DEK (never the vault items themselves), per
/// docs/security-model.md. The client derives the new KEK, re-wraps the existing DEK with it, and
/// sends the new EncryptedDek/salt/KDF parameters already wrapped — the server never sees a
/// master password, old or new, in the clear, and never touches a single vault item.
/// </summary>
internal sealed class ChangeMasterPasswordService : IChangeMasterPasswordService
{
    private readonly CffVaultManagerDbContext _db;
    private readonly IAuthHashHasher _authHashHasher;
    private readonly IRefreshTokenService _refreshTokens;

    public ChangeMasterPasswordService(CffVaultManagerDbContext db, IAuthHashHasher authHashHasher, IRefreshTokenService refreshTokens)
    {
        _db = db;
        _authHashHasher = authHashHasher;
        _refreshTokens = refreshTokens;
    }

    public async Task<bool> ChangeMasterPasswordAsync(Guid userId, ChangeMasterPasswordRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.NewEncryptedDek is null || request.NewEncryptedDek.Length == 0)
        {
            throw new ArgumentException("NewEncryptedDek must not be empty.", nameof(request));
        }

        if (request.NewMasterPasswordSalt is null || request.NewMasterPasswordSalt.Length == 0)
        {
            throw new ArgumentException("NewMasterPasswordSalt must not be empty.", nameof(request));
        }

        // Runs post-authentication, so the tenant query filter is resolved and correctly scopes
        // this to the caller's own user record (mirrors MfaSetupService).
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        if (user.MasterPasswordHash is null || !_authHashHasher.Verify(request.CurrentAuthHash, user.MasterPasswordHash))
        {
            return false;
        }

        user.MasterPasswordHash = _authHashHasher.Hash(request.NewAuthHash);
        user.EncryptedDek = request.NewEncryptedDek;
        user.MasterPasswordSalt = request.NewMasterPasswordSalt;
        user.KdfMemoryKb = request.NewKdfMemoryKb;
        user.KdfIterations = request.NewKdfIterations;
        user.KdfVersion = request.NewKdfVersion;

        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.MasterPasswordChanged));
        await _db.SaveChangesAsync(ct);

        // Every active session — including the caller's own — must re-authenticate with the new
        // master password afterward: old refresh tokens still validate at the token level, but
        // the client can no longer derive the KEK needed to unwrap the (now different) DEK
        // without the new master password anyway, so leaving them active buys nothing and a stale
        // stolen refresh token is exactly the scenario a password change is meant to shut out.
        await _refreshTokens.RevokeAllSessionsAsync(user.Id, user.TenantId, ct);

        return true;
    }
}
