using CffVaultManager.Application.Abstractions;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <inheritdoc cref="IKeyPairService"/>
internal sealed class KeyPairService : IKeyPairService
{
    private readonly CffVaultManagerDbContext _db;

    public KeyPairService(CffVaultManagerDbContext db) => _db = db;

    public async Task SetKeyPairAsync(Guid userId, byte[] publicKey, byte[] encryptedPrivateKey, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        if (user.PublicKey is not null)
        {
            throw new InvalidOperationException("A key pair has already been generated for this account.");
        }

        user.PublicKey = publicKey;
        user.EncryptedPrivateKey = encryptedPrivateKey;
        await _db.SaveChangesAsync(ct);
    }
}
