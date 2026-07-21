using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Folder management scoped to a caller-owned personal vault. Ownership is enforced through
/// <see cref="VaultAccessGuard"/>; folder names are kept unique per vault by both a proactive
/// check and a database unique index (the <see cref="DbUpdateException"/> fallback closes the race).
/// </summary>
internal sealed class FolderService : IFolderService
{
    private readonly CffVaultManagerDbContext _db;

    public FolderService(CffVaultManagerDbContext db) => _db = db;

    public async Task<FolderDto> CreateAsync(Guid vaultId, Guid callerId, CreateFolderRequest request, CancellationToken ct = default)
    {
        var vault = await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        if (await _db.Folders.AnyAsync(f => f.VaultId == vaultId && f.Name == request.Name, ct))
        {
            throw new InvalidOperationException("A folder with this name already exists in this vault.");
        }

        var folder = new Folder(Guid.NewGuid(), vault.TenantId, vaultId, request.Name);
        _db.Folders.Add(folder);
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            throw new InvalidOperationException("A folder with this name already exists in this vault.");
        }

        return new FolderDto(folder.Id, folder.Name);
    }

    public async Task<IReadOnlyList<FolderDto>> ListAsync(Guid vaultId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        return await _db.Folders
            .Where(f => f.VaultId == vaultId)
            .OrderBy(f => f.Name)
            .Select(f => new FolderDto(f.Id, f.Name))
            .ToListAsync(ct);
    }

    public async Task<FolderDto> RenameAsync(Guid vaultId, Guid folderId, Guid callerId, RenameFolderRequest request, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var folder = await _db.Folders.FirstOrDefaultAsync(f => f.Id == folderId && f.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Folder not found.");

        if (await _db.Folders.AnyAsync(f => f.VaultId == vaultId && f.Name == request.Name && f.Id != folderId, ct))
        {
            throw new InvalidOperationException("A folder with this name already exists in this vault.");
        }

        folder.Name = request.Name;
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            throw new InvalidOperationException("A folder with this name already exists in this vault.");
        }

        return new FolderDto(folder.Id, folder.Name);
    }

    public async Task DeleteAsync(Guid vaultId, Guid folderId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var folder = await _db.Folders.FirstOrDefaultAsync(f => f.Id == folderId && f.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Folder not found.");

        // The Folder FK on VaultItem is OnDelete(SetNull), so removing the folder simply nulls
        // FolderId on its items at the database level — the items themselves are untouched.
        _db.Folders.Remove(folder);
        await _db.SaveChangesAsync(ct);
    }
}
