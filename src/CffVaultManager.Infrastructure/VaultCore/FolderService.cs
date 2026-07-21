using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Folder management scoped to a vault the caller can access (personal or organization). Access and
/// effective permission are resolved through <see cref="VaultAccessGuard"/>; writes require
/// <see cref="VaultPermission.ReadWrite"/>. Folder names are kept unique per vault by both a
/// proactive check and a database unique index (the <see cref="DbUpdateException"/> fallback closes
/// the race).
/// </summary>
internal sealed class FolderService : IFolderService
{
    private readonly CffVaultManagerDbContext _db;

    public FolderService(CffVaultManagerDbContext db) => _db = db;

    public async Task<FolderDto> CreateAsync(Guid vaultId, Guid callerId, CreateFolderRequest request, CancellationToken ct = default)
    {
        var (vault, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);
        if (permission != VaultPermission.ReadWrite) throw new InsufficientVaultPermissionException();

        if (await _db.Folders.AnyAsync(f => f.VaultId == vaultId && f.Name == request.Name, ct))
        {
            throw new InvalidOperationException("A folder with this name already exists in this vault.");
        }

        var folder = new Folder(Guid.NewGuid(), vault.TenantId, vaultId, request.Name);
        _db.Folders.Add(folder);
        WriteAudit(vault.TenantId, callerId, AuditAction.Created);
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
        await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);

        return await _db.Folders
            .Where(f => f.VaultId == vaultId)
            .OrderBy(f => f.Name)
            .Select(f => new FolderDto(f.Id, f.Name))
            .ToListAsync(ct);
    }

    public async Task<FolderDto> RenameAsync(Guid vaultId, Guid folderId, Guid callerId, RenameFolderRequest request, CancellationToken ct = default)
    {
        var (vault, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);
        if (permission != VaultPermission.ReadWrite) throw new InsufficientVaultPermissionException();

        var folder = await _db.Folders.FirstOrDefaultAsync(f => f.Id == folderId && f.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Folder not found.");

        if (await _db.Folders.AnyAsync(f => f.VaultId == vaultId && f.Name == request.Name && f.Id != folderId, ct))
        {
            throw new InvalidOperationException("A folder with this name already exists in this vault.");
        }

        folder.Name = request.Name;
        WriteAudit(vault.TenantId, callerId, AuditAction.Updated);
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
        var (vault, permission) = await VaultAccessGuard.GetAccessibleVaultAsync(_db, vaultId, callerId, ct);
        if (permission != VaultPermission.ReadWrite) throw new InsufficientVaultPermissionException();

        var folder = await _db.Folders.FirstOrDefaultAsync(f => f.Id == folderId && f.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Folder not found.");

        // The Folder FK on VaultItem is OnDelete(SetNull), so removing the folder simply nulls
        // FolderId on its items at the database level — the items themselves are untouched.
        _db.Folders.Remove(folder);
        WriteAudit(vault.TenantId, callerId, AuditAction.Deleted);
        await _db.SaveChangesAsync(ct);
    }

    // Folder actions have no dedicated audit FK (AuditLogEntry.VaultItemId only targets vault
    // items), so entries here record tenant/caller/action without a linked entity id.
    private void WriteAudit(Guid tenantId, Guid callerId, AuditAction action) =>
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), tenantId, callerId, action));
}
