using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Tag management scoped to a caller-owned personal vault. Ownership is enforced through
/// <see cref="VaultAccessGuard"/>; tag names are kept unique per vault by both a proactive check
/// and a database unique index (the <see cref="DbUpdateException"/> fallback closes the race).
/// </summary>
internal sealed class TagService : ITagService
{
    private readonly CffVaultManagerDbContext _db;

    public TagService(CffVaultManagerDbContext db) => _db = db;

    public async Task<TagDto> CreateAsync(Guid vaultId, Guid callerId, CreateTagRequest request, CancellationToken ct = default)
    {
        var vault = await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        if (await _db.Tags.AnyAsync(t => t.VaultId == vaultId && t.Name == request.Name, ct))
        {
            throw new InvalidOperationException("A tag with this name already exists in this vault.");
        }

        var tag = new Tag(Guid.NewGuid(), vault.TenantId, vaultId, request.Name);
        _db.Tags.Add(tag);
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            throw new InvalidOperationException("A tag with this name already exists in this vault.");
        }

        return new TagDto(tag.Id, tag.Name);
    }

    public async Task<IReadOnlyList<TagDto>> ListAsync(Guid vaultId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        return await _db.Tags
            .Where(t => t.VaultId == vaultId)
            .OrderBy(t => t.Name)
            .Select(t => new TagDto(t.Id, t.Name))
            .ToListAsync(ct);
    }

    public async Task<TagDto> RenameAsync(Guid vaultId, Guid tagId, Guid callerId, RenameTagRequest request, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var tag = await _db.Tags.FirstOrDefaultAsync(t => t.Id == tagId && t.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Tag not found.");

        if (await _db.Tags.AnyAsync(t => t.VaultId == vaultId && t.Name == request.Name && t.Id != tagId, ct))
        {
            throw new InvalidOperationException("A tag with this name already exists in this vault.");
        }

        tag.Name = request.Name;
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            throw new InvalidOperationException("A tag with this name already exists in this vault.");
        }

        return new TagDto(tag.Id, tag.Name);
    }

    public async Task DeleteAsync(Guid vaultId, Guid tagId, Guid callerId, CancellationToken ct = default)
    {
        await VaultAccessGuard.GetOwnedPersonalVaultAsync(_db, vaultId, callerId, ct);

        var tag = await _db.Tags.FirstOrDefaultAsync(t => t.Id == tagId && t.VaultId == vaultId, ct)
            ?? throw new KeyNotFoundException("Tag not found.");

        // VaultItemTag rows cascade on tag delete (see VaultItemTagConfiguration).
        _db.Tags.Remove(tag);
        await _db.SaveChangesAsync(ct);
    }
}
