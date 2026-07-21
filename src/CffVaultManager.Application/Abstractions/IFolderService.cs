using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Manages folders inside a caller-owned personal vault. Access is strictly owner-only: a vault the
/// caller does not own (or an organization vault) is reported as not found, never as forbidden.
/// Folder names are unique per vault; a duplicate name is a conflict.
/// </summary>
public interface IFolderService
{
    Task<FolderDto> CreateAsync(Guid vaultId, Guid callerId, CreateFolderRequest request, CancellationToken ct = default);

    Task<IReadOnlyList<FolderDto>> ListAsync(Guid vaultId, Guid callerId, CancellationToken ct = default);

    Task<FolderDto> RenameAsync(Guid vaultId, Guid folderId, Guid callerId, RenameFolderRequest request, CancellationToken ct = default);

    Task DeleteAsync(Guid vaultId, Guid folderId, Guid callerId, CancellationToken ct = default);
}
