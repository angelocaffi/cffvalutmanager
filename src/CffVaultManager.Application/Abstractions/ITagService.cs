using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Manages tags inside a caller-owned personal vault. Access is strictly owner-only: a vault the
/// caller does not own (or an organization vault) is reported as not found, never as forbidden.
/// Tag names are unique per vault; a duplicate name is a conflict.
/// </summary>
public interface ITagService
{
    Task<TagDto> CreateAsync(Guid vaultId, Guid callerId, CreateTagRequest request, CancellationToken ct = default);

    Task<IReadOnlyList<TagDto>> ListAsync(Guid vaultId, Guid callerId, CancellationToken ct = default);

    Task<TagDto> RenameAsync(Guid vaultId, Guid tagId, Guid callerId, RenameTagRequest request, CancellationToken ct = default);

    Task DeleteAsync(Guid vaultId, Guid tagId, Guid callerId, CancellationToken ct = default);
}
