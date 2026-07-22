using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Time-limited anonymous links to a single vault item (see docs/features/sharing-access-control.md
/// "Link di condivisione esterna"). The server only ever stores and returns opaque ciphertext — the
/// one-off decryption key is generated client-side and never sent here.
/// </summary>
public interface IExternalShareLinkService
{
    Task<ExternalShareLinkDto> CreateAsync(Guid vaultId, Guid itemId, Guid callerId, CreateExternalShareLinkRequest request, CancellationToken ct = default);

    /// <summary>
    /// Anonymous lookup by token — no caller identity involved. Returns null for an unknown,
    /// expired, or revoked token, uniformly (an expired/revoked row is deleted on this call).
    /// </summary>
    Task<ExternalShareLinkContentDto?> GetByTokenAsync(string token, CancellationToken ct = default);

    Task RevokeAsync(Guid vaultId, Guid itemId, Guid linkId, Guid callerId, CancellationToken ct = default);

    Task<IReadOnlyList<ExternalShareLinkDto>> ListForItemAsync(Guid vaultId, Guid itemId, Guid callerId, CancellationToken ct = default);
}
