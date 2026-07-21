using CffVaultManager.Application.Dtos.Authentication;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Master-password change for an already-authenticated user. Re-encrypts only the DEK — never
/// any vault item — per docs/security-model.md.
/// </summary>
public interface IChangeMasterPasswordService
{
    /// <summary>
    /// Verifies <see cref="ChangeMasterPasswordRequest.CurrentAuthHash"/> and, only on a match,
    /// replaces the stored auth hash, wrapped DEK, salt and KDF parameters with the new ones the
    /// client already produced. Returns false (no changes made) if the current auth hash is
    /// wrong. On success, every active refresh-token session — including the caller's own — is
    /// revoked, since re-authenticating anywhere now requires the new master password anyway.
    /// </summary>
    Task<bool> ChangeMasterPasswordAsync(Guid userId, ChangeMasterPasswordRequest request, CancellationToken ct = default);
}
