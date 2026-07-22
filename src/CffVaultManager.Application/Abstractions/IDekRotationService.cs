using CffVaultManager.Application.Dtos.Authentication;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Rotates the caller's personal-vault DEK independently of the master password (see
/// docs/features/encryption-key-management.md "Rotazione DEK") — distinct from
/// <see cref="IChangeMasterPasswordService"/>, which re-wraps the *same* DEK under a new KEK. Useful
/// as a standalone security-hygiene action (e.g. suspected key exposure) without forcing a master
/// password change.
/// </summary>
public interface IDekRotationService
{
    /// <summary>
    /// Replaces the caller's wrapped DEK and every current, non-deleted, non-shared personal-vault
    /// item's ciphertext atomically. <see cref="RotateDekRequest.ReencryptedItems"/> must cover
    /// exactly that set — a mismatch throws <see cref="InvalidOperationException"/>.
    /// </summary>
    Task RotateDekAsync(Guid userId, RotateDekRequest request, CancellationToken ct = default);
}
