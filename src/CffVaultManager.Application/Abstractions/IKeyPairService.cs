using CffVaultManager.Application.Dtos.Authentication;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Sets and retrieves the caller's long-term X25519 keypair, used for ECIES-style sharing
/// (organization-vault memberships and per-item sharing — see
/// docs/features/sharing-access-control.md). Set-once: there is no rotation yet, since anything
/// already wrapped for the old public key would be orphaned by replacing it.
/// </summary>
public interface IKeyPairService
{
    Task SetKeyPairAsync(Guid userId, byte[] publicKey, byte[] encryptedPrivateKey, CancellationToken ct = default);

    /// <summary>
    /// Returns the caller's own keypair so their client can unwrap something wrapped for them
    /// (e.g. a shared item's key). Not found if no keypair has been generated yet.
    /// </summary>
    Task<KeyPairDto> GetOwnKeyPairAsync(Guid userId, CancellationToken ct = default);
}
