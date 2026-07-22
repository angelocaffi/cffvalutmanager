namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Sets the caller's long-term X25519 keypair, used for ECIES-style sharing (organization-vault
/// memberships today; per-item sharing eventually — see docs/features/sharing-access-control.md).
/// Set-once: there is no rotation yet, since anything already wrapped for the old public key would
/// be orphaned by replacing it.
/// </summary>
public interface IKeyPairService
{
    Task SetKeyPairAsync(Guid userId, byte[] publicKey, byte[] encryptedPrivateKey, CancellationToken ct = default);
}
