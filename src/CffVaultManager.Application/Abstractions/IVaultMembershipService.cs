using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Manages membership of organization vaults within a single tenant (see
/// docs/features/sharing-access-control.md). All wrapped-key material arrives precomputed from the
/// client and is stored opaquely: the server never performs any cryptography on it and never sees a
/// private key or an unwrapped DEK. Every target user and vault is verified to belong to the
/// caller's own tenant; a cross-tenant reference is reported as not found, never as forbidden, so
/// tenant membership is not leaked.
/// </summary>
public interface IVaultMembershipService
{
    /// <summary>
    /// Returns the target user's long-term public key so the caller's client can wrap the vault DEK
    /// for them. Not found if the user does not exist or is in another tenant.
    /// </summary>
    Task<PublicKeyDto> GetPublicKeyAsync(Guid targetUserId, Guid callerId, Guid callerTenantId, CancellationToken ct = default);

    /// <summary>
    /// Same as <see cref="GetPublicKeyAsync"/>, looked up by email instead of user id — used to
    /// find a per-item share recipient (see docs/features/sharing-access-control.md), where the
    /// sharer knows the recipient's email but not their id.
    /// </summary>
    Task<PublicKeyDto> GetPublicKeyByEmailAsync(string email, Guid callerTenantId, CancellationToken ct = default);

    /// <summary>
    /// Grants a same-tenant user access to an organization vault, storing the client-provided
    /// wrapped DEK. The vault must be an organization vault the caller (an Admin) belongs to.
    /// </summary>
    Task<VaultMembershipDto> InviteAsync(Guid vaultId, Guid callerId, Guid callerTenantId, CreateMembershipRequest request, CancellationToken ct = default);

    /// <summary>
    /// Revokes a member and rotates the vault DEK atomically: re-encrypts every current item and
    /// rewraps the DEK for every remaining active member (see the exact coverage rules in
    /// docs/features/sharing-access-control.md).
    /// </summary>
    Task RevokeAsync(Guid vaultId, Guid callerId, Guid callerTenantId, RevokeMembershipRequest request, CancellationToken ct = default);

    /// <summary>Lists the active members of a vault the caller can access.</summary>
    Task<IReadOnlyList<VaultMembershipDto>> ListMembersAsync(Guid vaultId, Guid callerId, Guid callerTenantId, CancellationToken ct = default);

    /// <summary>
    /// Returns the caller's own active membership row for an organization vault, including the
    /// wrapped DEK material needed to unlock it — never another member's. Not found if the vault
    /// doesn't exist, isn't an organization vault, or the caller has no active membership on it.
    /// </summary>
    Task<MyVaultMembershipDto> GetMyMembershipAsync(Guid vaultId, Guid callerId, Guid callerTenantId, CancellationToken ct = default);
}
