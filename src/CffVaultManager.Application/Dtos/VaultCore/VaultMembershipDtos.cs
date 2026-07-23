using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.VaultCore;

/// <summary>
/// A member's access to an organization vault. Carries no wrapped-key material — only metadata.
/// </summary>
public sealed record VaultMembershipDto(Guid Id, Guid VaultId, Guid UserId, VaultPermission Permission, DateTimeOffset CreatedAt);

/// <summary>
/// The caller's own membership row on an organization vault, including their wrapped DEK — safe to
/// return because a caller can only ever request their own row, never another member's (see
/// <see cref="IVaultMembershipService.GetMyMembershipAsync"/>). The client needs this to unwrap the
/// vault's DEK when opening it; <see cref="VaultMembershipDto"/> (the general member list, visible
/// to every active member) deliberately omits key material for that reason.
/// </summary>
public sealed record MyVaultMembershipDto(Guid Id, Guid VaultId, VaultPermission Permission, byte[] WrappedVaultDek, byte[] EphemeralPublicKey, DateTimeOffset CreatedAt);

/// <summary>
/// Invites a user to an organization vault. <see cref="WrappedVaultDek"/> and
/// <see cref="EphemeralPublicKey"/> are computed client-side (ECIES over X25519) and stored opaquely.
/// </summary>
public sealed record CreateMembershipRequest(Guid UserId, VaultPermission Permission, byte[] WrappedVaultDek, byte[] EphemeralPublicKey);

/// <summary>An item re-encrypted under a rotated vault DEK. <see cref="EncryptedPayload"/> is opaque ciphertext.</summary>
public sealed record ReencryptedItem(Guid ItemId, byte[] EncryptedPayload);

/// <summary>The rewrapped DEK for a remaining member after a rotation. All byte arrays are opaque to the server.</summary>
public sealed record NewMembership(Guid UserId, byte[] WrappedVaultDek, byte[] EphemeralPublicKey);

/// <summary>
/// Revokes a member and rotates the vault DEK in one operation: <see cref="ReencryptedItems"/> must
/// cover exactly the vault's current items and <see cref="NewMemberships"/> exactly the remaining
/// active members (see docs/features/sharing-access-control.md).
/// </summary>
public sealed record RevokeMembershipRequest(Guid RevokedUserId, IReadOnlyList<ReencryptedItem> ReencryptedItems, IReadOnlyList<NewMembership> NewMemberships);

/// <summary>
/// A user's long-term X25519 public key, mediated by the server for client-side wrapping.
/// <see cref="UserId"/> is included so the by-email lookup can also resolve the id an organization-
/// vault invite needs (<see cref="CreateMembershipRequest"/> takes a <see cref="Guid"/>, not an
/// email — unlike per-item sharing, whose server-side email resolution never has to hand the id
/// back to the client).
/// </summary>
public sealed record PublicKeyDto(byte[] PublicKey, Guid UserId);
