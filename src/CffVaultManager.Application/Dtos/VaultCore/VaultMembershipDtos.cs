using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.VaultCore;

/// <summary>
/// A member's access to an organization vault. Carries no wrapped-key material — only metadata.
/// </summary>
public sealed record VaultMembershipDto(Guid Id, Guid VaultId, Guid UserId, VaultPermission Permission, DateTimeOffset CreatedAt);

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

/// <summary>A user's long-term X25519 public key, mediated by the server for client-side wrapping.</summary>
public sealed record PublicKeyDto(byte[] PublicKey);
