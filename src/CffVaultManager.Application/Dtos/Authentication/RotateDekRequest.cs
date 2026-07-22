using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Rotates the caller's personal DEK without changing the master password: a fresh random DEK,
/// wrapped with the unchanged KEK, plus every current personal-vault item re-encrypted with it
/// (see docs/features/encryption-key-management.md "Rotazione DEK"). <see cref="ReencryptedItems"/>
/// must cover exactly the caller's current, non-deleted, non-shared personal-vault items — an
/// already-shared item uses its own dedicated key (see ItemMembership) and is unaffected by this.
/// </summary>
public sealed record RotateDekRequest(byte[] NewEncryptedDek, IReadOnlyList<ReencryptedItem> ReencryptedItems);
