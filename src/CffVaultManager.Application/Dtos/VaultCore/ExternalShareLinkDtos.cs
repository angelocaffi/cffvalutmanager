namespace CffVaultManager.Application.Dtos.VaultCore;

/// <summary>Metadata about an external share link — never includes the decryption key, which the server never sees.</summary>
public sealed record ExternalShareLinkDto(Guid Id, Guid VaultItemId, string Token, DateTimeOffset ExpiresAt, DateTimeOffset CreatedAt);

/// <summary>
/// <see cref="EncryptedPayload"/> is a snapshot re-encrypted client-side with a one-off key that
/// never reaches the server. <see cref="ExpiresInMinutes"/> is clamped server-side to a sane range.
/// </summary>
public sealed record CreateExternalShareLinkRequest(byte[] EncryptedPayload, int ExpiresInMinutes);

/// <summary>What the anonymous recipient fetches — no item id, owner, or other metadata, just the ciphertext and its expiry.</summary>
public sealed record ExternalShareLinkContentDto(byte[] EncryptedPayload, DateTimeOffset ExpiresAt);
