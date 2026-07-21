namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>A registered WebAuthn credential, as exposed to its owner for device management — never the public key or credential ID.</summary>
public sealed record WebAuthnCredentialDto(Guid Id, string? Nickname, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);
