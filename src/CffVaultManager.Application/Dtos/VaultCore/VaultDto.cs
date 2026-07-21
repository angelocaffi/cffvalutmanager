namespace CffVaultManager.Application.Dtos.VaultCore;

/// <summary>
/// Non-sensitive metadata about a vault. Never carries encrypted material or secrets.
/// </summary>
public sealed record VaultDto(Guid Id, string Name, bool IsOrganizationVault);
