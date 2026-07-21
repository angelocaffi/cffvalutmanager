namespace CffVaultManager.Application.Dtos.VaultCore;

/// <summary>
/// Organizational tag metadata within a vault. The name is plaintext metadata.
/// </summary>
public sealed record TagDto(Guid Id, string Name);

public sealed record CreateTagRequest(string Name);

public sealed record RenameTagRequest(string Name);
