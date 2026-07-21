namespace CffVaultManager.Application.Dtos.VaultCore;

/// <summary>
/// Organizational folder metadata within a vault. The name is plaintext metadata.
/// </summary>
public sealed record FolderDto(Guid Id, string Name);

public sealed record CreateFolderRequest(string Name);

public sealed record RenameFolderRequest(string Name);
