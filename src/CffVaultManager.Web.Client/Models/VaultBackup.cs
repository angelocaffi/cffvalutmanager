namespace CffVaultManager.Web.Client.Models;

/// <summary>
/// Encrypted vault backup file format (docs/features/import-export.md). Deliberately a thin
/// wrapper around data the server already returns: every item's <see cref="VaultBackupItem.EncryptedPayload"/>
/// is copied verbatim from <c>VaultItemResponse.EncryptedPayload</c>, still AES-256-GCM-encrypted
/// with the vault's DEK — this file is never decrypted or re-encrypted by the export/import code,
/// only reassembled. It is therefore only restorable into an account that already holds the same
/// DEK (i.e. back into the account it came from); importing into a different account produces
/// items that fail to decrypt, which is expected, not a bug.
/// </summary>
public sealed record VaultBackupFile(
    int FormatVersion,
    DateTimeOffset ExportedAt,
    string VaultName,
    IReadOnlyList<VaultBackupFolder> Folders,
    IReadOnlyList<VaultBackupTag> Tags,
    IReadOnlyList<VaultBackupItem> Items);

public sealed record VaultBackupFolder(Guid Id, string Name);

public sealed record VaultBackupTag(Guid Id, string Name);

public sealed record VaultBackupItem(
    string Type,
    byte[] EncryptedPayload,
    Guid? FolderId,
    bool IsFavorite,
    IReadOnlyList<Guid> TagIds);
