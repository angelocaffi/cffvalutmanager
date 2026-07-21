namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Request to provision a brand-new tenant together with its first Admin user.
/// All cryptographic fields are produced on the client and stored as-is; the server
/// never sees the master password or the plaintext DEK.
/// </summary>
public sealed record ProvisionTenantRequest(
    string TenantName,
    string TenantSlug,
    string AdminEmail,
    byte[] AuthHash,
    byte[] EncryptedDek,
    byte[] MasterPasswordSalt,
    int KdfMemoryKb,
    int KdfIterations,
    int KdfVersion,
    string? PlanName = null,
    int? MaxUsers = null,
    long? MaxStorageBytes = null);
