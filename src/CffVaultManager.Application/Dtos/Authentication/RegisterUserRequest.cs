using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Request to register an additional user inside an already-provisioned tenant.
/// The target tenant is never taken from this request: it is always the caller's tenant
/// (see <see cref="Abstractions.IUserRegistrationService"/>), to prevent cross-tenant injection.
/// </summary>
public sealed record RegisterUserRequest(
    string Email,
    UserRole Role,
    byte[] AuthHash,
    byte[] EncryptedDek,
    byte[] MasterPasswordSalt,
    int KdfMemoryKb,
    int KdfIterations,
    int KdfVersion);
