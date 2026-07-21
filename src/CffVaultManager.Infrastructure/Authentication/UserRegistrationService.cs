using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Registers an additional user inside the caller's tenant. The new user is always bound to
/// <c>callingTenantId</c>; any tenant hint in the request is ignored to prevent cross-tenant
/// user injection.
/// </summary>
internal sealed class UserRegistrationService : IUserRegistrationService
{
    private readonly CffVaultManagerDbContext _db;
    private readonly IAuthHashHasher _authHashHasher;

    public UserRegistrationService(CffVaultManagerDbContext db, IAuthHashHasher authHashHasher)
    {
        _db = db;
        _authHashHasher = authHashHasher;
    }

    public async Task<Guid> RegisterInTenantAsync(
        RegisterUserRequest request,
        Guid callingUserId,
        UserRole callingUserRole,
        Guid callingTenantId,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (callingUserRole != UserRole.Admin)
        {
            throw new UnauthorizedAccessException("Only a tenant Admin may register users.");
        }

        var userId = Guid.NewGuid();
        var user = User.CreateTenantUser(
            userId,
            callingTenantId,
            request.Email,
            request.Role,
            request.EncryptedDek,
            masterPasswordHash: _authHashHasher.Hash(request.AuthHash),
            masterPasswordSalt: request.MasterPasswordSalt,
            kdfMemoryKb: request.KdfMemoryKb,
            kdfIterations: request.KdfIterations,
            kdfVersion: request.KdfVersion);

        _db.Users.Add(user);
        _db.Vaults.Add(new Vault(Guid.NewGuid(), callingTenantId, "Personale", isOrganizationVault: false, ownerUserId: userId));
        await _db.SaveChangesAsync(ct);

        return userId;
    }
}
