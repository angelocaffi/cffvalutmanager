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
    private readonly IEmailVerificationService? _emailVerification;

    // emailVerification is optional so DI resolves it to the real service in production; tests
    // that don't care about email verification can omit it entirely (mirrors the
    // Argon2Parameters? convenience default on ServerAuthHashHasher).
    public UserRegistrationService(CffVaultManagerDbContext db, IAuthHashHasher authHashHasher, IEmailVerificationService? emailVerification = null)
    {
        _db = db;
        _authHashHasher = authHashHasher;
        _emailVerification = emailVerification;
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

        // Best-effort, after the new user is durably committed — see docs/features/
        // authentication.md "Verifica email in registrazione".
        if (_emailVerification is not null)
        {
            await _emailVerification.RequestAsync(userId, ip: null, userAgent: null, ct);
        }

        return userId;
    }
}
