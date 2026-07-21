using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Registers additional users inside an existing tenant. Only an Admin of that tenant may call it,
/// and the new user is always created in the caller's tenant regardless of any tenant hint in the
/// request (cross-tenant injection is not possible).
/// </summary>
public interface IUserRegistrationService
{
    Task<Guid> RegisterInTenantAsync(
        RegisterUserRequest request,
        Guid callingUserId,
        UserRole callingUserRole,
        Guid callingTenantId,
        CancellationToken ct = default);
}
