using CffVaultManager.Application.Dtos.Authentication;

namespace CffVaultManager.Application.Abstractions;

/// <summary>Reads the caller's own account status — see <see cref="UserProfileDto"/>.</summary>
public interface IUserProfileService
{
    Task<UserProfileDto> GetOwnProfileAsync(Guid userId, CancellationToken ct = default);
}
