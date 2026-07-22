using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Backs <c>GET /api/auth/me</c>: lets the client render its own security settings (which MFA
/// factors are enabled, whether the email is verified) without a dedicated "full profile"
/// endpoint that would expose more than the client needs.
/// </summary>
internal sealed class UserProfileService : IUserProfileService
{
    private readonly CffVaultManagerDbContext _db;

    public UserProfileService(CffVaultManagerDbContext db) => _db = db;

    public async Task<UserProfileDto> GetOwnProfileAsync(Guid userId, CancellationToken ct = default)
    {
        // Runs post-authentication, so the tenant query filter already scopes this to the
        // caller's own user record (mirrors MfaSetupService/EmailOtpMfaService).
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        return new UserProfileDto(user.Email, user.EmailVerifiedAt is not null, user.MfaEnabled, user.MfaEmailOtpEnabled, user.PublicKey is not null);
    }
}
