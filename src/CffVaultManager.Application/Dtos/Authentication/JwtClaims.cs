using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// The claims extracted from a validated JWT. <see cref="TenantId"/> and <see cref="Role"/>
/// are null on a bare MFA-challenge token, which carries only <see cref="UserId"/> and
/// <see cref="Purpose"/>.
/// </summary>
public sealed record JwtClaims(
    Guid UserId,
    Guid? TenantId,
    UserRole? Role,
    string? Purpose);
