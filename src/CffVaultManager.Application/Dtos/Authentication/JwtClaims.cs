using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// The claims extracted from a validated JWT. <see cref="TenantId"/> and <see cref="Role"/>
/// are null on a bare MFA-challenge token, which carries only <see cref="UserId"/> and
/// <see cref="Purpose"/>. <see cref="IsReadOnly"/> reflects the tenant's trial/paid-plan state at
/// the time the token was issued (see docs/features/billing.md) — accepted to go stale until the
/// next refresh.
/// </summary>
public sealed record JwtClaims(
    Guid UserId,
    Guid? TenantId,
    UserRole? Role,
    string? Purpose,
    bool IsReadOnly = false);
