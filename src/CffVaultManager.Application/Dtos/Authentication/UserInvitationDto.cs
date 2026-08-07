using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>A pending invitation, for the Admin-facing <c>/users</c> page (see docs/features/roles-permissions.md).</summary>
public sealed record UserInvitationDto(Guid Id, string Email, UserRole Role, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);

/// <summary>Shown on the public accept-invitation page before the recipient commits to setting a master password.</summary>
public sealed record InvitationPreviewDto(string TenantName, UserRole Role, string InvitedByEmail);

/// <summary>An existing member of the caller's tenant, for the same <c>/users</c> page — no sensitive data.</summary>
public sealed record TenantUserSummaryDto(Guid Id, string Email, UserRole Role, DateTimeOffset CreatedAt);
