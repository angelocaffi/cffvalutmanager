using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Administration;

/// <summary>
/// Non-sensitive metadata about a tenant, exposed to platform administrators.
/// Never carries encrypted material or secrets.
/// </summary>
public sealed record TenantSummaryDto(
    Guid Id,
    string Name,
    string Slug,
    TenantStatus Status,
    string? PlanName,
    int UserCount,
    int VaultCount,
    DateTimeOffset CreatedAt);
