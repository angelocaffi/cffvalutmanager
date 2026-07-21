using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Dtos.Administration;

/// <summary>
/// Aggregate, non-sensitive usage counters for a single tenant.
/// Never carries encrypted material or secrets.
/// </summary>
public sealed record TenantUsageSummaryDto(
    Guid TenantId,
    string Name,
    string Slug,
    TenantStatus Status,
    int UserCount,
    int VaultCount,
    int VaultItemCount,
    DateTimeOffset? LastUserLoginAt);
