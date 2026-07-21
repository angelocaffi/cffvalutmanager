namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Metadata about one of the caller's active refresh-token sessions — never the token or its
/// hash. Each row corresponds to one login (a device/browser), rotated on every refresh but
/// remaining a single active row until revoked or expired (see docs/features/authentication.md
/// "Logout remoto").
/// </summary>
public sealed record ActiveSessionDto(
    Guid Id,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    string? CreatedByIp,
    string? CreatedByUserAgent);
