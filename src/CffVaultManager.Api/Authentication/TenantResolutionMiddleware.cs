using System.Security.Claims;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Api.Authentication;

/// <summary>
/// Runs after authentication and populates the request-scoped <see cref="ITenantContext"/> from
/// the validated claims — never from client-supplied input — per the resolution pipeline in
/// docs/multi-tenancy.md. When the claims are missing or inconsistent the context is deliberately
/// left unresolved: EF Core's global query filters are fail-closed, so every tenant-scoped query
/// then matches no rows instead of leaking data.
/// </summary>
internal sealed class TenantResolutionMiddleware
{
    private readonly RequestDelegate _next;

    public TenantResolutionMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, ITenantContext tenantContext)
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            ResolveTenant(context.User, tenantContext);
        }

        await _next(context);
    }

    private static void ResolveTenant(ClaimsPrincipal user, ITenantContext tenantContext)
    {
        string? userIdClaim = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdClaim, out var userId))
        {
            return;
        }

        string? roleClaim = user.FindFirstValue(ClaimTypes.Role);
        string? tenantIdClaim = user.FindFirstValue(TenantClaimTypes.TenantId);

        if (Guid.TryParse(tenantIdClaim, out var tenantId))
        {
            tenantContext.SetTenant(tenantId, userId);
            return;
        }

        if (Enum.TryParse<UserRole>(roleClaim, out var role) && role == UserRole.SuperAdmin)
        {
            tenantContext.SetSuperAdmin(userId);
        }
    }
}
