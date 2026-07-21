using System.Security.Claims;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Audit;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// The tenant's audit trail. An Admin sees every entry in the tenant; an Operator sees only
/// their own actions (see docs/features/roles-permissions.md). SuperAdmins are out of scope here
/// — platform-level audit is a separate, not-yet-built surface (Dashboard SuperAdmin minima).
/// </summary>
internal static class AuditEndpoints
{
    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/audit", async (
            AuditAction? action,
            DateTimeOffset? from,
            DateTimeOffset? to,
            int? skip,
            int? take,
            IAuditLogService service,
            ITenantContext tenantContext,
            ClaimsPrincipal caller,
            CancellationToken ct) =>
        {
            var callerRole = Enum.Parse<UserRole>(caller.FindFirstValue(ClaimTypes.Role)!);
            var query = new AuditLogQuery(action, from, to, skip ?? 0, take ?? 50);
            var entries = await service.ListAsync(tenantContext.UserId!.Value, callerRole, query, ct);
            return Results.Ok(entries);
        }).RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.Admin), nameof(UserRole.Operator)));

        return app;
    }
}
