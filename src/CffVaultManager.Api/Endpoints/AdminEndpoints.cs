using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Platform-administration surface for SuperAdmins: tenant metadata only, never secrets — see
/// <see cref="ITenantAdministrationService"/> and docs/features/roles-permissions.md.
/// </summary>
internal static class AdminEndpoints
{
    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/admin").RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.SuperAdmin)));

        group.MapGet("/tenants", async (ITenantAdministrationService service, CancellationToken ct) =>
            Results.Ok(await service.GetAllTenantsAsync(ct)));

        group.MapGet("/tenants/{tenantId:guid}/usage", async (Guid tenantId, ITenantAdministrationService service, CancellationToken ct) =>
        {
            var usage = await service.GetTenantUsageAsync(tenantId, ct);
            return usage is null ? Results.NotFound() : Results.Ok(usage);
        });

        return app;
    }
}
