using CffVaultManager.Api.Authorization;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Lists the authenticated caller's own personal vaults and organization vaults, and creates new
/// organization vaults. Ownership/membership is taken from <see cref="ITenantContext"/>, never
/// from the request.
/// </summary>
internal static class VaultsEndpoints
{
    public static IEndpointRouteBuilder MapVaultEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/vaults", async (IVaultService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.ListOwnedVaultsAsync(tenantContext.UserId!.Value, ct)))
            .RequireAuthorization();

        app.MapGet("/api/vaults/organization", async (IVaultService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.ListAccessibleOrgVaultsAsync(tenantContext.UserId!.Value, ct)))
            .RequireAuthorization();

        // Only tenant Admins create organization vaults (see docs/roadmap.md Fase 1 scope, same
        // gate as membership invite/revoke in VaultMembershipsEndpoints).
        app.MapPost("/api/vaults/organization", async (
            CreateOrganizationVaultRequest request, IVaultService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            var vault = await service.CreateOrganizationVaultAsync(
                tenantContext.UserId!.Value, tenantContext.TenantId!.Value, request, ct);
            return Results.Created($"/api/vaults/{vault.Id}", vault);
        }).RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.Admin))).AddEndpointFilter<ReadOnlyEnforcementFilter>();

        return app;
    }
}
