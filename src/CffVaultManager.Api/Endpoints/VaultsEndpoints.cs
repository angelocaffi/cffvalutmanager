using CffVaultManager.Application.Abstractions;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Lists the authenticated caller's own personal vaults. Ownership is taken from
/// <see cref="ITenantContext"/>, never from the request.
/// </summary>
internal static class VaultsEndpoints
{
    public static IEndpointRouteBuilder MapVaultEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/vaults", async (IVaultService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.ListOwnedVaultsAsync(tenantContext.UserId!.Value, ct)))
            .RequireAuthorization();

        return app;
    }
}
