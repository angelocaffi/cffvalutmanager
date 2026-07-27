using CffVaultManager.Api.Authorization;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Time-limited anonymous links to a single vault item, for sharing outside the tenant with someone
/// who has no account (see docs/features/sharing-access-control.md "Link di condivisione esterna").
/// The read endpoint is intentionally public: the decryption key never reaches the server (it
/// travels only in the URL fragment, client-side), so serving the ciphertext to anyone holding a
/// valid token leaks nothing on its own.
/// </summary>
internal static class ExternalShareLinkEndpoints
{
    public static IEndpointRouteBuilder MapExternalShareLinkEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/vaults/{vaultId:guid}/items/{itemId:guid}/share-links").RequireAuthorization().AddEndpointFilter<ReadOnlyEnforcementFilter>();

        group.MapPost("", (Guid vaultId, Guid itemId, CreateExternalShareLinkRequest request, IExternalShareLinkService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                var link = await service.CreateAsync(vaultId, itemId, tenantContext.UserId!.Value, request, ct);
                return Results.Created($"/api/vaults/{vaultId}/items/{itemId}/share-links/{link.Id}", link);
            }));

        group.MapGet("", (Guid vaultId, Guid itemId, IExternalShareLinkService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.ListForItemAsync(vaultId, itemId, tenantContext.UserId!.Value, ct))));

        group.MapPost("/{linkId:guid}/revoke", (Guid vaultId, Guid itemId, Guid linkId, IExternalShareLinkService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.RevokeAsync(vaultId, itemId, linkId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        // Public: no authentication, no tenant context resolved. Rate-limited like every other
        // anonymous auth endpoint against token brute-forcing (defense in depth on top of the
        // token's 256-bit entropy).
        app.MapGet("/api/share-links/{token}", async (string token, IExternalShareLinkService service, CancellationToken ct) =>
        {
            var content = await service.GetByTokenAsync(token, ct);
            return content is not null ? Results.Ok(content) : Results.NotFound();
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        return app;
    }
}
