using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Live sharing of a single vault item with another user in the same tenant (see
/// docs/features/sharing-access-control.md "Condivisione live di singola voce"), independent of
/// which vault the item lives in. The first share requires the caller to hold ReadWrite on the
/// item's containing vault; every subsequent operation (add member, revoke, list, view/edit as a
/// recipient) is resolved purely through the caller's own <c>ItemMembership</c> — no vault id
/// involved or exposed.
/// </summary>
internal static class ItemMembershipEndpoints
{
    public static IEndpointRouteBuilder MapItemMembershipEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/vaults/{vaultId:guid}/items/{itemId:guid}/share", (
            Guid vaultId, Guid itemId, ShareItemRequest request, IItemMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                var membership = await service.ShareAsync(vaultId, itemId, tenantContext.UserId!.Value, tenantContext.TenantId!.Value, request, ct);
                return Results.Created($"/api/items/{itemId}/memberships/{membership.Id}", membership);
            })).RequireAuthorization();

        app.MapPost("/api/items/{itemId:guid}/memberships", (
            Guid itemId, AddItemMemberRequest request, IItemMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                var membership = await service.AddMemberAsync(itemId, tenantContext.UserId!.Value, tenantContext.TenantId!.Value, request, ct);
                return Results.Created($"/api/items/{itemId}/memberships/{membership.Id}", membership);
            })).RequireAuthorization();

        app.MapPost("/api/items/{itemId:guid}/memberships/{userId:guid}/revoke", (
            Guid itemId, Guid userId, RevokeItemMemberRequest request, IItemMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                if (userId != request.RevokedUserId)
                {
                    return Results.BadRequest(new { error = "Route user id and revoked user id must match." });
                }

                await service.RevokeAsync(itemId, tenantContext.UserId!.Value, request, ct);
                return Results.NoContent();
            })).RequireAuthorization();

        app.MapGet("/api/items/{itemId:guid}/memberships", (Guid itemId, IItemMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.ListMembersAsync(itemId, tenantContext.UserId!.Value, ct))))
            .RequireAuthorization();

        app.MapGet("/api/shared-items", (IItemMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.GetSharedWithMeAsync(tenantContext.UserId!.Value, ct))))
            .RequireAuthorization();

        app.MapGet("/api/shared-items/{itemId:guid}", (Guid itemId, IItemMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.GetSharedItemAsync(itemId, tenantContext.UserId!.Value, ct))))
            .RequireAuthorization();

        app.MapPut("/api/shared-items/{itemId:guid}", (
            Guid itemId, UpdateSharedItemRequest request, IItemMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.UpdateSharedItemAsync(itemId, tenantContext.UserId!.Value, request, ct);
                return Results.NoContent();
            })).RequireAuthorization();

        return app;
    }
}
