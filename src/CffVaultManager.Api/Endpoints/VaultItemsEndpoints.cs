using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Vault-item management, including the soft-delete trash lifecycle and tag assignment, within a
/// caller-owned vault. Ownership/scope mismatches surface as 404, invalid state transitions as 409
/// (see <see cref="VaultCoreEndpointHelpers"/>). Tag assignment/removal is idempotent.
/// </summary>
internal static class VaultItemsEndpoints
{
    public static IEndpointRouteBuilder MapVaultItemEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/vaults/{vaultId:guid}/items").RequireAuthorization();

        group.MapPost("", (Guid vaultId, CreateVaultItemRequest request, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                var item = await service.CreateAsync(vaultId, tenantContext.UserId!.Value, request, ct);
                return Results.Created($"/api/vaults/{vaultId}/items/{item.Id}", item);
            }));

        group.MapGet("", (
            Guid vaultId,
            Guid? folderId,
            Guid? tagId,
            VaultItemType? type,
            bool? favorite,
            VaultItemSortBy? sortBy,
            SortDirection? sortDirection,
            IVaultItemService service,
            ITenantContext tenantContext,
            CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                var query = new VaultItemListQuery(
                    folderId,
                    tagId,
                    type,
                    favorite,
                    sortBy ?? VaultItemSortBy.UpdatedAt,
                    sortDirection ?? SortDirection.Descending);
                return Results.Ok(await service.ListAsync(vaultId, tenantContext.UserId!.Value, query, ct));
            }));

        // Mapped before "/{itemId:guid}" so the intent is obvious; the :guid constraint would
        // disambiguate "trash" regardless.
        group.MapGet("/trash", (Guid vaultId, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.ListTrashAsync(vaultId, tenantContext.UserId!.Value, ct))));

        group.MapGet("/{itemId:guid}", (Guid vaultId, Guid itemId, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.GetAsync(vaultId, itemId, tenantContext.UserId!.Value, ct))));

        group.MapPut("/{itemId:guid}", (Guid vaultId, Guid itemId, UpdateVaultItemRequest request, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.UpdateAsync(vaultId, itemId, tenantContext.UserId!.Value, request, ct))));

        group.MapDelete("/{itemId:guid}", (Guid vaultId, Guid itemId, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.SoftDeleteAsync(vaultId, itemId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        group.MapPost("/{itemId:guid}/restore", (Guid vaultId, Guid itemId, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.RestoreAsync(vaultId, itemId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        group.MapDelete("/{itemId:guid}/permanent", (Guid vaultId, Guid itemId, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.PermanentlyDeleteAsync(vaultId, itemId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        group.MapPost("/{itemId:guid}/reveal", (Guid vaultId, Guid itemId, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.RecordRevealAsync(vaultId, itemId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        group.MapPost("/{itemId:guid}/tags/{tagId:guid}", (Guid vaultId, Guid itemId, Guid tagId, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.AssignTagAsync(vaultId, itemId, tagId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        group.MapDelete("/{itemId:guid}/tags/{tagId:guid}", (Guid vaultId, Guid itemId, Guid tagId, IVaultItemService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.RemoveTagAsync(vaultId, itemId, tagId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        return app;
    }
}
