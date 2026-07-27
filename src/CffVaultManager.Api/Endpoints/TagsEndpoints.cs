using CffVaultManager.Api.Authorization;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Tag management within a caller-owned vault. Ownership mismatches surface as 404, duplicate
/// names as 409 (see <see cref="VaultCoreEndpointHelpers"/>).
/// </summary>
internal static class TagsEndpoints
{
    public static IEndpointRouteBuilder MapTagEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/vaults/{vaultId:guid}/tags").RequireAuthorization().AddEndpointFilter<ReadOnlyEnforcementFilter>();

        group.MapPost("", (Guid vaultId, CreateTagRequest request, ITagService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                var tag = await service.CreateAsync(vaultId, tenantContext.UserId!.Value, request, ct);
                return Results.Created($"/api/vaults/{vaultId}/tags/{tag.Id}", tag);
            }));

        group.MapGet("", (Guid vaultId, ITagService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.ListAsync(vaultId, tenantContext.UserId!.Value, ct))));

        group.MapPut("/{tagId:guid}", (Guid vaultId, Guid tagId, RenameTagRequest request, ITagService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.RenameAsync(vaultId, tagId, tenantContext.UserId!.Value, request, ct))));

        group.MapDelete("/{tagId:guid}", (Guid vaultId, Guid tagId, ITagService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.DeleteAsync(vaultId, tagId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        return app;
    }
}
