using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Folder management within a caller-owned vault. Ownership mismatches surface as 404, duplicate
/// names as 409 (see <see cref="VaultCoreEndpointHelpers"/>).
/// </summary>
internal static class FoldersEndpoints
{
    public static IEndpointRouteBuilder MapFolderEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/vaults/{vaultId:guid}/folders").RequireAuthorization();

        group.MapPost("", (Guid vaultId, CreateFolderRequest request, IFolderService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                var folder = await service.CreateAsync(vaultId, tenantContext.UserId!.Value, request, ct);
                return Results.Created($"/api/vaults/{vaultId}/folders/{folder.Id}", folder);
            }));

        group.MapGet("", (Guid vaultId, IFolderService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.ListAsync(vaultId, tenantContext.UserId!.Value, ct))));

        group.MapPut("/{folderId:guid}", (Guid vaultId, Guid folderId, RenameFolderRequest request, IFolderService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.RenameAsync(vaultId, folderId, tenantContext.UserId!.Value, request, ct))));

        group.MapDelete("/{folderId:guid}", (Guid vaultId, Guid folderId, IFolderService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.DeleteAsync(vaultId, folderId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        return app;
    }
}
