using CffVaultManager.Api.Authorization;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Organization-vault membership management within the caller's tenant (see
/// docs/features/sharing-access-control.md). Invite and revoke require the caller to be an active
/// Owner of the target vault (enforced in <c>VaultMembershipService</c>, not here — these routes
/// only require authentication); any active member may list a vault's members and any authenticated
/// user may fetch another same-tenant user's public key. Cross-tenant references surface as 404. The
/// server only ever stores opaque wrapped-key bytes.
/// </summary>
internal static class VaultMembershipsEndpoints
{
    public static IEndpointRouteBuilder MapVaultMembershipEndpoints(this IEndpointRouteBuilder app)
    {
        // Fetching a user's public key to wrap the DEK for them: available to any authenticated
        // caller in the same tenant. A user without a generated keypair is a 422 (unprocessable),
        // distinct from the shared helper's 409-conflict mapping, so it is handled inline here.
        app.MapGet("/api/tenant/users/{userId:guid}/public-key", async (
            Guid userId, IVaultMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                var dto = await service.GetPublicKeyAsync(userId, tenantContext.UserId!.Value, tenantContext.TenantId!.Value, ct);
                return Results.Ok(dto);
            }
            catch (KeyNotFoundException)
            {
                return Results.NotFound();
            }
            catch (InvalidOperationException ex)
            {
                return Results.UnprocessableEntity(new { error = ex.Message });
            }
        }).RequireAuthorization();

        // Same lookup, keyed by email instead of user id — used to find a per-item share
        // recipient (see docs/features/sharing-access-control.md), where the sharer knows the
        // recipient's email but not their id.
        app.MapGet("/api/tenant/users/by-email/{email}/public-key", async (
            string email, IVaultMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                var dto = await service.GetPublicKeyByEmailAsync(email, tenantContext.TenantId!.Value, ct);
                return Results.Ok(dto);
            }
            catch (KeyNotFoundException)
            {
                return Results.NotFound();
            }
            catch (InvalidOperationException ex)
            {
                return Results.UnprocessableEntity(new { error = ex.Message });
            }
        }).RequireAuthorization();

        var group = app.MapGroup("/api/vaults/{vaultId:guid}/memberships").RequireAuthorization().AddEndpointFilter<ReadOnlyEnforcementFilter>();

        // Owner-only, enforced inside VaultMembershipService.InviteAsync — not a tenant role gate.
        group.MapPost("", (Guid vaultId, CreateMembershipRequest request, IVaultMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                var membership = await service.InviteAsync(vaultId, tenantContext.UserId!.Value, tenantContext.TenantId!.Value, request, ct);
                return Results.Created($"/api/vaults/{vaultId}/memberships/{membership.Id}", membership);
            }));

        // Owner-only, enforced inside VaultMembershipService.RevokeAsync — not a tenant role gate.
        group.MapPost("/{userId:guid}/revoke", (Guid vaultId, Guid userId, RevokeMembershipRequest request, IVaultMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                if (userId != request.RevokedUserId)
                {
                    return Results.BadRequest(new { error = "Route user id and revoked user id must match." });
                }

                await service.RevokeAsync(vaultId, tenantContext.UserId!.Value, tenantContext.TenantId!.Value, request, ct);
                return Results.NoContent();
            }));

        // Any active member may see who else has access.
        group.MapGet("", (Guid vaultId, IVaultMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.ListMembersAsync(vaultId, tenantContext.UserId!.Value, tenantContext.TenantId!.Value, ct))));

        // The caller's own row, including their wrapped DEK — needed to unlock the vault. Unlike
        // the list above, this returns key material, so it is scoped to "mine only" rather than
        // added as a field on every row of ListMembersAsync's response.
        group.MapGet("/me", (Guid vaultId, IVaultMembershipService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
                Results.Ok(await service.GetMyMembershipAsync(vaultId, tenantContext.UserId!.Value, tenantContext.TenantId!.Value, ct))));

        return app;
    }
}
