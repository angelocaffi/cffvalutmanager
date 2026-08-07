using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Tenant-Admin user management (see docs/features/roles-permissions.md "Invito di nuovi utenti").
/// The invite/list/revoke routes are Admin-only and tenant-scoped; the preview/complete routes are
/// public and token-driven — the invitee has no account yet.
/// </summary>
internal static class UserInvitationsEndpoints
{
    public static IEndpointRouteBuilder MapUserInvitationsEndpoints(this IEndpointRouteBuilder app)
    {
        var adminGroup = app.MapGroup("/api/tenant/users").RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.Admin)));

        adminGroup.MapGet("", async (IUserInvitationService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.ListTenantUsersAsync(tenantContext.TenantId!.Value, ct)));

        adminGroup.MapGet("/invitations", async (IUserInvitationService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.ListPendingAsync(tenantContext.TenantId!.Value, ct)));

        adminGroup.MapPost("/invitations", async (InviteUserRequest request, IUserInvitationService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                return Results.Ok(await service.InviteAsync(request.Email, request.Role, tenantContext.UserId!.Value, tenantContext.TenantId!.Value, ct));
            }
            catch (InvalidOperationException ex)
            {
                return Results.Conflict(new { error = ex.Message });
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        adminGroup.MapPost("/invitations/{id:guid}/revoke", async (Guid id, IUserInvitationService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                await service.RevokeAsync(id, tenantContext.TenantId!.Value, ct);
                return Results.NoContent();
            }
            catch (KeyNotFoundException)
            {
                return Results.NotFound();
            }
        });

        var publicGroup = app.MapGroup("/api/tenant/users/invitations");

        publicGroup.MapGet("/{token}", async (string token, IUserInvitationService service, CancellationToken ct) =>
        {
            var preview = await service.GetPreviewAsync(token, ct);
            return preview is null ? Results.NotFound() : Results.Ok(preview);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        publicGroup.MapPost("/{token}/complete", async (string token, AcceptInvitationRequest request, IUserInvitationService service, CancellationToken ct) =>
        {
            Guid? userId = await service.AcceptAsync(
                token, request.AuthHash, request.EncryptedDek, request.MasterPasswordSalt,
                request.KdfMemoryKb, request.KdfIterations, request.KdfVersion, ct);
            return userId is null ? Results.NotFound() : Results.Ok(new { UserId = userId });
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        return app;
    }
}

internal sealed record InviteUserRequest(string Email, UserRole Role);

internal sealed record AcceptInvitationRequest(
    byte[] AuthHash,
    byte[] EncryptedDek,
    byte[] MasterPasswordSalt,
    int KdfMemoryKb,
    int KdfIterations,
    int KdfVersion);
