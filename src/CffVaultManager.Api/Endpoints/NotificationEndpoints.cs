using CffVaultManager.Application.Abstractions;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// In-app notifications for the caller (see docs/features/notifications.md) — the counterpart to
/// the security-alert emails, always scoped to the caller's own notifications only.
/// </summary>
internal static class NotificationEndpoints
{
    public static IEndpointRouteBuilder MapNotificationEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/notifications").RequireAuthorization();

        group.MapGet("", async (INotificationService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.ListAsync(tenantContext.UserId!.Value, ct)));

        group.MapGet("/unread-count", async (INotificationService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.CountUnreadAsync(tenantContext.UserId!.Value, ct)));

        group.MapPost("/{id:guid}/read", (Guid id, INotificationService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                await service.MarkAsReadAsync(id, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }));

        group.MapPost("/read-all", async (INotificationService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            await service.MarkAllAsReadAsync(tenantContext.UserId!.Value, ct);
            return Results.NoContent();
        });

        return app;
    }
}
