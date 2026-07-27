using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Trial/paid-plan status and PayPal checkout (see docs/features/billing.md). Deliberately never
/// covered by <see cref="Authorization.ReadOnlyEnforcementFilter"/> — a read-only tenant must still
/// be able to check its status and pay.
/// </summary>
internal static class BillingEndpoints
{
    public static IEndpointRouteBuilder MapBillingEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/billing").RequireAuthorization();

        group.MapGet("/status", async (IBillingService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.GetStatusAsync(tenantContext.TenantId!.Value, ct)));

        // Only Admin can start/complete a payment (see multi-tenancy.md: Admin administers
        // organization-level settings) — an Operator can only read /status.
        group.MapPost("/checkout", async (IBillingService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                return Results.Ok(await service.CreateCheckoutAsync(tenantContext.TenantId!.Value, tenantContext.UserId!.Value, ct));
            }
            catch (PayPalNotConfiguredException)
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }
        }).RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.Admin)));

        group.MapPost("/checkout/{orderId}/capture", (string orderId, IBillingService service, ITenantContext tenantContext, CancellationToken ct) =>
            VaultCoreEndpointHelpers.ExecuteAsync(async () =>
            {
                try
                {
                    return Results.Ok(await service.CaptureCheckoutAsync(tenantContext.TenantId!.Value, tenantContext.UserId!.Value, orderId, ct));
                }
                catch (PayPalNotConfiguredException)
                {
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                }
            })).RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.Admin)));

        return app;
    }
}
