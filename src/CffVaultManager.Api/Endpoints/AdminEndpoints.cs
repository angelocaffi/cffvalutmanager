using CffVaultManager.Application.Abstractions;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Platform-administration surface for SuperAdmins: tenant metadata only, never secrets — see
/// <see cref="ITenantAdministrationService"/> and docs/features/roles-permissions.md.
/// </summary>
internal static class AdminEndpoints
{
    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/admin").RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.SuperAdmin)));

        group.MapGet("/tenants", async (ITenantAdministrationService service, CancellationToken ct) =>
            Results.Ok(await service.GetAllTenantsAsync(ct)));

        group.MapGet("/tenants/{tenantId:guid}/usage", async (Guid tenantId, ITenantAdministrationService service, CancellationToken ct) =>
        {
            var usage = await service.GetTenantUsageAsync(tenantId, ct);
            return usage is null ? Results.NotFound() : Results.Ok(usage);
        });

        group.MapPost("/tenants/{tenantId:guid}/suspend", async (
            Guid tenantId, ITenantAdministrationService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                await service.SuspendTenantAsync(tenantId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }
            catch (KeyNotFoundException)
            {
                return Results.NotFound();
            }
        });

        group.MapPost("/tenants/{tenantId:guid}/reactivate", async (
            Guid tenantId, ITenantAdministrationService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                await service.ReactivateTenantAsync(tenantId, tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }
            catch (KeyNotFoundException)
            {
                return Results.NotFound();
            }
        });

        // Platform-wide subscription pricing (see docs/features/billing.md "Prezzo modificabile
        // da SuperAdmin") — not tenant data, so it lives under /api/admin like the rest of this
        // group rather than under /api/billing (tenant-facing checkout).
        group.MapGet("/billing/pricing", async (IBillingPricingAdminService service, CancellationToken ct) =>
            Results.Ok(await service.GetAsync(ct)));

        group.MapPut("/billing/pricing", async (
            UpdateBillingPricingRequest request, IBillingPricingAdminService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                return Results.Ok(await service.UpdateAsync(
                    request.StandardAnnualPrice,
                    request.DiscountedAnnualPrice,
                    request.DiscountExpiresAt,
                    request.PromoMessage,
                    tenantContext.UserId!.Value,
                    ct));
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        return app;
    }
}

internal sealed record UpdateBillingPricingRequest(
    decimal StandardAnnualPrice,
    decimal? DiscountedAnnualPrice,
    DateTimeOffset? DiscountExpiresAt,
    string? PromoMessage);
