using System.Security.Claims;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Api.Endpoints;

internal static class UsersEndpoints
{
    public static IEndpointRouteBuilder MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        // Registers an additional user inside the caller's own tenant. Both the tenant and the
        // acting user/role are taken from ITenantContext/the authenticated principal, never from
        // the request body, so a manipulated payload cannot target another tenant.
        app.MapPost("/api/users", async (
            RegisterUserRequest request,
            IUserRegistrationService service,
            ITenantContext tenantContext,
            ClaimsPrincipal caller,
            CancellationToken ct) =>
        {
            var callingRole = Enum.Parse<UserRole>(caller.FindFirstValue(ClaimTypes.Role)!);
            try
            {
                Guid newUserId = await service.RegisterInTenantAsync(
                    request, tenantContext.UserId!.Value, callingRole, tenantContext.TenantId!.Value, ct);
                return Results.Created($"/api/users/{newUserId}", new { Id = newUserId });
            }
            catch (UnauthorizedAccessException)
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }
        }).RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.Admin)));

        return app;
    }
}
