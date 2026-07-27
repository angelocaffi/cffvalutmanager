using CffVaultManager.Api.Authentication;

namespace CffVaultManager.Api.Authorization;

/// <summary>
/// Blocks vault-content mutations for a tenant whose trial has ended with no active paid plan
/// (see docs/features/billing.md "Enforcement sola lettura"). Reads/HEAD always pass through;
/// applied only to the vault-content-mutating endpoint groups — never to auth/billing/
/// notifications/audit/admin, so a read-only tenant can still pay, log out, or change its master
/// password.
/// </summary>
internal sealed class ReadOnlyEnforcementFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var request = context.HttpContext.Request;
        if (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method))
        {
            return await next(context);
        }

        bool isReadOnly = context.HttpContext.User.HasClaim(TenantClaimTypes.ReadOnly, "true");
        if (isReadOnly)
        {
            return Results.Json(
                new { error = "This tenant's trial has ended. Upgrade to keep writing." },
                statusCode: StatusCodes.Status402PaymentRequired);
        }

        return await next(context);
    }
}
