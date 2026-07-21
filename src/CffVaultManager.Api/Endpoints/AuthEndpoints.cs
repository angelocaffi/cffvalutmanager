using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using Microsoft.AspNetCore.RateLimiting;

namespace CffVaultManager.Api.Endpoints;

/// <summary>Name of the per-IP rate-limiting policy applied to the unauthenticated auth endpoints (see Program.cs).</summary>
internal static class AuthRateLimiting
{
    public const string PolicyName = "auth";
}

internal static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        // Self-service tenant signup: creates the organization and its first Admin. Public by
        // design (see docs/multi-tenancy.md#provisioning-di-un-nuovo-tenant) — the caller is not
        // yet a member of any tenant, so there is nothing to authorize against.
        app.MapPost("/api/tenants", async (ProvisionTenantRequest request, IProvisionTenantService service, CancellationToken ct) =>
        {
            var result = await service.ProvisionAsync(request, ct);
            return Results.Created($"/api/admin/tenants/{result.TenantId}", result);
        });

        app.MapPost("/api/auth/login", async (LoginRequest request, IAuthenticationService auth, HttpContext http, CancellationToken ct) =>
        {
            var result = await auth.LoginAsync(request.Email, request.AuthHash, ClientIp(http), UserAgent(http), ct);
            return result.Success || result.RequiresMfa ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/mfa/verify", async (VerifyMfaRequest request, IAuthenticationService auth, HttpContext http, CancellationToken ct) =>
        {
            var result = await auth.VerifyMfaAsync(request.ChallengeToken, request.Code, ClientIp(http), UserAgent(http), ct);
            return result.Success ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/refresh", async (RefreshRequest request, IAuthenticationService auth, HttpContext http, CancellationToken ct) =>
        {
            var result = await auth.RefreshAsync(request.RefreshToken, ClientIp(http), UserAgent(http), ct);
            return result.Success ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/mfa/setup", async (IMfaSetupService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            string uri = await service.SetupTotpAsync(tenantContext.UserId!.Value, ct);
            return Results.Ok(new { ProvisioningUri = uri });
        }).RequireAuthorization();

        app.MapPost("/api/auth/mfa/confirm", async (ConfirmMfaRequest request, IMfaSetupService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            bool confirmed = await service.ConfirmTotpAsync(tenantContext.UserId!.Value, request.Code, ct);
            return confirmed ? Results.Ok() : Results.BadRequest();
        }).RequireAuthorization();

        // "Logout remoto" (docs/features/authentication.md): lists/revokes the caller's own
        // refresh-token sessions. Revoking a session blocks future silent renewal via /refresh, but
        // an already-issued access token remains valid until its own short expiry (15 min) —
        // stateless JWTs can't be individually invalidated without a server-side blocklist, so this
        // is an accepted residual window, same shape as tenant suspension's.
        app.MapGet("/api/auth/sessions", async (IRefreshTokenService refreshTokens, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await refreshTokens.ListActiveSessionsAsync(tenantContext.UserId!.Value, ct)))
            .RequireAuthorization();

        app.MapPost("/api/auth/sessions/{sessionId:guid}/revoke", async (
            Guid sessionId, IRefreshTokenService refreshTokens, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                await refreshTokens.RevokeSessionAsync(tenantContext.UserId!.Value, tenantContext.TenantId, sessionId, ct);
                return Results.NoContent();
            }
            catch (KeyNotFoundException)
            {
                return Results.NotFound();
            }
        }).RequireAuthorization();

        app.MapPost("/api/auth/sessions/revoke-all", async (IRefreshTokenService refreshTokens, ITenantContext tenantContext, CancellationToken ct) =>
        {
            await refreshTokens.RevokeAllSessionsAsync(tenantContext.UserId!.Value, tenantContext.TenantId, ct);
            return Results.NoContent();
        }).RequireAuthorization();

        return app;
    }

    private static string? ClientIp(HttpContext http) => http.Connection.RemoteIpAddress?.ToString();

    private static string? UserAgent(HttpContext http) =>
        http.Request.Headers.UserAgent.Count > 0 ? http.Request.Headers.UserAgent.ToString() : null;
}

internal sealed record LoginRequest(string Email, byte[] AuthHash);

internal sealed record VerifyMfaRequest(string ChallengeToken, string Code);

internal sealed record RefreshRequest(string RefreshToken);

internal sealed record ConfirmMfaRequest(string Code);
