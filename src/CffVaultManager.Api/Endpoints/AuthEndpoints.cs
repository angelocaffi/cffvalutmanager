using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Enums;
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
        // yet a member of any tenant, so there is nothing to authorize against. Rate-limited and
        // duplicate-checked like the other public auth endpoints: unrestricted, it would let
        // anyone mass-create tenants, and a duplicate slug/email would otherwise surface as an
        // unhandled 500 from the unique-index violation instead of a clean 409.
        app.MapPost("/api/tenants", async (ProvisionTenantRequest request, IProvisionTenantService service, CancellationToken ct) =>
        {
            try
            {
                var result = await service.ProvisionAsync(request, ct);
                return Results.Created($"/api/admin/tenants/{result.TenantId}", result);
            }
            catch (InvalidOperationException ex)
            {
                return Results.Conflict(new { error = ex.Message });
            }
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        // "Prelogin": lets a client that has never cached its own salt/KDF params (a fresh device,
        // or the very first login after registration) fetch what it needs to derive its KEK and
        // compute an auth hash — see IAuthenticationService.PreloginAsync for the anti-enumeration
        // handling of an unknown email. Always 200; there is no failure case to distinguish here.
        app.MapPost("/api/auth/prelogin", async (PreloginRequest request, IAuthenticationService auth, CancellationToken ct) =>
            Results.Ok(await auth.PreloginAsync(request.Email, ct)))
            .RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/login", async (LoginRequest request, IAuthenticationService auth, HttpContext http, CancellationToken ct) =>
        {
            var result = await auth.LoginAsync(request.Email, request.AuthHash, ClientIp(http), UserAgent(http), ct);
            return result.Success || result.RequiresMfa ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/mfa/verify", async (VerifyMfaRequest request, IAuthenticationService auth, HttpContext http, CancellationToken ct) =>
        {
            var result = await auth.VerifyMfaAsync(request.ChallengeToken, request.Code, request.Factor, ClientIp(http), UserAgent(http), ct);
            return result.Success ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        // Email OTP requires an explicit send (unlike TOTP, whose code already lives on the
        // user's device) — see docs/features/authentication.md "Email OTP come fattore MFA". The
        // challenge token itself is the only identity carried here; a user without this factor
        // enabled still gets a 202 (uniform response, no-op internally in EmailOtpMfaService).
        app.MapPost("/api/auth/mfa/email-otp/send", async (
            MfaEmailOtpSendRequest request, IAuthenticationService auth, HttpContext http, CancellationToken ct) =>
        {
            bool ok = await auth.RequestMfaEmailOtpAsync(request.ChallengeToken, ClientIp(http), UserAgent(http), ct);
            return ok ? Results.Accepted() : Results.Unauthorized();
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        // Enabling/disabling Email OTP as an MFA factor is a plain authenticated settings change —
        // unlike TOTP there is no secret to enroll, so no separate confirm step: possession of the
        // account email was already proven at registration (EmailVerifiedAt), which enable requires.
        app.MapPost("/api/auth/mfa/email-otp/enable", async (IEmailOtpMfaService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                await service.EnableAsync(tenantContext.UserId!.Value, ct);
                return Results.NoContent();
            }
            catch (InvalidOperationException ex)
            {
                return Results.Conflict(new { error = ex.Message });
            }
        }).RequireAuthorization();

        app.MapPost("/api/auth/mfa/email-otp/disable", async (IEmailOtpMfaService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            await service.DisableAsync(tenantContext.UserId!.Value, ct);
            return Results.NoContent();
        }).RequireAuthorization();

        app.MapPost("/api/auth/refresh", async (RefreshRequest request, IAuthenticationService auth, HttpContext http, CancellationToken ct) =>
        {
            var result = await auth.RefreshAsync(request.RefreshToken, ClientIp(http), UserAgent(http), ct);
            return result.Success ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        // The caller's own account status — enough for the client to render security settings
        // (which MFA factors are on, whether the email is verified) without a heavier "full
        // profile" endpoint.
        app.MapGet("/api/auth/me", async (IUserProfileService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.GetOwnProfileAsync(tenantContext.UserId!.Value, ct)))
            .RequireAuthorization();

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

        // Re-encrypts only the DEK (never a vault item) — see docs/security-model.md and
        // ChangeMasterPasswordService. Success revokes every active session (including the
        // caller's own), so every device must re-authenticate with the new master password.
        app.MapPost("/api/auth/change-master-password", async (
            ChangeMasterPasswordRequest request, IChangeMasterPasswordService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            bool changed = await service.ChangeMasterPasswordAsync(tenantContext.UserId!.Value, request, ct);
            return changed
                ? Results.NoContent()
                : Results.Json(new { error = "Current master password is incorrect." }, statusCode: StatusCodes.Status401Unauthorized);
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

        // "Verifica email in registrazione" (docs/features/authentication.md): a code is sent
        // automatically at the end of registration (ProvisionTenantService/UserRegistrationService);
        // these two public endpoints let the client resend it and confirm it. Both are
        // unauthenticated by necessity — the user may not be able to log in yet — so both are
        // anti-enumeration (uniform response regardless of whether the email exists) and share the
        // same rate limiter as the other public auth endpoints.
        app.MapPost("/api/auth/email-verification/resend", async (
            ResendEmailVerificationRequest request, IEmailVerificationService service, HttpContext http, CancellationToken ct) =>
        {
            await service.ResendAsync(request.Email, ClientIp(http), UserAgent(http), ct);
            return Results.Accepted();
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/email-verification/confirm", async (
            ConfirmEmailVerificationRequest request, IEmailVerificationService service, HttpContext http, CancellationToken ct) =>
        {
            bool confirmed = await service.ConfirmAsync(request.Email, request.Code, ClientIp(http), UserAgent(http), ct);
            return confirmed ? Results.NoContent() : Results.Unauthorized();
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        return app;
    }

    private static string? ClientIp(HttpContext http) => http.Connection.RemoteIpAddress?.ToString();

    private static string? UserAgent(HttpContext http) =>
        http.Request.Headers.UserAgent.Count > 0 ? http.Request.Headers.UserAgent.ToString() : null;
}

internal sealed record PreloginRequest(string Email);

internal sealed record LoginRequest(string Email, byte[] AuthHash);

internal sealed record VerifyMfaRequest(string ChallengeToken, string Code, MfaFactor Factor = MfaFactor.Totp);

internal sealed record MfaEmailOtpSendRequest(string ChallengeToken);

internal sealed record RefreshRequest(string RefreshToken);

internal sealed record ConfirmMfaRequest(string Code);

internal sealed record ResendEmailVerificationRequest(string Email);

internal sealed record ConfirmEmailVerificationRequest(string Email, string Code);
