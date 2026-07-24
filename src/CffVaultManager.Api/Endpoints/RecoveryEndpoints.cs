using System.Text.Json;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Enums;
using static CffVaultManager.Api.Endpoints.RequestContext;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// The optional, opt-in recovery-kit flow — see docs/security-model.md#recovery-kit. Kept separate
/// from AuthEndpoints.cs (already sizeable) even though both live under the /api/auth/* prefix.
/// </summary>
internal static class RecoveryEndpoints
{
    public static IEndpointRouteBuilder MapRecoveryEndpoints(this IEndpointRouteBuilder app)
    {
        // Generates/regenerates a kit for the authenticated caller — no re-proof of the current
        // master password required, same convention as /api/auth/mfa/setup and /api/auth/keypair.
        app.MapPost("/api/auth/recovery-kit", async (
            GenerateRecoveryKitRequest request, IAccountRecoveryService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            await service.GenerateKitAsync(tenantContext.UserId!.Value, request, ct);
            return Results.NoContent();
        }).RequireAuthorization();

        // Always 200 with a fixed-length blob (real or fake) — anti-enumeration, same principle as
        // POST /api/auth/prelogin's fake salt for an unknown email.
        app.MapPost("/api/auth/recovery/start", async (RecoveryStartRequest request, IAccountRecoveryService service, CancellationToken ct) =>
            Results.Ok(new RecoveryStartResult(await service.StartAsync(request.Email, ct))))
            .RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/recovery/verify", async (
            RecoveryVerifyRequest request, IAccountRecoveryService service, HttpContext http, CancellationToken ct) =>
        {
            var result = await service.VerifyAsync(request.Email, request.RecoveryAuthHash, ClientIp(http), UserAgent(http), ct);
            return result.Success || result.RequiresMfa ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/recovery/verify-mfa", async (
            RecoveryVerifyMfaRequest request, IAccountRecoveryService service, HttpContext http, CancellationToken ct) =>
        {
            var result = await service.VerifyMfaAsync(request.ChallengeToken, request.Code, request.Factor, ClientIp(http), UserAgent(http), ct);
            return result.Success ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/recovery/mfa/email-otp/send", async (
            RecoveryChallengeRequest request, IAccountRecoveryService service, HttpContext http, CancellationToken ct) =>
        {
            bool ok = await service.RequestMfaEmailOtpAsync(request.ChallengeToken, ClientIp(http), UserAgent(http), ct);
            return ok ? Results.Accepted() : Results.Unauthorized();
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/recovery/webauthn/begin", async (
            RecoveryChallengeRequest request, IAccountRecoveryService service, CancellationToken ct) =>
        {
            string? optionsJson = await service.RequestWebAuthnAssertionOptionsAsync(request.ChallengeToken, ct);
            return optionsJson is not null ? Results.Text(optionsJson, "application/json") : Results.Unauthorized();
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/recovery/webauthn/complete", async (
            RecoveryWebAuthnCompleteRequest request, IAccountRecoveryService service, HttpContext http, CancellationToken ct) =>
        {
            var result = await service.VerifyWebAuthnAsync(
                request.ChallengeToken, request.AssertionResponse.GetRawText(), ClientIp(http), UserAgent(http), ct);
            return result.Success ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/recovery/complete", async (RecoveryCompleteRequest request, IAccountRecoveryService service, CancellationToken ct) =>
        {
            bool completed = await service.CompleteAsync(request, ct);
            return completed ? Results.NoContent() : Results.Unauthorized();
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        return app;
    }
}

internal sealed record RecoveryStartRequest(string Email);

internal sealed record RecoveryStartResult(byte[] RecoveryEncryptedDek);

internal sealed record RecoveryVerifyRequest(string Email, byte[] RecoveryAuthHash);

internal sealed record RecoveryVerifyMfaRequest(string ChallengeToken, string Code, MfaFactor Factor = MfaFactor.Totp);

internal sealed record RecoveryChallengeRequest(string ChallengeToken);

internal sealed record RecoveryWebAuthnCompleteRequest(string ChallengeToken, JsonElement AssertionResponse);
