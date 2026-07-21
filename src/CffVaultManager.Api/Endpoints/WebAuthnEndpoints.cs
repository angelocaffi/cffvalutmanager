using System.Text.Json;
using CffVaultManager.Application.Abstractions;
using static CffVaultManager.Api.Endpoints.RequestContext;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// WebAuthn/Passkey as an MFA factor (docs/features/authentication.md). Registration/device
/// management is authenticated; the assertion begin/complete pair is public like the rest of the
/// MFA challenge flow, since the caller has only cleared the password step at that point (see
/// AuthEndpoints' /mfa/verify and /mfa/email-otp/*).
/// </summary>
internal static class WebAuthnEndpoints
{
    public static IEndpointRouteBuilder MapWebAuthnEndpoints(this IEndpointRouteBuilder app)
    {
        // Fido2NetLib's options objects are already JSON on the wire (CredentialCreateOptions/
        // AssertionOptions .ToJson()) — Results.Content avoids re-encoding that string as a JSON
        // string literal, which Results.Ok(string) would do.
        app.MapPost("/api/auth/webauthn/register/begin", async (IWebAuthnService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Content(await service.BeginRegistrationAsync(tenantContext.UserId!.Value, ct), "application/json"))
            .RequireAuthorization();

        app.MapPost("/api/auth/webauthn/register/complete", async (
            WebAuthnRegisterCompleteRequest request, IWebAuthnService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            try
            {
                Guid credentialId = await service.CompleteRegistrationAsync(
                    tenantContext.UserId!.Value, request.AttestationResponse.GetRawText(), request.Nickname, ct);
                return Results.Created($"/api/auth/webauthn/credentials/{credentialId}", new { Id = credentialId });
            }
            catch (InvalidOperationException)
            {
                // Covers both "no pending ceremony" and any attestation verification failure —
                // WebAuthnService.CompleteRegistrationAsync wraps every failure mode this way.
                return Results.BadRequest(new { error = "Registration could not be verified." });
            }
        }).RequireAuthorization();

        app.MapGet("/api/auth/webauthn/credentials", async (IWebAuthnService service, ITenantContext tenantContext, CancellationToken ct) =>
            Results.Ok(await service.ListCredentialsAsync(tenantContext.UserId!.Value, ct)))
            .RequireAuthorization();

        app.MapPost("/api/auth/webauthn/credentials/{credentialId:guid}/remove", async (
            Guid credentialId, IWebAuthnService service, ITenantContext tenantContext, CancellationToken ct) =>
        {
            await service.RemoveCredentialAsync(tenantContext.UserId!.Value, credentialId, ct);
            return Results.NoContent();
        }).RequireAuthorization();

        // Public, rate-limited like the Email OTP MFA send/verify pair: the caller has only
        // cleared the password step (holds a bare mfa_challenge token), not a full session.
        app.MapPost("/api/auth/webauthn/assertion/begin", async (
            WebAuthnAssertionBeginRequest request, IAuthenticationService auth, CancellationToken ct) =>
        {
            string? optionsJson = await auth.RequestWebAuthnAssertionOptionsAsync(request.ChallengeToken, ct);
            return optionsJson is null ? Results.Unauthorized() : Results.Content(optionsJson, "application/json");
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        app.MapPost("/api/auth/webauthn/assertion/complete", async (
            WebAuthnAssertionCompleteRequest request, IAuthenticationService auth, HttpContext http, CancellationToken ct) =>
        {
            var result = await auth.VerifyWebAuthnAsync(
                request.ChallengeToken, request.AssertionResponse.GetRawText(), ClientIp(http), UserAgent(http), ct);
            return result.Success ? Results.Ok(result) : Results.Json(result, statusCode: StatusCodes.Status401Unauthorized);
        }).RequireRateLimiting(AuthRateLimiting.PolicyName);

        return app;
    }
}

internal sealed record WebAuthnRegisterCompleteRequest(JsonElement AttestationResponse, string? Nickname);

internal sealed record WebAuthnAssertionBeginRequest(string ChallengeToken);

internal sealed record WebAuthnAssertionCompleteRequest(string ChallengeToken, JsonElement AssertionResponse);
