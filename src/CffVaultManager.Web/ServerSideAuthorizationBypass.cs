using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.Extensions.Options;

namespace CffVaultManager.Web;

/// <summary>
/// Always reports "no result" — never authenticates anyone, never throws. Exists only so
/// <c>IAuthenticationService</c> has a default scheme to call: this host has no real server-side
/// session to check in the first place (see docs/security-model.md — the JWT and unwrapped DEK
/// live only in the WASM client's memory), so there is nothing this handler could legitimately
/// authenticate against.
/// </summary>
internal sealed class NoOpAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "NoOp";

    public NoOpAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(AuthenticateResult.NoResult());
}

/// <summary>
/// Lets every request through regardless of the authorization outcome. A routable component
/// carrying <c>@attribute [Authorize]</c> (e.g. Vault.razor, Security.razor) becomes an ASP.NET
/// Core endpoint with authorization metadata attached, for every render mode, prerendered or not —
/// and the framework throws outright if it finds that metadata with no authorization middleware
/// configured to enforce it. The real "is the vault unlocked" check can only ever be answered
/// client-side (there is no server session to consult), so the correct behavior here is to let the
/// request through unconditionally: the server always serves the app shell, exactly like /login
/// already does, and Web.Client's own AuthorizeRouteView/RedirectToLogin (backed by
/// VaultAuthenticationStateProvider) makes the real decision once the WASM client boots. Without
/// this, the default handler would otherwise 401/403/redirect the initial document request itself
/// — before the WASM client ever gets a chance to run.
/// </summary>
internal sealed class PassthroughAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    public Task HandleAsync(
        RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult) =>
        next(context);
}
