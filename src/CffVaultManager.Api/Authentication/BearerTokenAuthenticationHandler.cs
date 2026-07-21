using System.Security.Claims;
using System.Text.Encodings.Web;
using CffVaultManager.Application.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CffVaultManager.Api.Authentication;

/// <summary>
/// Authenticates requests carrying an <c>Authorization: Bearer</c> access token issued by
/// <see cref="IJwtTokenService"/>. Validation is delegated to that same service so there is a
/// single source of truth for token rules; tokens carrying a <c>purpose</c> claim (e.g. the
/// short-lived MFA-challenge token) are explicitly rejected here, since they must never grant
/// API access on their own.
/// </summary>
internal sealed class BearerTokenAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Bearer";

    private readonly IJwtTokenService _jwt;

    public BearerTokenAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IJwtTokenService jwt)
        : base(options, logger, encoder)
    {
        _jwt = jwt;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string header = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        string token = header["Bearer ".Length..].Trim();
        var claims = await _jwt.ValidateAsync(token);
        if (claims is null || claims.Purpose is not null)
        {
            return AuthenticateResult.Fail("Invalid or unsupported access token.");
        }

        var identity = new ClaimsIdentity(SchemeName);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, claims.UserId.ToString()));

        if (claims.Role is { } role)
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, role.ToString()));
        }

        if (claims.TenantId is { } tenantId)
        {
            identity.AddClaim(new Claim(TenantClaimTypes.TenantId, tenantId.ToString()));
        }

        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);
        return AuthenticateResult.Success(ticket);
    }
}
