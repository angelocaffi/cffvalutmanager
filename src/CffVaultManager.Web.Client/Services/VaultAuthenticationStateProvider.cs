using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Bridges <see cref="SessionState"/> into Blazor's standard authorization pipeline, so routable
/// pages can gate themselves with a plain <c>@attribute [Authorize]</c> instead of each
/// reimplementing its own "redirect if locked" check.
/// </summary>
public sealed class VaultAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly SessionState _session;

    public VaultAuthenticationStateProvider(SessionState session)
    {
        _session = session;
        _session.Changed += () => NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        ClaimsIdentity identity = _session.IsUnlocked
            ? new ClaimsIdentity(
                [new Claim(ClaimTypes.Email, _session.Email!), new Claim(ClaimTypes.Role, _session.Role!)],
                authenticationType: "vault-session")
            : new ClaimsIdentity();

        return Task.FromResult(new AuthenticationState(new ClaimsPrincipal(identity)));
    }
}
