using System.Net;
using CffVaultManager.Web;
using CffVaultManager.Web.Components;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents();

// ForwardedHeaders below fixed HSTS (verified live) but not this: the antiforgery cookie's
// SecurePolicy default turned out not to follow Request.IsHttps here, so it still needs an
// explicit override — see docs/pentest-report-2026-08-20.md finding #5.
builder.Services.AddAntiforgery(options => options.Cookie.SecurePolicy = CookieSecurePolicy.Always);

// Same trusted-proxy configuration as CffVaultManager.Api's Program.cs, and for the same reason:
// without it, this host never learns a request arrived over HTTPS (Caddy terminates TLS and
// forwards plain HTTP within the Docker network) — which silently neutered both UseHsts() below
// and the antiforgery cookie's default Secure policy (SameAsRequest sees "not HTTPS" and omits
// the flag). See docs/pentest-report-2026-08-20.md, findings #4/#5.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = 1;
    foreach (string proxy in builder.Configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [])
    {
        options.KnownProxies.Add(IPAddress.Parse(proxy));
    }
});

// This host never has a real server-side session to check (no cookie, nothing — the JWT and
// unwrapped DEK live only in the WASM client's memory, see docs/security-model.md). But ASP.NET
// Core's routing still attaches [Authorize] (from e.g. Vault.razor/Security.razor's
// @attribute [Authorize]) as HTTP endpoint metadata for every render mode, prerendered or not, and
// throws outright if it finds that metadata with no authorization middleware configured — so both
// registrations below exist purely to satisfy that framework requirement, not to perform any real
// check. NoOpAuthenticationHandler never authenticates anyone;
// PassthroughAuthorizationMiddlewareResultHandler lets every request through regardless of the
// outcome. The server therefore unconditionally serves the app shell for every route, exactly like
// /login already does, and the real "is the vault unlocked" decision is made only where it
// actually can be: client-side, by AuthorizeRouteView/RedirectToLogin (backed by
// VaultAuthenticationStateProvider) in Web.Client's Routes.razor.
builder.Services.AddAuthorization();
builder.Services
    .AddAuthentication(NoOpAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, NoOpAuthenticationHandler>(NoOpAuthenticationHandler.SchemeName, _ => { });
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, PassthroughAuthorizationMiddlewareResultHandler>();

var app = builder.Build();

// Must run before anything that inspects the scheme (UseHsts below, the antiforgery cookie's
// Secure policy) — same ordering requirement as CffVaultManager.Api's Program.cs.
app.UseForwardedHeaders();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(CffVaultManager.Web.Client._Imports).Assembly);

app.Run();
