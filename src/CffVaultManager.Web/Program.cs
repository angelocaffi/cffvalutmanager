using CffVaultManager.Web;
using CffVaultManager.Web.Components;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents();

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
