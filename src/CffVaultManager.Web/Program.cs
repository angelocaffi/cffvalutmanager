using CffVaultManager.Web.Components;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents();

// Routes.razor's CascadingAuthenticationState/AuthorizeRouteView render once here on the server
// during prerendering (before the WASM client takes over), so this host needs the authorization
// policy machinery too, not just Web.Client — even though every real auth decision (is the vault
// actually unlocked?) only ever happens client-side, since that's the only place SessionState
// exists. No AuthenticationStateProvider registered here: the default (anonymous) one is exactly
// right for a prerender pass, where no session can exist anyway. The full AddAuthorization (not
// just Blazor's AddAuthorizationCore) is required here: the minimal-hosting model auto-inserts
// UseAuthorization() into the pipeline once any authorization services are present, and that
// middleware needs the full registration to satisfy its own startup check.
builder.Services.AddAuthorization();

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
