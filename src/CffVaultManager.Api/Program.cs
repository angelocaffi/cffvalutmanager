using System.Net;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using CffVaultManager.Api.Authentication;
using CffVaultManager.Api.Endpoints;
using CffVaultManager.Infrastructure.DependencyInjection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Enums (e.g. UserRole) travel as their string name, not a raw ordinal, over the wire.
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

builder.Services.AddInfrastructure(builder.Configuration);

// Behind a reverse proxy, Connection.RemoteIpAddress is otherwise always the proxy's own address —
// which would misattribute every request to one IP for both the rate limiter's partition key
// (below) and the audit log's IpAddress (AuthEndpoints.ClientIp). Only trusted from proxies
// explicitly listed in configuration (empty by default, i.e. a no-op unless deployed behind one);
// ForwardLimit is 1 so only the immediate hop's header is honored, not an arbitrary caller-supplied
// chain (which would otherwise let a client spoof its own IP and dodge the rate limit).
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = 1;
    foreach (string proxy in builder.Configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [])
    {
        options.KnownProxies.Add(IPAddress.Parse(proxy));
    }
});

builder.Services
    .AddAuthentication(BearerTokenAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, BearerTokenAuthenticationHandler>(BearerTokenAuthenticationHandler.SchemeName, _ => { });
builder.Services.AddAuthorization();

// Per-IP fixed-window limiter on the unauthenticated auth endpoints (login/mfa-verify/refresh),
// which are otherwise brute-forceable by an anonymous caller regardless of per-account lockout
// (see AuthenticationService's FailedLoginAttempts/LockedUntil) — see docs/features/
// authentication.md "Rate limiting su tentativi di login". No queueing: an attacker gains nothing
// from being queued, and a legitimate user's next real attempt should just be rejected outright,
// not delayed.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy(AuthRateLimiting.PolicyName, httpContext => RateLimitPartition.GetFixedWindowLimiter(
        partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        factory: _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
// Must run before anything that inspects the scheme or the remote IP (rate limiter, HTTPS
// redirection, audit logging) so those see the original client, not the proxy.
app.UseForwardedHeaders();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}
else
{
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRateLimiter();

app.UseAuthentication();
app.UseMiddleware<TenantResolutionMiddleware>();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapUserEndpoints();
app.MapAdminEndpoints();
app.MapVaultEndpoints();
app.MapFolderEndpoints();
app.MapTagEndpoints();
app.MapVaultItemEndpoints();
app.MapVaultMembershipEndpoints();
app.MapAuditEndpoints();

app.Run();

// Exposed for WebApplicationFactory<Program> in integration tests.
public partial class Program;
