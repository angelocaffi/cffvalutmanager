using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using CffVaultManager.Api.Authentication;
using CffVaultManager.Api.Endpoints;
using CffVaultManager.Infrastructure.DependencyInjection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Enums (e.g. UserRole) travel as their string name, not a raw ordinal, over the wire.
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

builder.Services.AddInfrastructure(builder.Configuration);

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
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
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
