using CffVaultManager.Application.Abstractions;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// Boots the real Api host (real DI wiring, real JWT/tenant-resolution middleware) against an
/// in-memory SQLite database instead of PostgreSQL, mirroring the approach already used by
/// CffVaultManager.Infrastructure.Tests. One instance == one isolated database.
/// </summary>
public sealed class ApiTestFactory : WebApplicationFactory<Program>
{
    public const string JwtSigningKey = "test-signing-key-that-is-comfortably-long-enough-0123456789abcdef";

    /// <summary>Must match what <see cref="FakeWebAuthnAuthenticator"/> signs its fake responses for.</summary>
    public const string WebAuthnRpId = "localhost";

    public const string WebAuthnOrigin = "https://localhost:5001";

    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    /// <summary>The fake registered in place of the real (logging-only) <see cref="IEmailSender"/> — read back to observe one-time codes that would have been emailed.</summary>
    public FakeEmailSender EmailSender { get; } = new();

    public ApiTestFactory() => _connection.Open();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SigningKey"] = JwtSigningKey,
                ["WebAuthn:RelyingPartyId"] = WebAuthnRpId,
                ["WebAuthn:ServerName"] = "Test",
                ["WebAuthn:Origins:0"] = WebAuthnOrigin,
            });
        });

        builder.ConfigureServices(services =>
        {
            // AddDbContext accumulates provider-specific configuration onto the same
            // IDbContextOptionsConfiguration<T> registration; removing only DbContextOptions<T>
            // leaves the Npgsql provider config behind and EF Core refuses to start with two
            // providers registered. Both descriptors must go before re-adding with SQLite.
            services.RemoveAll<DbContextOptions<CffVaultManagerDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<CffVaultManagerDbContext>>();
            services.AddDbContext<CffVaultManagerDbContext>(options => options.UseSqlite(_connection));

            // Swap the real (logging-only) email sender for a fake the test can read back from.
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(EmailSender);

            // Removed unconditionally (rather than relying on config-key overrides above) so tests
            // never depend on, or make live calls with, real PayPal sandbox credentials that
            // happen to be present in the developer machine's own user-secrets for the real Api
            // project — Development-environment test hosts load those too, and user-secrets can
            // outrank an in-memory config override depending on provider ordering.
            // BillingEndpointsTests swaps in its own FakePayPalClient per-test where needed.
            services.RemoveAll<IPayPalClient>();
        });
    }

    public async Task EnsureDatabaseCreatedAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CffVaultManagerDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _connection.Dispose();
        }
    }
}
