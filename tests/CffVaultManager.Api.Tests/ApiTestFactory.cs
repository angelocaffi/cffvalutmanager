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
/// in-memory SQLite database instead of SQL Server, mirroring the approach already used by
/// CffVaultManager.Infrastructure.Tests. One instance == one isolated database.
/// </summary>
public sealed class ApiTestFactory : WebApplicationFactory<Program>
{
    public const string JwtSigningKey = "test-signing-key-that-is-comfortably-long-enough-0123456789abcdef";

    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public ApiTestFactory() => _connection.Open();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SigningKey"] = JwtSigningKey,
            });
        });

        builder.ConfigureServices(services =>
        {
            // AddDbContext accumulates provider-specific configuration onto the same
            // IDbContextOptionsConfiguration<T> registration; removing only DbContextOptions<T>
            // leaves the SQL Server provider config behind and EF Core refuses to start with two
            // providers registered. Both descriptors must go before re-adding with SQLite.
            services.RemoveAll<DbContextOptions<CffVaultManagerDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<CffVaultManagerDbContext>>();
            services.AddDbContext<CffVaultManagerDbContext>(options => options.UseSqlite(_connection));
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
