using CffVaultManager.Application.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Runs <see cref="ITenantProvisioningRequestService.PurgeExpiredAsync"/> once at startup and then
/// every 24h for the life of the process — mirrors <c>Audit.AuditLogRetentionHostedService</c>. A
/// single self-hosted instance, so an in-process timer is enough; the service is scoped (holds a
/// DbContext), so each tick resolves it from a fresh <see cref="IServiceScope"/>.
/// </summary>
internal sealed class TenantProvisioningRequestCleanupHostedService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<TenantProvisioningRequestCleanupHostedService> _logger;

    public TenantProvisioningRequestCleanupHostedService(
        IServiceScopeFactory scopeFactory, ILogger<TenantProvisioningRequestCleanupHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Waits for the first tick instead of purging immediately at startup (unlike
        // AuditLogRetentionHostedService): expired pending requests are harmless for up to 24h, and
        // this avoids a second DbContext/connection being initialized concurrently with the rest of
        // app startup — a real SQLite thread-safety race (SqliteConnection.CreateFunction) surfaced
        // in the test suite once two hosted services both did this at once.
        using var timer = new PeriodicTimer(Interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await PurgeAsync(stoppingToken);
        }
    }

    private async Task PurgeAsync(CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var requests = scope.ServiceProvider.GetRequiredService<ITenantProvisioningRequestService>();
            int purged = await requests.PurgeExpiredAsync(ct);
            if (purged > 0)
            {
                _logger.LogInformation("Tenant provisioning request cleanup: purged {Count} expired requests.", purged);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Tenant provisioning request cleanup failed.");
        }
    }
}
