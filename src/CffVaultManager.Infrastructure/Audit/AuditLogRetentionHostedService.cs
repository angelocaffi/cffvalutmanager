using CffVaultManager.Application.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CffVaultManager.Infrastructure.Audit;

/// <summary>
/// Runs <see cref="IAuditLogRetentionService"/> once at startup and then every 24h for the life of
/// the process. A single self-hosted instance, so an in-process timer is enough — no distributed
/// scheduler needed. <see cref="IAuditLogRetentionService"/> is scoped (holds a DbContext), so each
/// tick resolves it from a fresh <see cref="IServiceScope"/>.
/// </summary>
internal sealed class AuditLogRetentionHostedService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<AuditLogRetentionHostedService> _logger;

    public AuditLogRetentionHostedService(IServiceScopeFactory scopeFactory, ILogger<AuditLogRetentionHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        do
        {
            await PurgeAsync(stoppingToken);
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task PurgeAsync(CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var retention = scope.ServiceProvider.GetRequiredService<IAuditLogRetentionService>();
            int purged = await retention.PurgeExpiredEntriesAsync(ct);
            if (purged > 0)
            {
                _logger.LogInformation("Audit log retention: purged {Count} expired entries.", purged);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Audit log retention purge failed.");
        }
    }
}
