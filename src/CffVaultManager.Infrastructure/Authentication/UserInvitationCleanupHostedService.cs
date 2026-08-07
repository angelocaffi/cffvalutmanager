using CffVaultManager.Application.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Runs <see cref="IUserInvitationService.PurgeExpiredAsync"/> once every 24h for the life of the
/// process — exact mirror of <see cref="TenantProvisioningRequestCleanupHostedService"/>, including
/// waiting for the first tick instead of purging immediately at startup (same SQLite thread-safety
/// reasoning documented there).
/// </summary>
internal sealed class UserInvitationCleanupHostedService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<UserInvitationCleanupHostedService> _logger;

    public UserInvitationCleanupHostedService(IServiceScopeFactory scopeFactory, ILogger<UserInvitationCleanupHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
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
            var invitations = scope.ServiceProvider.GetRequiredService<IUserInvitationService>();
            int purged = await invitations.PurgeExpiredAsync(ct);
            if (purged > 0)
            {
                _logger.LogInformation("User invitation cleanup: purged {Count} expired invitations.", purged);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "User invitation cleanup failed.");
        }
    }
}
