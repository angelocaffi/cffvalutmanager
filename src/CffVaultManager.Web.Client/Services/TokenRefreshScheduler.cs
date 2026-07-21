namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Silently renews the access/refresh token pair shortly before the access token expires, so an
/// open tab isn't logged out mid-session just from the JWT's short (15 min) lifetime. Never
/// touches the DEK or re-prompts for the master password — a real page reload still always
/// requires a fresh login, by design (see SessionState). If the refresh itself is rejected
/// (revoked/expired refresh token), the session is torn down like any other unrecoverable auth
/// failure, requiring the user to log in again.
/// </summary>
public sealed class TokenRefreshScheduler : IDisposable
{
    private static readonly TimeSpan RefreshBuffer = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan MinDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(15);

    private readonly SessionState _session;
    private readonly AuthApiClient _authApi;
    private Timer? _timer;

    public TokenRefreshScheduler(SessionState session, AuthApiClient authApi)
    {
        _session = session;
        _authApi = authApi;
        _session.Changed += Reschedule;
        Reschedule();
    }

    private void Reschedule()
    {
        _timer?.Dispose();
        _timer = null;

        if (!_session.IsUnlocked || _session.AccessTokenExpiresAtUtc is not { } expiresAt)
        {
            return;
        }

        TimeSpan delay = expiresAt - RefreshBuffer - DateTimeOffset.UtcNow;
        if (delay < MinDelay)
        {
            delay = MinDelay;
        }

        _timer = new Timer(_ => _ = RunRefreshAsync(), null, delay, Timeout.InfiniteTimeSpan);
    }

    private async Task RunRefreshAsync()
    {
        string? refreshToken = _session.RefreshToken;
        if (refreshToken is null)
        {
            return;
        }

        try
        {
            var result = await _authApi.RefreshAsync(refreshToken);
            if (result is { Success: true, AccessToken: not null, RefreshToken: not null })
            {
                // Triggers SessionState.Changed -> Reschedule, arming the next renewal.
                _session.UpdateTokens(result.AccessToken, result.RefreshToken);
            }
            else
            {
                _session.Clear();
            }
        }
        catch (Exception)
        {
            // Transient network failure — the access token still has ~60s of life left
            // (RefreshBuffer), so retry shortly rather than tearing down a good session. If it's
            // still unreachable when the token truly expires, the next authenticated call 401s
            // and surfaces as a real session failure then.
            _timer?.Dispose();
            _timer = new Timer(_ => _ = RunRefreshAsync(), null, RetryDelay, Timeout.InfiniteTimeSpan);
        }
    }

    public void Dispose()
    {
        _session.Changed -= Reschedule;
        _timer?.Dispose();
    }
}
