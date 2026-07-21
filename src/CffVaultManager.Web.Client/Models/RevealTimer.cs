namespace CffVaultManager.Web.Client.Models;

/// <summary>
/// Backs the "reveal requires explicit confirmation, then auto-hides after a short window" pattern
/// required for the highest-value secrets (full card number/CVV, wallet private key/seed phrase —
/// see docs/features/credit-cards.md, crypto-wallets.md). A component owns one instance per
/// sensitive field it renders.
/// </summary>
public sealed class RevealTimer : IDisposable
{
    private readonly Action _onExpire;
    private Timer? _timer;

    /// <param name="onExpire">Called (off the UI thread) when the reveal window elapses — the owning component should re-render, e.g. <c>() =&gt; InvokeAsync(StateHasChanged)</c>.</param>
    public RevealTimer(Action onExpire) => _onExpire = onExpire;

    public bool IsRevealed { get; private set; }

    public void Reveal(TimeSpan duration)
    {
        IsRevealed = true;
        _timer?.Dispose();
        _timer = new Timer(_ =>
        {
            IsRevealed = false;
            _onExpire();
        }, null, duration, Timeout.InfiniteTimeSpan);
    }

    public void Hide()
    {
        IsRevealed = false;
        _timer?.Dispose();
        _timer = null;
    }

    public void Dispose() => _timer?.Dispose();
}
