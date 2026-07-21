using Microsoft.JSInterop;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Wraps wwwroot/js/clipboard.js: copies a value and clears it again after a short delay — the
/// "auto-clear appunti" requirement wherever a secret (password, CVV, card number, private key,
/// seed phrase) can be copied.
/// </summary>
public sealed class ClipboardJsInterop : IAsyncDisposable
{
    private static readonly TimeSpan DefaultClearDelay = TimeSpan.FromSeconds(20);

    private readonly Lazy<Task<IJSObjectReference>> _moduleTask;

    public ClipboardJsInterop(IJSRuntime js) =>
        _moduleTask = new Lazy<Task<IJSObjectReference>>(() =>
            js.InvokeAsync<IJSObjectReference>("import", "./js/clipboard.js").AsTask());

    public async Task CopyWithAutoClearAsync(string text, TimeSpan? clearAfter = null)
    {
        var module = await _moduleTask.Value;
        await module.InvokeVoidAsync("copyWithAutoClear", text, (int)(clearAfter ?? DefaultClearDelay).TotalMilliseconds);
    }

    public async ValueTask DisposeAsync()
    {
        if (_moduleTask.IsValueCreated)
        {
            var module = await _moduleTask.Value;
            await module.DisposeAsync();
        }
    }
}
