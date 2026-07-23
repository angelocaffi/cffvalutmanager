using Microsoft.JSInterop;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Wraps wwwroot/js/theme.js: reads the current light/dark theme (as applied to
/// &lt;html data-bs-theme&gt; — set synchronously by an inline script in App.razor before Blazor
/// starts, to avoid a flash of the wrong theme) and persists an explicit user choice.
/// </summary>
public sealed class ThemeJsInterop : IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> _moduleTask;

    public ThemeJsInterop(IJSRuntime js) =>
        _moduleTask = new Lazy<Task<IJSObjectReference>>(() =>
            js.InvokeAsync<IJSObjectReference>("import", "./js/theme.js").AsTask());

    public async Task<string> GetCurrentThemeAsync()
    {
        var module = await _moduleTask.Value;
        return await module.InvokeAsync<string>("getCurrentTheme");
    }

    public async Task SetThemeAsync(string theme)
    {
        var module = await _moduleTask.Value;
        await module.InvokeVoidAsync("setTheme", theme);
    }

    public async Task ReapplyStoredThemeAsync()
    {
        var module = await _moduleTask.Value;
        await module.InvokeVoidAsync("reapplyStoredTheme");
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
