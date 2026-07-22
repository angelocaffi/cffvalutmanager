using Microsoft.JSInterop;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Wraps wwwroot/js/urlFragment.js: reads/writes the URL fragment (after '#'), which per HTTP spec
/// never reaches the server — the transport for the external share-link decryption key (see
/// docs/features/sharing-access-control.md "Link di condivisione esterna").
/// </summary>
public sealed class UrlFragmentJsInterop : IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> _moduleTask;

    public UrlFragmentJsInterop(IJSRuntime js) =>
        _moduleTask = new Lazy<Task<IJSObjectReference>>(() =>
            js.InvokeAsync<IJSObjectReference>("import", "./js/urlFragment.js").AsTask());

    public async Task<string> GetHashAsync()
    {
        var module = await _moduleTask.Value;
        return await module.InvokeAsync<string>("getHash");
    }

    public async Task SetHashAsync(string value)
    {
        var module = await _moduleTask.Value;
        await module.InvokeVoidAsync("setHash", value);
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
