using Microsoft.JSInterop;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Wraps wwwroot/js/download.js: triggers a browser download of in-memory text content — used for
/// the encrypted vault backup export (docs/features/import-export.md). Blazor WASM has no
/// filesystem API of its own, so this goes through the standard Blob + object URL + synthetic
/// anchor-click pattern in JS.
/// </summary>
public sealed class FileDownloadJsInterop : IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> _moduleTask;

    public FileDownloadJsInterop(IJSRuntime js) =>
        _moduleTask = new Lazy<Task<IJSObjectReference>>(() =>
            js.InvokeAsync<IJSObjectReference>("import", "./js/download.js").AsTask());

    public async Task DownloadAsync(string filename, string content, string mimeType = "application/json")
    {
        var module = await _moduleTask.Value;
        await module.InvokeVoidAsync("downloadFile", filename, content, mimeType);
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
