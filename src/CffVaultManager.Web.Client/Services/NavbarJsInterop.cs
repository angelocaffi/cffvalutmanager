using Microsoft.JSInterop;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Wraps wwwroot/js/navbar.js: collapses the mobile navbar's hamburger menu, which Bootstrap
/// otherwise leaves open across a Blazor client-side navigation (see the .js file's comment).
/// </summary>
public sealed class NavbarJsInterop : IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> _moduleTask;

    public NavbarJsInterop(IJSRuntime js) =>
        _moduleTask = new Lazy<Task<IJSObjectReference>>(() =>
            js.InvokeAsync<IJSObjectReference>("import", "./js/navbar.js").AsTask());

    public async Task CollapseAsync(string elementId)
    {
        var module = await _moduleTask.Value;
        await module.InvokeVoidAsync("collapseNavbar", elementId);
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
