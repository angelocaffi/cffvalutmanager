using Microsoft.JSInterop;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over wwwroot/js/paypal-buttons.js: loads the PayPal SDK on demand and renders the
/// "Smart Buttons" widget, wiring its createOrder/onApprove/onError callbacks back into .NET (see
/// docs/features/billing.md).
/// </summary>
public sealed class PayPalJsInterop : IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> _moduleTask;

    public PayPalJsInterop(IJSRuntime js) =>
        _moduleTask = new Lazy<Task<IJSObjectReference>>(() =>
            js.InvokeAsync<IJSObjectReference>("import", "./js/paypal-buttons.js").AsTask());

    public async Task RenderButtonsAsync<T>(string containerId, string clientId, string currency, DotNetObjectReference<T> dotNetRef) where T : class
    {
        var module = await _moduleTask.Value;
        await module.InvokeVoidAsync("renderButtons", containerId, clientId, currency, dotNetRef);
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
