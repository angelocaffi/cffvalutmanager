using Microsoft.JSInterop;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over wwwroot/js/webauthn.js: converts the server's CredentialCreateOptions/
/// AssertionOptions JSON into real <c>navigator.credentials.create()</c>/<c>get()</c> calls (the
/// byte fields need base64url&lt;-&gt;ArrayBuffer conversion the JSON itself can't carry) and
/// serializes the browser's response back to the JSON shape the server verifies.
/// </summary>
public sealed class WebAuthnJsInterop : IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> _moduleTask;

    public WebAuthnJsInterop(IJSRuntime js) =>
        _moduleTask = new Lazy<Task<IJSObjectReference>>(() =>
            js.InvokeAsync<IJSObjectReference>("import", "./js/webauthn.js").AsTask());

    public async Task<bool> IsAvailableAsync()
    {
        var module = await _moduleTask.Value;
        return await module.InvokeAsync<bool>("isAvailable");
    }

    /// <summary>Whether the device exposes a platform authenticator (Windows Hello/Touch ID/Face ID/etc.), for showing a biometric-specific hint.</summary>
    public async Task<bool> IsPlatformAuthenticatorAvailableAsync()
    {
        var module = await _moduleTask.Value;
        return await module.InvokeAsync<bool>("isPlatformAuthenticatorAvailable");
    }

    /// <summary>Drives <c>navigator.credentials.create()</c> and returns the attestation response JSON, or null if the user cancelled/it failed.</summary>
    public async Task<string?> RegisterAsync(string credentialCreateOptionsJson)
    {
        var module = await _moduleTask.Value;
        try
        {
            return await module.InvokeAsync<string>("register", credentialCreateOptionsJson);
        }
        catch (JSException)
        {
            return null;
        }
    }

    /// <summary>Drives <c>navigator.credentials.get()</c> and returns the assertion response JSON, or null if the user cancelled/it failed.</summary>
    public async Task<string?> AuthenticateAsync(string assertionOptionsJson)
    {
        var module = await _moduleTask.Value;
        try
        {
            return await module.InvokeAsync<string>("authenticate", assertionOptionsJson);
        }
        catch (JSException)
        {
            return null;
        }
    }

    /// <summary>
    /// Drives <c>navigator.credentials.create()</c> with the WebAuthn PRF extension requested, for
    /// passwordless-enrollment (docs/security-model.md#sblocco-senza-password-via-passkey-webauthn-prf).
    /// <c>ResponseJson</c> is what the server verifies; <c>PrfOutput</c> never reaches the server —
    /// callers must derive the DEK-wrap key from it locally and discard it once used. Both null if
    /// the user cancelled or it failed; <c>PrfOutput</c> alone is null if the device/browser
    /// registered the credential but doesn't support PRF (caller must fall back gracefully).
    /// </summary>
    public async Task<(string? ResponseJson, byte[]? PrfOutput)> RegisterWithPrfAsync(string credentialCreateOptionsJson)
    {
        var module = await _moduleTask.Value;
        try
        {
            var result = await module.InvokeAsync<PrfCeremonyResult>("registerWithPrf", credentialCreateOptionsJson);
            return (result.ResponseJson, DecodePrfOutput(result.PrfOutput));
        }
        catch (JSException)
        {
            return (null, null);
        }
    }

    /// <summary>Same as <see cref="RegisterWithPrfAsync"/> but for a usernameless login assertion (<c>navigator.credentials.get()</c>).</summary>
    public async Task<(string? ResponseJson, byte[]? PrfOutput)> AuthenticateWithPrfAsync(string assertionOptionsJson)
    {
        var module = await _moduleTask.Value;
        try
        {
            var result = await module.InvokeAsync<PrfCeremonyResult>("authenticateWithPrf", assertionOptionsJson);
            return (result.ResponseJson, DecodePrfOutput(result.PrfOutput));
        }
        catch (JSException)
        {
            return (null, null);
        }
    }

    private static byte[]? DecodePrfOutput(string? base64Url)
    {
        if (base64Url is null)
        {
            return null;
        }

        string base64 = base64Url.Replace('-', '+').Replace('_', '/');
        base64 = (base64.Length % 4) switch
        {
            2 => base64 + "==",
            3 => base64 + "=",
            _ => base64,
        };
        return Convert.FromBase64String(base64);
    }

    private sealed record PrfCeremonyResult(string ResponseJson, string? PrfOutput);

    public async ValueTask DisposeAsync()
    {
        if (_moduleTask.IsValueCreated)
        {
            var module = await _moduleTask.Value;
            await module.DisposeAsync();
        }
    }
}
