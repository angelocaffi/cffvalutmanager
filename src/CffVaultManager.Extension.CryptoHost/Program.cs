using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

// Pure .NET-in-browser interop shim, no UI: hosted as the browser extension's offscreen document
// (chrome.offscreen — see docs/security-model.md "Estensione browser"), reusing
// CffVaultManager.Crypto directly instead of a second JS/WASM crypto implementation. Once this
// host finishes starting, CryptoInterop's [JSInvokable] static methods become callable from the
// extension's background service worker via DotNet.invokeMethodAsync. No root component to render
// — nothing in this project has a UI.
var builder = WebAssemblyHostBuilder.CreateDefault(args);
await builder.Build().RunAsync();
