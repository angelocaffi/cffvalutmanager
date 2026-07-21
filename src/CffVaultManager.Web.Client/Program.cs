using CffVaultManager.Crypto;
using CffVaultManager.Crypto.Abstractions;
using CffVaultManager.Web.Client.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

// Client-side crypto: same services/behavior as the server (Argon2id via Konscious with
// DegreeOfParallelism forced to 1, AES-256-GCM via BouncyCastle) — both already verified to run
// under the browser-wasm runtime, see docs/features/encryption-key-management.md.
builder.Services.AddSingleton<IKeyDerivationService, Argon2KeyDerivationService>();
builder.Services.AddSingleton<IAeadCipherService, AesGcmCipherService>();
builder.Services.AddSingleton<IDekService, DekService>();
builder.Services.AddSingleton<IAuthHashService, AuthHashService>();

builder.Services.AddSingleton<SessionState>();
builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<AuthenticationStateProvider, VaultAuthenticationStateProvider>();

builder.Services.AddTransient<BearerTokenHandler>();
builder.Services.AddHttpClient("Api", client =>
    client.BaseAddress = new Uri(builder.Configuration["Api:BaseUrl"] ?? builder.HostEnvironment.BaseAddress))
    .AddHttpMessageHandler<BearerTokenHandler>();

// Typed API clients all resolve the same named "Api" HttpClient — new ones (vault items, cards,
// wallets, memberships) just add another AddScoped<TClient> line here, reusing this factory.
builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("Api"));
builder.Services.AddScoped<AuthApiClient>();
builder.Services.AddScoped<VaultApiClient>();

await builder.Build().RunAsync();
