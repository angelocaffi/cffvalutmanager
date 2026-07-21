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

// Vault-item form helpers: password generation/strength, card and crypto-wallet format checks.
// All stateless and RNG-only where relevant (see docs/features/password-manager.md).
builder.Services.AddSingleton<IPasswordGeneratorService, PasswordGeneratorService>();
builder.Services.AddSingleton<IPasswordStrengthService, PasswordStrengthService>();
builder.Services.AddSingleton<ICardValidationService, CardValidationService>();
builder.Services.AddSingleton<ICryptoWalletValidationService, CryptoWalletValidationService>();

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
builder.Services.AddScoped<AuditApiClient>();
builder.Services.AddScoped<WebAuthnJsInterop>();
builder.Services.AddScoped<ClipboardJsInterop>();
builder.Services.AddScoped<TokenRefreshScheduler>();

var host = builder.Build();

// Resolved eagerly (never injected into a component) purely so its constructor subscribes to
// SessionState.Changed from app startup, regardless of which page is first navigated to.
host.Services.GetRequiredService<TokenRefreshScheduler>();

await host.RunAsync();
