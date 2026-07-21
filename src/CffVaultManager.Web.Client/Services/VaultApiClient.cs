using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for vault-core reads/writes. Starts
/// minimal (just listing owned vaults, enough to prove the login → unlock pipeline works
/// end-to-end) — grows with each following page (folders/tags/items).
/// </summary>
public sealed class VaultApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;

    public VaultApiClient(HttpClient http) => _http = http;

    public async Task<IReadOnlyList<VaultResponse>> ListVaultsAsync(CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<VaultResponse>>("/api/vaults", JsonOptions, ct) ?? [];
}

public sealed record VaultResponse(Guid Id, string Name, bool IsOrganizationVault);
