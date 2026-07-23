using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for the SuperAdmin-only platform
/// administration surface (<c>/api/admin/*</c>): tenant metadata and usage counters, never vault
/// content — see docs/features/roles-permissions.md. The server itself is the only place that
/// enforces the SuperAdmin role requirement; this client has no role-specific logic of its own.
/// </summary>
public sealed class AdminApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;

    public AdminApiClient(HttpClient http) => _http = http;

    public async Task<IReadOnlyList<TenantSummaryResponse>> ListTenantsAsync(CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<TenantSummaryResponse>>("/api/admin/tenants", JsonOptions, ct) ?? [];

    public async Task<TenantUsageResponse?> GetTenantUsageAsync(Guid tenantId, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/api/admin/tenants/{tenantId}/usage", ct);
        return response.IsSuccessStatusCode
            ? await response.Content.ReadFromJsonAsync<TenantUsageResponse>(JsonOptions, ct)
            : null;
    }

    public async Task<bool> SuspendTenantAsync(Guid tenantId, CancellationToken ct = default) =>
        (await _http.PostAsync($"/api/admin/tenants/{tenantId}/suspend", content: null, ct)).IsSuccessStatusCode;

    public async Task<bool> ReactivateTenantAsync(Guid tenantId, CancellationToken ct = default) =>
        (await _http.PostAsync($"/api/admin/tenants/{tenantId}/reactivate", content: null, ct)).IsSuccessStatusCode;
}

public sealed record TenantSummaryResponse(
    Guid Id,
    string Name,
    string Slug,
    string Status,
    string? PlanName,
    int UserCount,
    int VaultCount,
    DateTimeOffset CreatedAt);

public sealed record TenantUsageResponse(
    Guid TenantId,
    string Name,
    string Slug,
    string Status,
    int UserCount,
    int VaultCount,
    int VaultItemCount,
    DateTimeOffset? LastUserLoginAt);

/// <summary>Local mirror of Domain.Enums.TenantStatus — kept as plain strings per the layering note in VaultApiClient.VaultItemTypes.</summary>
public static class TenantStatuses
{
    public const string Active = "Active";
    public const string Suspended = "Suspended";
    public const string PendingSetup = "PendingSetup";
}
