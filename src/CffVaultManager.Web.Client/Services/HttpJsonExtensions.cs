using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Shared-across-every-*ApiClient safe alternatives to <c>HttpClient.GetFromJsonAsync</c>/
/// <c>HttpContent.ReadFromJsonAsync</c>. Both throw <see cref="JsonException"/> whenever the body
/// isn't valid JSON for the target type — which every non-2xx response risks being (empty body,
/// plain text, an ASP.NET Core default error page), not just the specific 429-from-rate-limiting
/// case that first surfaced this (see AuthApiClient's ReadJsonOrFailureAsync, fixed first because
/// it's what actually crashed live). An unhandled JsonException here crashes the whole Blazor page
/// (found live twice more: a 404 on a deleted vault item, an unrelated tenant-provisioning
/// conflict). These helpers make "the body wasn't parseable JSON" a value, never an exception.
/// </summary>
internal static class HttpJsonExtensions
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>For a GET that lists something: any non-2xx or unparseable body becomes an empty list — the same "nothing to show" state every caller already renders via EmptyState/an empty foreach.</summary>
    public static async Task<IReadOnlyList<T>> GetJsonListOrEmptyAsync<T>(this HttpClient http, string url, CancellationToken ct)
    {
        var response = await http.GetAsync(url, ct);
        if (!response.IsSuccessStatusCode)
        {
            return [];
        }

        try
        {
            return await response.Content.ReadFromJsonAsync<IReadOnlyList<T>>(JsonOptions, ct) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    /// <summary>For a GET returning a single, possibly-absent value: any non-2xx or unparseable body becomes null, same as the server's own "not found" 404/204 responses already do.</summary>
    public static async Task<T?> GetJsonOrDefaultAsync<T>(this HttpClient http, string url, CancellationToken ct)
    {
        var response = await http.GetAsync(url, ct);
        return await response.ReadJsonOrDefaultAsync<T>(ct);
    }

    /// <summary>Same as <see cref="GetJsonOrDefaultAsync{T}(HttpClient, string, CancellationToken)"/>, for a response already in hand (e.g. from a POST).</summary>
    public static async Task<T?> ReadJsonOrDefaultAsync<T>(this HttpResponseMessage response, CancellationToken ct)
    {
        if (!response.IsSuccessStatusCode)
        {
            return default;
        }

        try
        {
            return await response.Content.ReadFromJsonAsync<T>(JsonOptions, ct);
        }
        catch (JsonException)
        {
            return default;
        }
    }

    /// <summary>
    /// The server-side error message for a failed write, if the body happens to be a valid
    /// <see cref="ErrorResponse"/> JSON — <paramref name="fallback"/> otherwise (a 429 from
    /// <c>AuthRateLimiting</c>-style policies, or any other non-JSON error body).
    /// </summary>
    public static async Task<string> ReadErrorOrAsync(this HttpResponseMessage response, string fallback, CancellationToken ct)
    {
        try
        {
            var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
            return problem?.Error ?? fallback;
        }
        catch (JsonException)
        {
            return fallback;
        }
    }
}
