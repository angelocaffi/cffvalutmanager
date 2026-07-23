using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for the caller's in-app notifications
/// (<c>/api/notifications/*</c>) — the counterpart to the security-alert emails, see
/// docs/features/notifications.md. Never carries vault content, only a short event description.
/// </summary>
public sealed class NotificationApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;

    public NotificationApiClient(HttpClient http) => _http = http;

    public async Task<IReadOnlyList<NotificationResponse>> ListAsync(CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<NotificationResponse>>("/api/notifications", JsonOptions, ct) ?? [];

    public async Task<int> GetUnreadCountAsync(CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<int>("/api/notifications/unread-count", JsonOptions, ct);

    public async Task MarkAsReadAsync(Guid id, CancellationToken ct = default)
    {
        var response = await _http.PostAsync($"/api/notifications/{id}/read", null, ct);
        response.EnsureSuccessStatusCode();
    }

    public async Task MarkAllAsReadAsync(CancellationToken ct = default)
    {
        var response = await _http.PostAsync("/api/notifications/read-all", null, ct);
        response.EnsureSuccessStatusCode();
    }
}

public sealed record NotificationResponse(
    Guid Id,
    string Type,
    string Message,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ReadAt);
