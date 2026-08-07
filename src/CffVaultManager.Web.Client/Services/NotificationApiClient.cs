namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for the caller's in-app notifications
/// (<c>/api/notifications/*</c>) — the counterpart to the security-alert emails, see
/// docs/features/notifications.md. Never carries vault content, only a short event description.
/// </summary>
public sealed class NotificationApiClient
{
    private readonly HttpClient _http;

    public NotificationApiClient(HttpClient http) => _http = http;

    public async Task<IReadOnlyList<NotificationResponse>> ListAsync(CancellationToken ct = default) =>
        await _http.GetJsonListOrEmptyAsync<NotificationResponse>("/api/notifications", ct);

    /// <summary>0 on any failure — NotificationBell polls this on every route change (see docs/features/notifications.md), so this must never throw.</summary>
    public async Task<int> GetUnreadCountAsync(CancellationToken ct = default) =>
        await _http.GetJsonOrDefaultAsync<int>("/api/notifications/unread-count", ct);

    public async Task<bool> MarkAsReadAsync(Guid id, CancellationToken ct = default) =>
        (await _http.PostAsync($"/api/notifications/{id}/read", null, ct)).IsSuccessStatusCode;

    public async Task<bool> MarkAllAsReadAsync(CancellationToken ct = default) =>
        (await _http.PostAsync("/api/notifications/read-all", null, ct)).IsSuccessStatusCode;
}

public sealed record NotificationResponse(
    Guid Id,
    string Type,
    string Message,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ReadAt);
