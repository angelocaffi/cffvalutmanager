namespace CffVaultManager.Api.Endpoints;

/// <summary>Shared helpers for pulling audit-log context (client IP/user agent) out of an HTTP request.</summary>
internal static class RequestContext
{
    public static string? ClientIp(HttpContext http) => http.Connection.RemoteIpAddress?.ToString();

    public static string? UserAgent(HttpContext http) =>
        http.Request.Headers.UserAgent.Count > 0 ? http.Request.Headers.UserAgent.ToString() : null;
}
