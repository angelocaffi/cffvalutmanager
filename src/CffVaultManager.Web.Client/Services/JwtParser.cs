using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Reads the claims out of an access token's payload for display/session purposes. Never
/// verifies the signature — the token just arrived over HTTPS from our own server, which is the
/// only party that needs to (and does, on every subsequent call) verify it cryptographically.
/// </summary>
internal static class JwtParser
{
    public static (Guid UserId, Guid? TenantId, string Role) ParseAccessToken(string jwt)
    {
        var root = ParsePayload(jwt);

        Guid userId = Guid.Parse(root.GetProperty("sub").GetString()!);
        Guid? tenantId = root.TryGetProperty("tenant_id", out var tenantProp) ? Guid.Parse(tenantProp.GetString()!) : null;
        string role = root.GetProperty("role").GetString()!;

        return (userId, tenantId, role);
    }

    /// <summary>The token's "exp" claim (standard JWT expiry, seconds since Unix epoch), used to schedule a silent refresh ahead of time.</summary>
    public static DateTimeOffset GetExpiryUtc(string jwt)
    {
        var root = ParsePayload(jwt);
        return DateTimeOffset.FromUnixTimeSeconds(root.GetProperty("exp").GetInt64());
    }

    private static JsonElement ParsePayload(string jwt)
    {
        string[] parts = jwt.Split('.');
        if (parts.Length < 2)
        {
            throw new FormatException("Not a well-formed JWT.");
        }

        byte[] payloadBytes = Convert.FromBase64String(PadBase64Url(parts[1]));
        using var doc = JsonDocument.Parse(payloadBytes);
        return doc.RootElement.Clone();
    }

    private static string PadBase64Url(string base64Url)
    {
        string base64 = base64Url.Replace('-', '+').Replace('_', '/');
        return (base64.Length % 4) switch
        {
            2 => base64 + "==",
            3 => base64 + "=",
            _ => base64,
        };
    }
}
