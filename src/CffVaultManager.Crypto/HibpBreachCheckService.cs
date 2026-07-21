using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

/// <summary>See <see cref="IBreachCheckService"/>. Runs client-side; the caller supplies the <see cref="HttpClient"/> (a dedicated one pointed at the HIBP host, not the app's own Api client).</summary>
public sealed class HibpBreachCheckService : IBreachCheckService
{
    private const string RangeUrlFormat = "https://api.pwnedpasswords.com/range/{0}";

    private readonly HttpClient _http;

    public HibpBreachCheckService(HttpClient http) => _http = http;

    public async Task<long> CheckPasswordAsync(string password, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(password);

        // SHA-1 here is mandated by the k-anonymity API's own protocol (that's the hash HIBP's
        // corpus is indexed by) — not a security choice of ours, and never used for anything else
        // in this project (Argon2id/AES-256-GCM elsewhere for anything that actually needs to be
        // secure). Only the 5-character prefix ever leaves the client.
        byte[] hash = SHA1.HashData(Encoding.UTF8.GetBytes(password));
        string hex = Convert.ToHexString(hash);
        string prefix = hex[..5];
        string suffix = hex[5..];

        using var request = new HttpRequestMessage(HttpMethod.Get, string.Format(RangeUrlFormat, prefix));
        // Asks the API to mix in decoy entries so the response size alone can't reveal whether a
        // match was found — a documented HIBP privacy feature, essentially free to opt into.
        request.Headers.Add("Add-Padding", "true");

        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        string body = await response.Content.ReadAsStringAsync(ct);

        foreach (string rawLine in body.Split('\n'))
        {
            string line = rawLine.Trim();
            int separatorIndex = line.IndexOf(':');
            if (separatorIndex < 0)
            {
                continue;
            }

            string lineSuffix = line[..separatorIndex];
            if (!string.Equals(lineSuffix, suffix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string countText = line[(separatorIndex + 1)..].Trim();
            return long.TryParse(countText, out long count) ? count : 0;
        }

        return 0;
    }
}
