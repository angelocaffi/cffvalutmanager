using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for the unauthenticated login flow
/// (prelogin, login, MFA verification). Response DTOs here are local mirrors of the server's
/// Application-layer records — Web.Client cannot reference CffVaultManager.Application (only
/// CffVaultManager.Crypto, per the project's layering), so the JSON shape is duplicated
/// deliberately rather than shared.
/// </summary>
public sealed class AuthApiClient
{
    // ASP.NET Core serializes with camelCase property names by default; System.Text.Json's own
    // default is case-sensitive PascalCase, so this must be explicit on every call here (mirrors
    // the same JsonSerializerOptions used throughout CffVaultManager.Api.Tests for the same reason).
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;

    public AuthApiClient(HttpClient http) => _http = http;

    public async Task<PreloginResponse> PreloginAsync(string email, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/prelogin", new { Email = email }, ct);
        return (await response.Content.ReadFromJsonAsync<PreloginResponse>(JsonOptions, ct))!;
    }

    public async Task<LoginResponse> LoginAsync(string email, byte[] authHash, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash }, ct);
        return (await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions, ct))!;
    }

    public async Task<LoginResponse> VerifyMfaAsync(string challengeToken, string code, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            "/api/auth/mfa/verify", new { ChallengeToken = challengeToken, Code = code }, ct);
        return (await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions, ct))!;
    }
}

public sealed record PreloginResponse(byte[] MasterPasswordSalt, int KdfMemoryKb, int KdfIterations, int KdfVersion);

public sealed record CryptoMaterialsResponse(
    byte[] EncryptedDek, byte[]? MasterPasswordSalt, int? KdfMemoryKb, int? KdfIterations, int? KdfVersion);

public sealed record LoginResponse(
    bool Success,
    bool RequiresMfa,
    string? FailureReason,
    string? AccessToken,
    string? RefreshToken,
    string? MfaChallengeToken,
    CryptoMaterialsResponse? CryptoMaterials);
