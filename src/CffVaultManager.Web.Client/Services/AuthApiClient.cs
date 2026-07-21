using System.Net.Http.Json;
using System.Text.Json;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Thin wrapper over the "Api" <see cref="HttpClient"/> for both the unauthenticated login flow
/// (prelogin, login, MFA verification) and the authenticated security-settings calls that follow
/// it (enabling/disabling Email OTP as an MFA factor, reading the caller's own profile). Response
/// DTOs here are local mirrors of the server's Application-layer records — Web.Client cannot
/// reference CffVaultManager.Application (only CffVaultManager.Crypto, per the project's
/// layering), so the JSON shape is duplicated deliberately rather than shared.
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

    /// <summary>
    /// Silently renews the access/refresh token pair. Returns null only on a network-level
    /// failure (caller should retry); an expired/revoked refresh token instead comes back as a
    /// normal <c>Success: false</c> result, same shape as a failed login.
    /// </summary>
    public async Task<LoginResponse?> RefreshAsync(string refreshToken, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/refresh", new { RefreshToken = refreshToken }, ct);
        return await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions, ct);
    }

    public async Task<LoginResponse> VerifyMfaAsync(string challengeToken, string code, string factor, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            "/api/auth/mfa/verify", new { ChallengeToken = challengeToken, Code = code, Factor = factor }, ct);
        return (await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions, ct))!;
    }

    /// <summary>
    /// Triggers sending an Email OTP code for an in-progress MFA challenge — unlike TOTP, whose
    /// code already lives on the user's device, this factor requires an explicit send before the
    /// user has anything to enter. Always "succeeds" from the caller's perspective (uniform
    /// response, no-op server-side if the challenge token doesn't resolve to a real challenge);
    /// only an outright invalid/expired token surfaces as an error.
    /// </summary>
    public async Task<bool> SendMfaEmailOtpAsync(string challengeToken, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/mfa/email-otp/send", new { ChallengeToken = challengeToken }, ct);
        return response.IsSuccessStatusCode;
    }

    /// <summary>The caller's own account status, for rendering the security-settings page.</summary>
    public async Task<UserProfileResponse> GetProfileAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<UserProfileResponse>("/api/auth/me", JsonOptions, ct))!;

    /// <summary>
    /// Enables Email OTP as an MFA factor. Fails with a 409-derived message if the account's
    /// email has never been verified — the server refuses to send codes to an unproven address.
    /// </summary>
    public async Task<(bool Success, string? Error)> EnableEmailOtpMfaAsync(CancellationToken ct = default)
    {
        var response = await _http.PostAsync("/api/auth/mfa/email-otp/enable", content: null, ct);
        if (response.IsSuccessStatusCode)
        {
            return (true, null);
        }

        var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
        return (false, problem?.Error ?? "Impossibile abilitare l'Email OTP.");
    }

    public async Task DisableEmailOtpMfaAsync(CancellationToken ct = default) =>
        await _http.PostAsync("/api/auth/mfa/email-otp/disable", content: null, ct);

    /// <summary>Starts a WebAuthn registration ceremony; returns the raw CredentialCreateOptions JSON to hand to the browser.</summary>
    public async Task<string> BeginWebAuthnRegistrationAsync(CancellationToken ct = default)
    {
        var response = await _http.PostAsync("/api/auth/webauthn/register/begin", content: null, ct);
        return await response.Content.ReadAsStringAsync(ct);
    }

    /// <summary>
    /// Completes a WebAuthn registration with the browser's attestation response. Fails with a
    /// 400-derived message if the attestation itself doesn't verify (wrong origin, tampered
    /// response, expired ceremony, etc.).
    /// </summary>
    public async Task<(bool Success, string? Error)> CompleteWebAuthnRegistrationAsync(
        string attestationResponseJson, string? nickname, CancellationToken ct = default)
    {
        using var doc = JsonDocument.Parse(attestationResponseJson);
        var response = await _http.PostAsJsonAsync(
            "/api/auth/webauthn/register/complete",
            new { AttestationResponse = doc.RootElement, Nickname = nickname },
            ct);

        if (response.IsSuccessStatusCode)
        {
            return (true, null);
        }

        var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
        return (false, problem?.Error ?? "Impossibile registrare il dispositivo.");
    }

    public async Task<IReadOnlyList<WebAuthnCredentialResponse>> ListWebAuthnCredentialsAsync(CancellationToken ct = default) =>
        await _http.GetFromJsonAsync<IReadOnlyList<WebAuthnCredentialResponse>>("/api/auth/webauthn/credentials", JsonOptions, ct) ?? [];

    public async Task RemoveWebAuthnCredentialAsync(Guid credentialId, CancellationToken ct = default) =>
        await _http.PostAsync($"/api/auth/webauthn/credentials/{credentialId}/remove", content: null, ct);

    /// <summary>
    /// Starts a WebAuthn assertion for an in-progress MFA challenge; returns the raw
    /// AssertionOptions JSON to hand to the browser, or null if the challenge token itself is
    /// invalid/expired.
    /// </summary>
    public async Task<string?> BeginWebAuthnAssertionAsync(string challengeToken, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/webauthn/assertion/begin", new { ChallengeToken = challengeToken }, ct);
        return response.IsSuccessStatusCode ? await response.Content.ReadAsStringAsync(ct) : null;
    }

    public async Task<LoginResponse> CompleteWebAuthnAssertionAsync(string challengeToken, string assertionResponseJson, CancellationToken ct = default)
    {
        using var doc = JsonDocument.Parse(assertionResponseJson);
        var response = await _http.PostAsJsonAsync(
            "/api/auth/webauthn/assertion/complete",
            new { ChallengeToken = challengeToken, AssertionResponse = doc.RootElement },
            ct);
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
    IReadOnlyList<string>? AvailableMfaFactors,
    CryptoMaterialsResponse? CryptoMaterials);

public sealed record UserProfileResponse(string Email, bool EmailVerified, bool MfaEnabled, bool MfaEmailOtpEnabled);

public sealed record WebAuthnCredentialResponse(Guid Id, string? Nickname, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);

public sealed record ErrorResponse(string? Error);
