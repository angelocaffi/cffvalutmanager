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

    /// <summary>
    /// Every method below that returns a <c>LoginResponse</c>/<c>RecoveryVerifyResponse</c> relies
    /// on this instead of parsing <paramref name="response"/> directly: a non-success status (most
    /// commonly 429 from <c>AuthRateLimiting</c>, which every one of these endpoints is behind) can
    /// come back with an empty or plain-text body, and <c>ReadFromJsonAsync</c> throws
    /// <see cref="JsonException"/> on that — an unhandled exception that crashes the whole page
    /// (found live: a WebAuthn MFA assertion hitting the rate limit crashed Login.razor instead of
    /// showing "too many attempts"). Only ever parse JSON once the status is confirmed 2xx.
    /// </summary>
    private async Task<T> ReadJsonOrFailureAsync<T>(HttpResponseMessage response, Func<string, T> onFailure, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode)
        {
            var parsed = await response.Content.ReadFromJsonAsync<T>(JsonOptions, ct);
            if (parsed is not null)
            {
                return parsed;
            }
        }

        string message = response.StatusCode == System.Net.HttpStatusCode.TooManyRequests
            ? "Troppi tentativi. Riprova tra qualche minuto."
            : "Si è verificato un errore imprevisto. Riprova.";
        return onFailure(message);
    }

    private static LoginResponse FailedLogin(string reason) =>
        new(Success: false, RequiresMfa: false, FailureReason: reason, AccessToken: null, RefreshToken: null,
            MfaChallengeToken: null, AvailableMfaFactors: null, CryptoMaterials: null);

    // RecoveryVerifyResponse has no message field of its own — the caller (Recovery.razor) already
    // shows a fixed generic message on Success:false, same as every other real failure path.
    private static RecoveryVerifyResponse FailedRecovery(string reason) =>
        new(Success: false, RequiresMfa: false, MfaChallengeToken: null, AvailableMfaFactors: null, RecoveryToken: null);

    /// <summary>
    /// Creates a new tenant and its first Admin user. All crypto material (auth hash, wrapped
    /// DEK, salt, KDF parameters) is generated client-side and sent as opaque bytes — the server
    /// never sees the master password or the unwrapped DEK. Fails with a 409-derived message if
    /// the slug or admin email is already taken.
    /// </summary>
    public async Task<(bool Success, string? Error)> ProvisionTenantAsync(
        string tenantName,
        string tenantSlug,
        string adminEmail,
        byte[] authHash,
        byte[] encryptedDek,
        byte[] masterPasswordSalt,
        int kdfMemoryKb,
        int kdfIterations,
        int kdfVersion,
        CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = tenantName,
            TenantSlug = tenantSlug,
            AdminEmail = adminEmail,
            AuthHash = authHash,
            EncryptedDek = encryptedDek,
            MasterPasswordSalt = masterPasswordSalt,
            KdfMemoryKb = kdfMemoryKb,
            KdfIterations = kdfIterations,
            KdfVersion = kdfVersion,
        }, ct);

        if (response.IsSuccessStatusCode)
        {
            return (true, null);
        }

        var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
        return (false, problem?.Error ?? "Impossibile creare l'organizzazione.");
    }

    /// <summary>
    /// Starts the gated self-service signup (see docs/multi-tenancy.md#provisioning-di-un-nuovo-tenant):
    /// nothing is created yet, only a pending request — a verification code is emailed to
    /// <paramref name="adminEmail"/>. Same opaque crypto material as <see cref="ProvisionTenantAsync"/>,
    /// plus billing/anagrafica data collected here for reuse once a paid plan exists.
    /// </summary>
    public async Task<(Guid? RequestId, string? Error)> RequestTenantProvisioningAsync(
        string tenantName,
        string tenantSlug,
        string adminEmail,
        byte[] authHash,
        byte[] encryptedDek,
        byte[] masterPasswordSalt,
        int kdfMemoryKb,
        int kdfIterations,
        int kdfVersion,
        string legalName,
        bool isBusiness,
        string addressLine,
        string city,
        string postalCode,
        string province,
        string country,
        string? vatNumber = null,
        string? taxCode = null,
        string? sdiCode = null,
        string? pecAddress = null,
        string? phone = null,
        CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/tenants/requests", new
        {
            TenantName = tenantName,
            TenantSlug = tenantSlug,
            AdminEmail = adminEmail,
            AuthHash = authHash,
            EncryptedDek = encryptedDek,
            MasterPasswordSalt = masterPasswordSalt,
            KdfMemoryKb = kdfMemoryKb,
            KdfIterations = kdfIterations,
            KdfVersion = kdfVersion,
            LegalName = legalName,
            IsBusiness = isBusiness,
            AddressLine = addressLine,
            City = city,
            PostalCode = postalCode,
            Province = province,
            Country = country,
            VatNumber = vatNumber,
            TaxCode = taxCode,
            SdiCode = sdiCode,
            PecAddress = pecAddress,
            Phone = phone,
        }, ct);

        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadFromJsonAsync<RequestTenantProvisioningResponse>(JsonOptions, ct);
            return (result?.RequestId, null);
        }

        var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions, ct);
        return (null, problem?.Error ?? "Impossibile inviare la richiesta di creazione organizzazione.");
    }

    /// <summary>Confirms the code emailed by <see cref="RequestTenantProvisioningAsync"/>, actually provisioning the tenant.</summary>
    public async Task<(bool Success, string? Error)> ConfirmTenantProvisioningAsync(Guid requestId, string code, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/tenants/requests/confirm", new { RequestId = requestId, Code = code }, ct);
        return response.IsSuccessStatusCode
            ? (true, null)
            : (false, "Codice non valido o scaduto. Riprova o richiedi un nuovo codice.");
    }

    public async Task<PreloginResponse> PreloginAsync(string email, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/prelogin", new { Email = email }, ct);
        return (await response.Content.ReadFromJsonAsync<PreloginResponse>(JsonOptions, ct))!;
    }

    public async Task<LoginResponse> LoginAsync(string email, byte[] authHash, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash }, ct);
        return await ReadJsonOrFailureAsync<LoginResponse>(response, FailedLogin, ct);
    }

    /// <summary>
    /// Silently renews the access/refresh token pair. Returns null only on a network-level
    /// failure (caller should retry); an expired/revoked refresh token instead comes back as a
    /// normal <c>Success: false</c> result, same shape as a failed login.
    /// </summary>
    public async Task<LoginResponse?> RefreshAsync(string refreshToken, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/refresh", new { RefreshToken = refreshToken }, ct);
        return response.IsSuccessStatusCode ? await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions, ct) : null;
    }

    public async Task<LoginResponse> VerifyMfaAsync(string challengeToken, string code, string factor, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            "/api/auth/mfa/verify", new { ChallengeToken = challengeToken, Code = code, Factor = factor }, ct);
        return await ReadJsonOrFailureAsync<LoginResponse>(response, FailedLogin, ct);
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
    /// Sets the caller's long-term X25519 keypair (see docs/features/sharing-access-control.md).
    /// Set-once server-side: a second call returns 409, which the caller should treat as a no-op
    /// (someone/something else already provisioned one for this account).
    /// </summary>
    public async Task<bool> SetKeyPairAsync(byte[] publicKey, byte[] encryptedPrivateKey, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            "/api/auth/keypair",
            new { PublicKey = publicKey, EncryptedPrivateKey = encryptedPrivateKey },
            ct);
        return response.IsSuccessStatusCode;
    }

    /// <summary>The caller's own keypair, needed to unwrap something wrapped for them (e.g. a shared item's key). Null if none has been generated yet.</summary>
    public async Task<KeyPairResponse?> GetKeyPairAsync(CancellationToken ct = default)
    {
        var response = await _http.GetAsync("/api/auth/keypair", ct);
        return response.IsSuccessStatusCode
            ? await response.Content.ReadFromJsonAsync<KeyPairResponse>(JsonOptions, ct)
            : null;
    }

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

    /// <summary>
    /// Starts a WebAuthn registration ceremony; returns the raw CredentialCreateOptions JSON to
    /// hand to the browser. <paramref name="enablePasswordless"/> requests a discoverable
    /// credential with the PRF extension instead of a normal MFA-only one (docs/security-model.md#sblocco-senza-password-via-passkey-webauthn-prf).
    /// </summary>
    public async Task<string> BeginWebAuthnRegistrationAsync(bool enablePasswordless = false, CancellationToken ct = default)
    {
        string query = enablePasswordless ? "?enablePasswordless=true" : string.Empty;
        var response = await _http.PostAsync($"/api/auth/webauthn/register/begin{query}", content: null, ct);
        return await response.Content.ReadAsStringAsync(ct);
    }

    /// <summary>
    /// Completes a WebAuthn registration with the browser's attestation response. Fails with a
    /// 400-derived message if the attestation itself doesn't verify (wrong origin, tampered
    /// response, expired ceremony, etc.). <paramref name="prfWrappedDek"/> is set only when
    /// enrolling for passwordless login — the caller's own DEK, already wrapped client-side with a
    /// key derived from this ceremony's PRF output; opaque ciphertext to the server.
    /// </summary>
    public async Task<(bool Success, string? Error)> CompleteWebAuthnRegistrationAsync(
        string attestationResponseJson, string? nickname, byte[]? prfWrappedDek = null, CancellationToken ct = default)
    {
        using var doc = JsonDocument.Parse(attestationResponseJson);
        var response = await _http.PostAsJsonAsync(
            "/api/auth/webauthn/register/complete",
            new { AttestationResponse = doc.RootElement, Nickname = nickname, PrfWrappedDek = prfWrappedDek },
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
        return await ReadJsonOrFailureAsync<LoginResponse>(response, FailedLogin, ct);
    }

    /// <summary>
    /// Starts a passwordless, usernameless login — no email, no prior password step. Unlike
    /// <see cref="BeginWebAuthnAssertionAsync"/>, there is no challenge token yet; the server hands
    /// back a fresh ceremony id the client must re-present to <see cref="CompletePasskeyLoginAsync"/>.
    /// </summary>
    public async Task<PasskeyLoginBeginResponse> BeginPasskeyLoginAsync(CancellationToken ct = default)
    {
        var response = await _http.PostAsync("/api/auth/webauthn/passkey-login/begin", content: null, ct);
        return (await response.Content.ReadFromJsonAsync<PasskeyLoginBeginResponse>(JsonOptions, ct))!;
    }

    public async Task<LoginResponse> CompletePasskeyLoginAsync(Guid ceremonyId, string assertionResponseJson, CancellationToken ct = default)
    {
        using var doc = JsonDocument.Parse(assertionResponseJson);
        var response = await _http.PostAsJsonAsync(
            "/api/auth/webauthn/passkey-login/complete",
            new { CeremonyId = ceremonyId, AssertionResponse = doc.RootElement },
            ct);
        return await ReadJsonOrFailureAsync<LoginResponse>(response, FailedLogin, ct);
    }

    // ---- TOTP (authenticator app) MFA setup ------------------------------------------------------

    /// <summary>
    /// Starts (or restarts) TOTP enrollment: generates and stores an encrypted, not-yet-active
    /// secret and returns its <c>otpauth://</c> provisioning URI. Safe to call repeatedly before
    /// confirming — each call replaces the pending secret, so a scan that never gets confirmed
    /// never activates MFA.
    /// </summary>
    public async Task<string> BeginTotpSetupAsync(CancellationToken ct = default)
    {
        var response = await _http.PostAsync("/api/auth/mfa/setup", content: null, ct);
        var result = await response.Content.ReadFromJsonAsync<TotpSetupResponse>(JsonOptions, ct);
        return result!.ProvisioningUri;
    }

    /// <summary>Confirms the first code from the authenticator app, activating TOTP as an MFA factor.</summary>
    public async Task<bool> ConfirmTotpSetupAsync(string code, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/mfa/confirm", new { Code = code }, ct);
        return response.IsSuccessStatusCode;
    }

    /// <summary>Turns TOTP off and discards the stored secret. Re-enabling later requires scanning a fresh QR code.</summary>
    public async Task DisableTotpAsync(CancellationToken ct = default) =>
        await _http.PostAsync("/api/auth/mfa/totp/disable", content: null, ct);

    // ---- Recovery kit (see docs/security-model.md#recovery-kit) --------------------------------

    /// <summary>Generates/regenerates a kit for the authenticated caller — overwrites any prior one.</summary>
    public async Task<(bool Success, string? Error)> GenerateRecoveryKitAsync(byte[] recoveryEncryptedDek, byte[] recoveryAuthHash, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            "/api/auth/recovery-kit", new { RecoveryEncryptedDek = recoveryEncryptedDek, RecoveryAuthHash = recoveryAuthHash }, ct);
        return response.IsSuccessStatusCode ? (true, null) : (false, "Impossibile generare il kit di recupero.");
    }

    /// <summary>Always returns a fixed-length blob — real or fake, anti-enumeration (see the server-side implementation).</summary>
    public async Task<byte[]> StartRecoveryAsync(string email, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/recovery/start", new { Email = email }, ct);
        var result = await response.Content.ReadFromJsonAsync<RecoveryStartResponse>(JsonOptions, ct);
        return result!.RecoveryEncryptedDek;
    }

    public async Task<RecoveryVerifyResponse> VerifyRecoveryAsync(string email, byte[] recoveryAuthHash, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/recovery/verify", new { Email = email, RecoveryAuthHash = recoveryAuthHash }, ct);
        return await ReadJsonOrFailureAsync<RecoveryVerifyResponse>(response, FailedRecovery, ct);
    }

    public async Task<RecoveryVerifyResponse> VerifyRecoveryMfaAsync(string challengeToken, string code, string factor, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync(
            "/api/auth/recovery/verify-mfa", new { ChallengeToken = challengeToken, Code = code, Factor = factor }, ct);
        return await ReadJsonOrFailureAsync<RecoveryVerifyResponse>(response, FailedRecovery, ct);
    }

    public async Task<bool> SendRecoveryMfaEmailOtpAsync(string challengeToken, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/recovery/mfa/email-otp/send", new { ChallengeToken = challengeToken }, ct);
        return response.IsSuccessStatusCode;
    }

    public async Task<string?> BeginRecoveryWebAuthnAssertionAsync(string challengeToken, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/recovery/webauthn/begin", new { ChallengeToken = challengeToken }, ct);
        return response.IsSuccessStatusCode ? await response.Content.ReadAsStringAsync(ct) : null;
    }

    public async Task<RecoveryVerifyResponse> CompleteRecoveryWebAuthnAssertionAsync(string challengeToken, string assertionResponseJson, CancellationToken ct = default)
    {
        using var doc = JsonDocument.Parse(assertionResponseJson);
        var response = await _http.PostAsJsonAsync(
            "/api/auth/recovery/webauthn/complete",
            new { ChallengeToken = challengeToken, AssertionResponse = doc.RootElement },
            ct);
        return await ReadJsonOrFailureAsync<RecoveryVerifyResponse>(response, FailedRecovery, ct);
    }

    /// <summary>Submits the new master password after the recovery flow proved Recovery Key possession (+MFA if enabled).</summary>
    public async Task<(bool Success, string? Error)> CompleteRecoveryAsync(
        string recoveryToken,
        byte[] newAuthHash,
        byte[] newEncryptedDek,
        byte[] newMasterPasswordSalt,
        int newKdfMemoryKb,
        int newKdfIterations,
        int newKdfVersion,
        CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/recovery/complete", new
        {
            RecoveryToken = recoveryToken,
            NewAuthHash = newAuthHash,
            NewEncryptedDek = newEncryptedDek,
            NewMasterPasswordSalt = newMasterPasswordSalt,
            NewKdfMemoryKb = newKdfMemoryKb,
            NewKdfIterations = newKdfIterations,
            NewKdfVersion = newKdfVersion,
        }, ct);
        return response.IsSuccessStatusCode ? (true, null) : (false, "Impossibile completare il recupero. Il codice o il token potrebbero essere scaduti.");
    }
}

public sealed record PreloginResponse(byte[] MasterPasswordSalt, int KdfMemoryKb, int KdfIterations, int KdfVersion);

public sealed record CryptoMaterialsResponse(
    byte[] EncryptedDek, byte[]? MasterPasswordSalt, int? KdfMemoryKb, int? KdfIterations, int? KdfVersion, byte[]? PrfWrappedDek = null);

public sealed record PasskeyLoginBeginResponse(Guid CeremonyId, string OptionsJson);

public sealed record LoginResponse(
    bool Success,
    bool RequiresMfa,
    string? FailureReason,
    string? AccessToken,
    string? RefreshToken,
    string? MfaChallengeToken,
    IReadOnlyList<string>? AvailableMfaFactors,
    CryptoMaterialsResponse? CryptoMaterials,
    string? Email = null);

public sealed record UserProfileResponse(
    string Email,
    bool EmailVerified,
    bool MfaEnabled,
    bool MfaEmailOtpEnabled,
    bool HasKeyPair,
    bool HasRecoveryKit,
    DateTimeOffset? RecoveryKitGeneratedAt);

public sealed record KeyPairResponse(byte[] PublicKey, byte[] EncryptedPrivateKey);

public sealed record WebAuthnCredentialResponse(Guid Id, string? Nickname, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);

public sealed record ErrorResponse(string? Error);

public sealed record RequestTenantProvisioningResponse(Guid RequestId);

public sealed record TotpSetupResponse(string ProvisioningUri);

public sealed record RecoveryStartResponse(byte[] RecoveryEncryptedDek);

public sealed record RecoveryVerifyResponse(
    bool Success,
    bool RequiresMfa,
    string? MfaChallengeToken,
    IReadOnlyList<string>? AvailableMfaFactors,
    string? RecoveryToken);
