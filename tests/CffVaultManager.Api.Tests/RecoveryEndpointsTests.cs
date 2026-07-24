using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CffVaultManager.Crypto;
using CffVaultManager.Crypto.Abstractions;
using Microsoft.AspNetCore.WebUtilities;
using OtpNet;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of the recovery-kit flow (see docs/security-model.md#recovery-kit) over
/// real HTTP, using the real <see cref="CffVaultManager.Crypto"/> services (not opaque random
/// bytes) — same style as CryptoRoundTripTests, since this feature's whole point is unwrapping a
/// real DEK via a real Recovery Key.
/// </summary>
public sealed class RecoveryEndpointsTests : IAsyncLifetime
{
    private const string MasterPassword = "Tr0ub4dor&3-recovery-test";
    private const string NewMasterPassword = "Correct-Horse-Battery-Staple-9";

    // Deliberately much lighter than Argon2Parameters.Default: only the real derivation code path
    // needs to run, not production-calibrated cost.
    private static readonly Argon2Parameters KdfParams = new(memoryKb: 1024, iterations: 1);

    private readonly IKeyDerivationService _kdf = new Argon2KeyDerivationService();
    private readonly IAuthHashService _authHashService = new AuthHashService();
    private readonly IAeadCipherService _cipher = new AesGcmCipherService();
    private readonly IDekService _dekService;
    private readonly IRecoveryKeyService _recoveryKeyService = new RecoveryKeyService();

    private ApiTestFactory _factory = null!;
    private HttpClient _client = null!;

    public RecoveryEndpointsTests() => _dekService = new DekService(_cipher);

    public async Task InitializeAsync()
    {
        _factory = new ApiTestFactory();
        await _factory.EnsureDatabaseCreatedAsync();
        _client = _factory.CreateClient();
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Full_recovery_without_mfa_lets_login_with_the_new_master_password_and_not_the_old_one()
    {
        var (accessToken, authHash, dek) = await ProvisionAndLoginAsync("admin@acme.test");
        var (recoveryKey, recoveryAuthHash) = await GenerateRecoveryKitAsync(accessToken, dek);

        byte[] startedBlob = await StartRecoveryAsync("admin@acme.test");
        byte[] unwrappedDek = _cipher.Decrypt(EncryptedBlob.FromBytes(startedBlob), recoveryKey);
        Assert.Equal(dek, unwrappedDek);

        var verifyResponse = await _client.PostAsJsonAsync(
            "/api/auth/recovery/verify", new { Email = "admin@acme.test", RecoveryAuthHash = recoveryAuthHash });
        Assert.Equal(HttpStatusCode.OK, verifyResponse.StatusCode);
        using var verifyBody = JsonDocument.Parse(await verifyResponse.Content.ReadAsStringAsync());
        Assert.True(verifyBody.RootElement.GetProperty("success").GetBoolean());
        Assert.False(verifyBody.RootElement.GetProperty("requiresMfa").GetBoolean());
        string recoveryToken = verifyBody.RootElement.GetProperty("recoveryToken").GetString()!;

        await CompleteRecoveryAsync(recoveryToken, unwrappedDek);

        var loginNew = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "admin@acme.test", AuthHash = NewAuthHash });
        using var loginNewBody = JsonDocument.Parse(await loginNew.Content.ReadAsStringAsync());
        Assert.True(loginNewBody.RootElement.GetProperty("success").GetBoolean());

        var loginOld = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "admin@acme.test", AuthHash = authHash });
        using var loginOldBody = JsonDocument.Parse(await loginOld.Content.ReadAsStringAsync());
        Assert.False(loginOldBody.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Full_recovery_with_totp_mfa_requires_the_code_before_completing()
    {
        var (accessToken, _, dek) = await ProvisionAndLoginAsync("admin@acme.test");
        byte[] totpSecret = await EnableTotpAsync(accessToken);
        var (_, recoveryAuthHash) = await GenerateRecoveryKitAsync(accessToken, dek);

        var verifyResponse = await _client.PostAsJsonAsync(
            "/api/auth/recovery/verify", new { Email = "admin@acme.test", RecoveryAuthHash = recoveryAuthHash });
        using var verifyBody = JsonDocument.Parse(await verifyResponse.Content.ReadAsStringAsync());
        Assert.True(verifyBody.RootElement.GetProperty("requiresMfa").GetBoolean());
        string challengeToken = verifyBody.RootElement.GetProperty("mfaChallengeToken").GetString()!;

        var mfaResponse = await _client.PostAsJsonAsync("/api/auth/recovery/verify-mfa", new
        {
            ChallengeToken = challengeToken,
            Code = new Totp(totpSecret).ComputeTotp(),
            Factor = "Totp",
        });
        Assert.Equal(HttpStatusCode.OK, mfaResponse.StatusCode);
        using var mfaBody = JsonDocument.Parse(await mfaResponse.Content.ReadAsStringAsync());
        string recoveryToken = mfaBody.RootElement.GetProperty("recoveryToken").GetString()!;

        await CompleteRecoveryAsync(recoveryToken, dek);

        // TOTP is untouched by recovery (only the master password changes) — a login with the new
        // password correctly stops at "requires MFA again", not a full session.
        var loginNew = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "admin@acme.test", AuthHash = NewAuthHash });
        using var loginNewBody = JsonDocument.Parse(await loginNew.Content.ReadAsStringAsync());
        Assert.True(loginNewBody.RootElement.GetProperty("requiresMfa").GetBoolean());

        string loginChallengeToken = loginNewBody.RootElement.GetProperty("mfaChallengeToken").GetString()!;
        var mfaLoginResponse = await _client.PostAsJsonAsync("/api/auth/mfa/verify", new
        {
            ChallengeToken = loginChallengeToken,
            Code = new Totp(totpSecret).ComputeTotp(),
            Factor = "Totp",
        });
        using var mfaLoginBody = JsonDocument.Parse(await mfaLoginResponse.Content.ReadAsStringAsync());
        Assert.True(mfaLoginBody.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Start_for_an_unknown_email_returns_200_with_a_plausible_blob()
    {
        var response = await _client.PostAsJsonAsync("/api/auth/recovery/start", new { Email = "nobody@nowhere.test" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        byte[] blob = body.RootElement.GetProperty("recoveryEncryptedDek").GetBytesFromBase64();
        Assert.NotEmpty(blob);
    }

    [Fact]
    public async Task Verify_with_a_wrong_hash_returns_401_same_shape_for_known_and_unknown_email()
    {
        var (accessToken, _, dek) = await ProvisionAndLoginAsync("admin@acme.test");
        await GenerateRecoveryKitAsync(accessToken, dek);

        var knownWrong = await _client.PostAsJsonAsync(
            "/api/auth/recovery/verify", new { Email = "admin@acme.test", RecoveryAuthHash = RandomBytes(32) });
        var unknown = await _client.PostAsJsonAsync(
            "/api/auth/recovery/verify", new { Email = "nobody@nowhere.test", RecoveryAuthHash = RandomBytes(32) });

        Assert.Equal(HttpStatusCode.Unauthorized, knownWrong.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
    }

    [Fact]
    public async Task A_login_mfa_challenge_token_is_rejected_by_recovery_verify_mfa_and_vice_versa()
    {
        var (accessToken, authHash, dek) = await ProvisionAndLoginAsync("admin@acme.test");
        byte[] totpSecret = await EnableTotpAsync(accessToken);
        var (_, recoveryAuthHash) = await GenerateRecoveryKitAsync(accessToken, dek);

        // A login-minted challenge token...
        var loginAttempt = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "admin@acme.test", AuthHash = authHash });
        using var loginBody = JsonDocument.Parse(await loginAttempt.Content.ReadAsStringAsync());
        string loginChallengeToken = loginBody.RootElement.GetProperty("mfaChallengeToken").GetString()!;

        // ...must not be usable on the recovery MFA endpoint.
        var misuseAttempt = await _client.PostAsJsonAsync("/api/auth/recovery/verify-mfa", new
        {
            ChallengeToken = loginChallengeToken,
            Code = new Totp(totpSecret).ComputeTotp(),
            Factor = "Totp",
        });
        Assert.Equal(HttpStatusCode.Unauthorized, misuseAttempt.StatusCode);

        // And a recovery-minted challenge token must not be usable on the login MFA endpoint.
        var recoveryVerify = await _client.PostAsJsonAsync(
            "/api/auth/recovery/verify", new { Email = "admin@acme.test", RecoveryAuthHash = recoveryAuthHash });
        using var recoveryVerifyBody = JsonDocument.Parse(await recoveryVerify.Content.ReadAsStringAsync());
        string recoveryChallengeToken = recoveryVerifyBody.RootElement.GetProperty("mfaChallengeToken").GetString()!;

        var reverseMisuseAttempt = await _client.PostAsJsonAsync("/api/auth/mfa/verify", new
        {
            ChallengeToken = recoveryChallengeToken,
            Code = new Totp(totpSecret).ComputeTotp(),
            Factor = "Totp",
        });
        using var reverseBody = JsonDocument.Parse(await reverseMisuseAttempt.Content.ReadAsStringAsync());
        Assert.False(reverseBody.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Completing_recovery_invalidates_a_previously_issued_refresh_token()
    {
        var (accessToken, _, dek) = await ProvisionAndLoginAsync("admin@acme.test");
        var (recoveryKey, recoveryAuthHash) = await GenerateRecoveryKitAsync(accessToken, dek);

        // A session established before recovery.
        var preRecoveryLogin = await _client.PostAsJsonAsync("/api/auth/login", new
        {
            Email = "admin@acme.test",
            AuthHash = await LoginAuthHashAsync(),
        });

        byte[] startedBlob = await StartRecoveryAsync("admin@acme.test");
        byte[] unwrappedDek = _cipher.Decrypt(EncryptedBlob.FromBytes(startedBlob), recoveryKey);

        var verifyResponse = await _client.PostAsJsonAsync(
            "/api/auth/recovery/verify", new { Email = "admin@acme.test", RecoveryAuthHash = recoveryAuthHash });
        using var verifyBody = JsonDocument.Parse(await verifyResponse.Content.ReadAsStringAsync());
        string recoveryToken = verifyBody.RootElement.GetProperty("recoveryToken").GetString()!;
        await CompleteRecoveryAsync(recoveryToken, unwrappedDek);

        using var preRecoveryBody = JsonDocument.Parse(await preRecoveryLogin.Content.ReadAsStringAsync());
        string oldRefreshToken = preRecoveryBody.RootElement.GetProperty("refreshToken").GetString()!;
        var refreshAttempt = await _client.PostAsJsonAsync("/api/auth/refresh", new { RefreshToken = oldRefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refreshAttempt.StatusCode);
    }

    [Fact]
    public async Task Rotating_the_dek_invalidates_an_existing_kit()
    {
        var (accessToken, _, dek) = await ProvisionAndLoginAsync("admin@acme.test");
        var (_, recoveryAuthHash) = await GenerateRecoveryKitAsync(accessToken, dek);

        var rotateResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/rotate-dek", accessToken,
            new { NewEncryptedDek = RandomBytes(48), ReencryptedItems = Array.Empty<object>() });
        Assert.Equal(HttpStatusCode.NoContent, rotateResponse.StatusCode);

        var verifyResponse = await _client.PostAsJsonAsync(
            "/api/auth/recovery/verify", new { Email = "admin@acme.test", RecoveryAuthHash = recoveryAuthHash });
        Assert.Equal(HttpStatusCode.Unauthorized, verifyResponse.StatusCode);
    }

    // ---- Helpers ------------------------------------------------------------------------------

    // Set by CompleteRecoveryAsync so the "login with the new password" assertions can reuse it.
    private byte[] NewAuthHash = null!;

    private async Task<(string AccessToken, byte[] AuthHash, byte[] Dek)> ProvisionAndLoginAsync(string email)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] dek;
        byte[] authHash;
        EncryptedBlob wrappedDek;

        using (var kek = _kdf.DeriveKek(MasterPassword, salt, KdfParams))
        {
            authHash = _authHashService.DeriveAuthHash(kek, MasterPassword);
            dek = _dekService.GenerateDek();
            wrappedDek = _dekService.EncryptDek(dek, kek.Key);
        }

        var provisionResponse = await _client.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = "acme",
            TenantSlug = "acme",
            AdminEmail = email,
            AuthHash = authHash,
            EncryptedDek = wrappedDek.ToBytes(),
            MasterPasswordSalt = salt,
            KdfMemoryKb = KdfParams.MemoryKb,
            KdfIterations = KdfParams.Iterations,
            KdfVersion = KdfParams.Version,
        });
        Assert.Equal(HttpStatusCode.Created, provisionResponse.StatusCode);

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash });
        using var loginBody = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        string accessToken = loginBody.RootElement.GetProperty("accessToken").GetString()!;

        return (accessToken, authHash, dek);
    }

    private async Task<byte[]> LoginAuthHashAsync()
    {
        // Re-derives the same auth hash ProvisionAndLoginAsync already used, for a second login
        // against the same account (used only to obtain a second, independent refresh token).
        var prelogin = await _client.PostAsJsonAsync("/api/auth/prelogin", new { Email = "admin@acme.test" });
        using var body = JsonDocument.Parse(await prelogin.Content.ReadAsStringAsync());
        byte[] salt = body.RootElement.GetProperty("masterPasswordSalt").GetBytesFromBase64();
        var kdfParams = new Argon2Parameters(
            body.RootElement.GetProperty("kdfMemoryKb").GetInt32(),
            body.RootElement.GetProperty("kdfIterations").GetInt32(),
            body.RootElement.GetProperty("kdfVersion").GetInt32());
        using var kek = _kdf.DeriveKek(MasterPassword, salt, kdfParams);
        return _authHashService.DeriveAuthHash(kek, MasterPassword);
    }

    private async Task<(byte[] RecoveryKey, byte[] RecoveryAuthHash)> GenerateRecoveryKitAsync(string accessToken, byte[] dek)
    {
        byte[] recoveryKey = _recoveryKeyService.GenerateRecoveryKey();
        byte[] recoveryEncryptedDek = _cipher.Encrypt(dek, recoveryKey).ToBytes();
        byte[] recoveryAuthHash = _recoveryKeyService.DeriveRecoveryAuthHash(recoveryKey);

        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/recovery-kit", accessToken,
            new { RecoveryEncryptedDek = recoveryEncryptedDek, RecoveryAuthHash = recoveryAuthHash });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        return (recoveryKey, recoveryAuthHash);
    }

    private async Task<byte[]> StartRecoveryAsync(string email)
    {
        var response = await _client.PostAsJsonAsync("/api/auth/recovery/start", new { Email = email });
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("recoveryEncryptedDek").GetBytesFromBase64();
    }

    private async Task CompleteRecoveryAsync(string recoveryToken, byte[] dek)
    {
        byte[] newSalt = RandomNumberGenerator.GetBytes(16);
        using var newKek = _kdf.DeriveKek(NewMasterPassword, newSalt, KdfParams);
        NewAuthHash = _authHashService.DeriveAuthHash(newKek, NewMasterPassword);
        var newEncryptedDek = _dekService.EncryptDek(dek, newKek.Key);

        var response = await _client.PostAsJsonAsync("/api/auth/recovery/complete", new
        {
            RecoveryToken = recoveryToken,
            NewAuthHash = NewAuthHash,
            NewEncryptedDek = newEncryptedDek.ToBytes(),
            NewMasterPasswordSalt = newSalt,
            NewKdfMemoryKb = KdfParams.MemoryKb,
            NewKdfIterations = KdfParams.Iterations,
            NewKdfVersion = KdfParams.Version,
        });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private async Task<byte[]> EnableTotpAsync(string accessToken)
    {
        using var setupRequest = new HttpRequestMessage(HttpMethod.Post, "/api/auth/mfa/setup");
        setupRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var setupResponse = await _client.SendAsync(setupRequest);
        using var setupBody = JsonDocument.Parse(await setupResponse.Content.ReadAsStringAsync());
        byte[] secret = ExtractTotpSecret(setupBody.RootElement.GetProperty("provisioningUri").GetString()!);

        var confirmResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/mfa/confirm", accessToken,
            new { Code = new Totp(secret).ComputeTotp() });
        Assert.Equal(HttpStatusCode.OK, confirmResponse.StatusCode);

        return secret;
    }

    private async Task<HttpResponseMessage> SendAuthorizedAsync(HttpMethod method, string url, string accessToken, object body)
    {
        using var request = new HttpRequestMessage(method, url) { Content = JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await _client.SendAsync(request);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    private static byte[] ExtractTotpSecret(string provisioningUri)
    {
        var uri = new Uri(provisioningUri);
        var query = QueryHelpers.ParseQuery(uri.Query);
        string base32Secret = query["secret"]!;
        return Base32Encoding.ToBytes(base32Secret);
    }
}
