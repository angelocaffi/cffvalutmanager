using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end coverage of WebAuthn/Passkey as an MFA factor (docs/features/authentication.md) over
/// real HTTP: registering a credential, listing/removing it, and completing a login challenge with
/// it. Uses <see cref="FakeWebAuthnAuthenticator"/> as a stand-in for a real browser/authenticator.
/// </summary>
public sealed class WebAuthnEndpointsTests : IAsyncLifetime
{
    private ApiTestFactory _factory = null!;
    private HttpClient _client = null!;

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
    public async Task Register_begin_then_complete_with_a_valid_attestation_creates_a_credential()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("admin@acme.test", authHash);
        string accessToken = await LoginAsync("admin@acme.test", authHash);
        var authenticator = new FakeWebAuthnAuthenticator();

        var options = await BeginRegistrationAsync(accessToken);
        var completeResponse = await CompleteRegistrationAsync(accessToken, authenticator, options, nickname: "My Key");

        Assert.Equal(HttpStatusCode.Created, completeResponse.StatusCode);

        var listResponse = await SendAuthorizedAsync(HttpMethod.Get, "/api/auth/webauthn/credentials", accessToken, body: null);
        using var listBody = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        var credential = Assert.Single(listBody.RootElement.EnumerateArray());
        Assert.Equal("My Key", credential.GetProperty("nickname").GetString());
    }

    [Fact]
    public async Task Login_after_registering_a_credential_requires_a_webauthn_challenge_and_assertion_completes_it()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("admin@acme.test", authHash);
        string accessToken = await LoginAsync("admin@acme.test", authHash);
        var authenticator = new FakeWebAuthnAuthenticator();

        var createOptions = await BeginRegistrationAsync(accessToken);
        await CompleteRegistrationAsync(accessToken, authenticator, createOptions, nickname: null);

        var login = await LoginResponseAsync("admin@acme.test", authHash);
        Assert.False(login.RootElement.GetProperty("success").GetBoolean());
        Assert.True(login.RootElement.GetProperty("requiresMfa").GetBoolean());
        var factors = login.RootElement.GetProperty("availableMfaFactors").EnumerateArray().Select(e => e.GetString()).ToArray();
        Assert.Equal(new[] { "WebAuthn" }, factors);
        string challengeToken = login.RootElement.GetProperty("mfaChallengeToken").GetString()!;

        var beginResponse = await _client.PostAsJsonAsync("/api/auth/webauthn/assertion/begin", new { ChallengeToken = challengeToken });
        Assert.Equal(HttpStatusCode.OK, beginResponse.StatusCode);
        var assertionOptions = AssertionOptions.FromJson(await beginResponse.Content.ReadAsStringAsync());

        authenticator.SignCount++;
        string assertionResponseJson = authenticator.CreateAssertionResponseJson(assertionOptions, ApiTestFactory.WebAuthnOrigin, GetUserId(accessToken));

        var completeResponse = await _client.PostAsJsonAsync("/api/auth/webauthn/assertion/complete", new
        {
            ChallengeToken = challengeToken,
            AssertionResponse = JsonDocument.Parse(assertionResponseJson).RootElement,
        });

        Assert.Equal(HttpStatusCode.OK, completeResponse.StatusCode);
        using var completeBody = JsonDocument.Parse(await completeResponse.Content.ReadAsStringAsync());
        Assert.True(completeBody.RootElement.GetProperty("success").GetBoolean());
        Assert.NotNull(completeBody.RootElement.GetProperty("accessToken").GetString());
    }

    [Fact]
    public async Task PasskeyLogin_beginThenComplete_forAPasswordlessEnrolledCredential_returnsTokensAndThePrfWrappedDek()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("admin@acme.test", authHash);
        string accessToken = await LoginAsync("admin@acme.test", authHash);
        var authenticator = new FakeWebAuthnAuthenticator();
        byte[] prfOutput = RandomBytes(32);
        byte[] prfWrappedDek = RandomBytes(48);

        var beginResponse = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/webauthn/register/begin?enablePasswordless=true", accessToken, body: null);
        Assert.Equal(HttpStatusCode.OK, beginResponse.StatusCode);
        var createOptions = CredentialCreateOptions.FromJson(await beginResponse.Content.ReadAsStringAsync());

        string attestationResponseJson = authenticator.CreateAttestationResponseJson(createOptions, ApiTestFactory.WebAuthnOrigin, prfOutput);
        using var completeRequest = new HttpRequestMessage(HttpMethod.Post, "/api/auth/webauthn/register/complete")
        {
            Content = JsonContent.Create(new
            {
                AttestationResponse = JsonDocument.Parse(attestationResponseJson).RootElement,
                Nickname = (string?)null,
                PrfWrappedDek = prfWrappedDek,
            }),
        };
        completeRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var completeResponse = await _client.SendAsync(completeRequest);
        Assert.Equal(HttpStatusCode.Created, completeResponse.StatusCode);

        var beginLoginResponse = await _client.PostAsync("/api/auth/webauthn/passkey-login/begin", content: null);
        Assert.Equal(HttpStatusCode.OK, beginLoginResponse.StatusCode);
        using var beginLoginBody = JsonDocument.Parse(await beginLoginResponse.Content.ReadAsStringAsync());
        Guid ceremonyId = beginLoginBody.RootElement.GetProperty("ceremonyId").GetGuid();
        var assertionOptions = AssertionOptions.FromJson(beginLoginBody.RootElement.GetProperty("optionsJson").GetString()!);

        authenticator.SignCount++;
        string assertionResponseJson = authenticator.CreateAssertionResponseJson(
            assertionOptions, ApiTestFactory.WebAuthnOrigin, GetUserId(accessToken), prfOutput: prfOutput);

        var completeLoginResponse = await _client.PostAsJsonAsync("/api/auth/webauthn/passkey-login/complete", new
        {
            CeremonyId = ceremonyId,
            AssertionResponse = JsonDocument.Parse(assertionResponseJson).RootElement,
        });

        Assert.Equal(HttpStatusCode.OK, completeLoginResponse.StatusCode);
        using var loginBody = JsonDocument.Parse(await completeLoginResponse.Content.ReadAsStringAsync());
        Assert.True(loginBody.RootElement.GetProperty("success").GetBoolean());
        Assert.NotNull(loginBody.RootElement.GetProperty("accessToken").GetString());
        Assert.Equal("admin@acme.test", loginBody.RootElement.GetProperty("email").GetString());
        byte[] returnedPrfWrappedDek = loginBody.RootElement.GetProperty("cryptoMaterials").GetProperty("prfWrappedDek").GetBytesFromBase64();
        Assert.Equal(prfWrappedDek, returnedPrfWrappedDek);
    }

    [Fact]
    public async Task PasskeyLogin_complete_withAnUnknownCredential_returns401()
    {
        var unregistered = new FakeWebAuthnAuthenticator();

        var beginLoginResponse = await _client.PostAsync("/api/auth/webauthn/passkey-login/begin", content: null);
        using var beginLoginBody = JsonDocument.Parse(await beginLoginResponse.Content.ReadAsStringAsync());
        Guid ceremonyId = beginLoginBody.RootElement.GetProperty("ceremonyId").GetGuid();
        var assertionOptions = AssertionOptions.FromJson(beginLoginBody.RootElement.GetProperty("optionsJson").GetString()!);

        string assertionResponseJson = unregistered.CreateAssertionResponseJson(assertionOptions, ApiTestFactory.WebAuthnOrigin, Guid.NewGuid().ToByteArray());

        var completeLoginResponse = await _client.PostAsJsonAsync("/api/auth/webauthn/passkey-login/complete", new
        {
            CeremonyId = ceremonyId,
            AssertionResponse = JsonDocument.Parse(assertionResponseJson).RootElement,
        });

        Assert.Equal(HttpStatusCode.Unauthorized, completeLoginResponse.StatusCode);
    }

    [Fact]
    public async Task Remove_credential_removes_the_factor_and_login_no_longer_requires_a_challenge()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("admin@acme.test", authHash);
        string accessToken = await LoginAsync("admin@acme.test", authHash);
        var authenticator = new FakeWebAuthnAuthenticator();

        var createOptions = await BeginRegistrationAsync(accessToken);
        var completeResponse = await CompleteRegistrationAsync(accessToken, authenticator, createOptions, nickname: null);
        using var completeBody = JsonDocument.Parse(await completeResponse.Content.ReadAsStringAsync());
        string credentialId = completeBody.RootElement.GetProperty("id").GetString()!;

        var removeResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/auth/webauthn/credentials/{credentialId}/remove", accessToken, body: null);
        Assert.Equal(HttpStatusCode.NoContent, removeResponse.StatusCode);

        var login = await LoginResponseAsync("admin@acme.test", authHash);
        Assert.True(login.RootElement.GetProperty("success").GetBoolean());
        Assert.False(login.RootElement.GetProperty("requiresMfa").GetBoolean());
    }

    [Fact]
    public async Task Assertion_begin_with_an_invalid_challenge_token_returns_401()
    {
        var response = await _client.PostAsJsonAsync("/api/auth/webauthn/assertion/begin", new { ChallengeToken = "not-a-real-token" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Register_complete_with_a_tampered_attestation_returns_400()
    {
        var authHash = RandomBytes(32);
        await ProvisionTenantAsync("admin@acme.test", authHash);
        string accessToken = await LoginAsync("admin@acme.test", authHash);
        var authenticator = new FakeWebAuthnAuthenticator();

        var options = await BeginRegistrationAsync(accessToken);
        string attestationResponseJson = authenticator.CreateAttestationResponseJson(options, ApiTestFactory.WebAuthnOrigin);

        // Corrupt the attestation object so it can never verify.
        var node = System.Text.Json.Nodes.JsonNode.Parse(attestationResponseJson)!;
        node["response"]!["attestationObject"] = "AAAA";

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/webauthn/register/complete")
        {
            Content = JsonContent.Create(new
            {
                AttestationResponse = JsonDocument.Parse(node.ToJsonString()).RootElement,
                Nickname = (string?)null,
            }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var badResponse = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, badResponse.StatusCode);
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task<CredentialCreateOptions> BeginRegistrationAsync(string accessToken)
    {
        var response = await SendAuthorizedAsync(HttpMethod.Post, "/api/auth/webauthn/register/begin", accessToken, body: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return CredentialCreateOptions.FromJson(await response.Content.ReadAsStringAsync());
    }

    private async Task<HttpResponseMessage> CompleteRegistrationAsync(
        string accessToken, FakeWebAuthnAuthenticator authenticator, CredentialCreateOptions options, string? nickname)
    {
        string attestationResponseJson = authenticator.CreateAttestationResponseJson(options, ApiTestFactory.WebAuthnOrigin);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/webauthn/register/complete")
        {
            Content = JsonContent.Create(new
            {
                AttestationResponse = JsonDocument.Parse(attestationResponseJson).RootElement,
                Nickname = nickname,
            }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await _client.SendAsync(request);
    }

    private async Task ProvisionTenantAsync(string adminEmail, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = "acme",
            TenantSlug = "acme",
            AdminEmail = adminEmail,
            AuthHash = authHash,
            EncryptedDek = RandomBytes(4),
            MasterPasswordSalt = RandomBytes(16),
            KdfMemoryKb = 65536,
            KdfIterations = 3,
            KdfVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private async Task<string> LoginAsync(string email, byte[] authHash)
    {
        var login = await LoginResponseAsync(email, authHash);
        return login.RootElement.GetProperty("accessToken").GetString()!;
    }

    private async Task<JsonDocument> LoginResponseAsync(string email, byte[] authHash)
    {
        var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = email, AuthHash = authHash });
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private async Task<HttpResponseMessage> SendAuthorizedAsync(HttpMethod method, string url, string accessToken, object? body)
    {
        using var request = new HttpRequestMessage(method, url) { Content = body is null ? null : JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await _client.SendAsync(request);
    }

    private static byte[] GetUserId(string accessToken)
    {
        string payload = accessToken.Split('.')[1];
        payload = payload.Replace('-', '+').Replace('_', '/');
        payload += new string('=', (4 - payload.Length % 4) % 4);
        using var doc = JsonDocument.Parse(Convert.FromBase64String(payload));
        return Guid.Parse(doc.RootElement.GetProperty("sub").GetString()!).ToByteArray();
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);
}
