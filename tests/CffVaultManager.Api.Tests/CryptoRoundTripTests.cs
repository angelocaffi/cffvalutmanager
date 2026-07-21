using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CffVaultManager.Crypto;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// End-to-end zero-knowledge round trip over real HTTP: uses the actual
/// <see cref="CffVaultManager.Crypto"/> services (not opaque random bytes, unlike the other
/// vault-core tests) to derive a KEK from a master password, wrap a DEK, provision/login through
/// the real Api host, re-derive the KEK from what the server hands back on login, and encrypt/
/// decrypt a real vault item payload — proving the whole client-side crypto pipeline actually
/// interoperates with the server's storage/retrieval path, not just that each piece works in
/// isolation (already covered by CffVaultManager.Crypto.Tests) or that the server accepts opaque
/// bytes (already covered by VaultCoreEndpointsTests).
/// </summary>
public sealed class CryptoRoundTripTests : IAsyncLifetime
{
    private const string MasterPassword = "Tr0ub4dor&3-e2e-test";

    // Deliberately much lighter than Argon2Parameters.Default (which targets 300-500ms): this test
    // only needs the real derivation code path to run, not production-calibrated cost.
    private static readonly Argon2Parameters KdfParams = new(memoryKb: 1024, iterations: 1);

    private readonly IKeyDerivationService _kdf = new Argon2KeyDerivationService();
    private readonly IAuthHashService _authHashService = new AuthHashService();
    private readonly IAeadCipherService _cipher = new AesGcmCipherService();
    private readonly IDekService _dekService;

    private ApiTestFactory _factory = null!;
    private HttpClient _client = null!;

    public CryptoRoundTripTests() => _dekService = new DekService(_cipher);

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
    public async Task Provision_login_and_vault_item_round_trip_with_real_zero_knowledge_crypto()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] dek;
        byte[] authHash;
        EncryptedBlob wrappedDek;

        using (var registrationKek = _kdf.DeriveKek(MasterPassword, salt, KdfParams))
        {
            authHash = _authHashService.DeriveAuthHash(registrationKek, MasterPassword);
            dek = _dekService.GenerateDek();
            wrappedDek = _dekService.EncryptDek(dek, registrationKek.Key);
        }

        var provisionResponse = await _client.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = "acme",
            TenantSlug = "acme",
            AdminEmail = "admin@acme.test",
            AuthHash = authHash,
            EncryptedDek = wrappedDek.ToBytes(),
            MasterPasswordSalt = salt,
            KdfMemoryKb = KdfParams.MemoryKb,
            KdfIterations = KdfParams.Iterations,
            KdfVersion = KdfParams.Version,
        });
        Assert.Equal(HttpStatusCode.Created, provisionResponse.StatusCode);

        // Login: the server only ever re-verifies the auth hash: it never sees the master
        // password, the KEK, or the unwrapped DEK.
        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new { Email = "admin@acme.test", AuthHash = authHash });
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        using var loginBody = JsonDocument.Parse(await loginResponse.Content.ReadAsStringAsync());
        Assert.True(loginBody.RootElement.GetProperty("success").GetBoolean());
        string accessToken = loginBody.RootElement.GetProperty("accessToken").GetString()!;
        var materials = loginBody.RootElement.GetProperty("cryptoMaterials");

        // The client re-derives the KEK from exactly what the server handed back, simulating a
        // fresh session/device that never held the original salt/params in memory.
        byte[] returnedSalt = materials.GetProperty("masterPasswordSalt").GetBytesFromBase64();
        var returnedParams = new Argon2Parameters(
            memoryKb: materials.GetProperty("kdfMemoryKb").GetInt32(),
            iterations: materials.GetProperty("kdfIterations").GetInt32(),
            version: materials.GetProperty("kdfVersion").GetInt32());
        var returnedWrappedDek = EncryptedBlob.FromBytes(materials.GetProperty("encryptedDek").GetBytesFromBase64());

        byte[] unwrappedDek;
        using (var sessionKek = _kdf.DeriveKek(MasterPassword, returnedSalt, returnedParams))
        {
            unwrappedDek = _dekService.DecryptDek(returnedWrappedDek, sessionKek.Key);
        }

        Assert.Equal(dek, unwrappedDek);

        // Encrypt a real secret client-side with the unwrapped DEK, store it, fetch it back over
        // HTTP, and decrypt it — the server only ever touched opaque ciphertext bytes throughout.
        Guid vaultId = await GetOwnedVaultIdAsync(accessToken);
        const string secretPlaintext = "hunter2-super-secret-password";
        var encryptedItem = _cipher.Encrypt(Encoding.UTF8.GetBytes(secretPlaintext), unwrappedDek);

        var createResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", accessToken, new
        {
            Type = "Password",
            EncryptedPayload = encryptedItem.ToBytes(),
            FolderId = (Guid?)null,
            IsFavorite = false,
        });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        using var created = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        Guid itemId = created.RootElement.GetProperty("id").GetGuid();

        var getResponse = await GetAuthorizedAsync($"/api/vaults/{vaultId}/items/{itemId}", accessToken);
        using var fetched = JsonDocument.Parse(await getResponse.Content.ReadAsStringAsync());
        byte[] fetchedPayload = fetched.RootElement.GetProperty("encryptedPayload").GetBytesFromBase64();

        byte[] decrypted = _cipher.Decrypt(EncryptedBlob.FromBytes(fetchedPayload), unwrappedDek);
        Assert.Equal(secretPlaintext, Encoding.UTF8.GetString(decrypted));
    }

    [Fact]
    public async Task Decrypting_a_stored_payload_with_the_wrong_dek_fails_authentication()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] authHash;
        EncryptedBlob wrappedDek;

        using (var registrationKek = _kdf.DeriveKek(MasterPassword, salt, KdfParams))
        {
            authHash = _authHashService.DeriveAuthHash(registrationKek, MasterPassword);
            wrappedDek = _dekService.EncryptDek(_dekService.GenerateDek(), registrationKek.Key);
        }

        await _client.PostAsJsonAsync("/api/tenants", new
        {
            TenantName = "acme",
            TenantSlug = "acme",
            AdminEmail = "admin@acme.test",
            AuthHash = authHash,
            EncryptedDek = wrappedDek.ToBytes(),
            MasterPasswordSalt = salt,
            KdfMemoryKb = KdfParams.MemoryKb,
            KdfIterations = KdfParams.Iterations,
            KdfVersion = KdfParams.Version,
        });

        using var loginBody = JsonDocument.Parse(await (await _client.PostAsJsonAsync(
            "/api/auth/login", new { Email = "admin@acme.test", AuthHash = authHash })).Content.ReadAsStringAsync());
        string accessToken = loginBody.RootElement.GetProperty("accessToken").GetString()!;

        Guid vaultId = await GetOwnedVaultIdAsync(accessToken);
        byte[] dek = _dekService.GenerateDek();
        var encryptedItem = _cipher.Encrypt(Encoding.UTF8.GetBytes("some-secret"), dek);

        var createResponse = await SendAuthorizedAsync(HttpMethod.Post, $"/api/vaults/{vaultId}/items", accessToken, new
        {
            Type = "Password",
            EncryptedPayload = encryptedItem.ToBytes(),
            FolderId = (Guid?)null,
            IsFavorite = false,
        });
        using var created = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        Guid itemId = created.RootElement.GetProperty("id").GetGuid();

        using var fetched = JsonDocument.Parse(await (await GetAuthorizedAsync(
            $"/api/vaults/{vaultId}/items/{itemId}", accessToken)).Content.ReadAsStringAsync());
        byte[] fetchedPayload = fetched.RootElement.GetProperty("encryptedPayload").GetBytesFromBase64();

        // A different (correct-length, but wrong) DEK must fail AEAD authentication rather than
        // silently return garbage plaintext — the server storing ciphertext verbatim means this
        // check only has value if the client-side decrypt path actually rejects a mismatched key.
        byte[] wrongDek = _dekService.GenerateDek();
        Assert.Throws<CryptographicException>(() => _cipher.Decrypt(EncryptedBlob.FromBytes(fetchedPayload), wrongDek));
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private async Task<Guid> GetOwnedVaultIdAsync(string accessToken)
    {
        var response = await GetAuthorizedAsync("/api/vaults", accessToken);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.EnumerateArray().First().GetProperty("id").GetGuid();
    }

    private Task<HttpResponseMessage> GetAuthorizedAsync(string url, string accessToken) =>
        SendAuthorizedAsync(HttpMethod.Get, url, accessToken, null);

    private async Task<HttpResponseMessage> SendAuthorizedAsync(HttpMethod method, string url, string accessToken, object? body)
    {
        using var request = new HttpRequestMessage(method, url);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await _client.SendAsync(request);
    }
}
