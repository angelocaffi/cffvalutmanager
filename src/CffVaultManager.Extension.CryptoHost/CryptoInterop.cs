using CffVaultManager.Crypto;
using CffVaultManager.Crypto.Abstractions;
using Microsoft.JSInterop;

namespace CffVaultManager.Extension.CryptoHost;

/// <summary>
/// The extension's entire crypto surface, called from the background service worker's JS via
/// <c>DotNet.invokeMethodAsync('CffVaultManager.Extension.CryptoHost', ...)</c> once this offscreen
/// document finishes starting (see docs/security-model.md "Estensione browser"). Every parameter
/// and return value that is byte material travels as base64 — the messaging boundary between this
/// document and the background service worker is JSON (<c>chrome.runtime</c>), so this avoids ever
/// needing a binary-safe channel. No state is kept between calls: the caller (background.js) holds
/// the unlocked DEK in its own memory for the duration of its wake episode and passes it back in on
/// every call that needs it — this class never remembers a master password, KEK, or DEK itself.
/// </summary>
public static class CryptoInterop
{
    private static readonly IKeyDerivationService KeyDerivation = new Argon2KeyDerivationService();
    private static readonly IAuthHashService AuthHash = new AuthHashService();
    private static readonly IAeadCipherService Cipher = new AesGcmCipherService();
    private static readonly IAsymmetricKeyExchangeService KeyExchange = new X25519KeyExchangeService(Cipher);

    /// <summary>
    /// Step 1 of login: derives the auth hash sent to <c>POST /api/auth/login</c>, from the KDF
    /// parameters <c>POST /api/auth/prelogin</c> already returned for this email — same two-step
    /// flow as <c>Login.razor</c>, see <see cref="IAuthHashService"/>.
    /// </summary>
    [JSInvokable]
    public static async Task<string> DeriveAuthHashAsync(string masterPassword, string saltBase64, int memoryKb, int iterations, int kdfVersion)
    {
        var parameters = new Argon2Parameters(memoryKb, iterations, version: kdfVersion);
        using var kek = await KeyDerivation.DeriveKekAsync(masterPassword, Convert.FromBase64String(saltBase64), parameters);
        return Convert.ToBase64String(AuthHash.DeriveAuthHash(kek, masterPassword));
    }

    /// <summary>
    /// Step 2, after a successful login: re-derives the same KEK and unwraps <c>EncryptedDek</c>
    /// from the login response into the vault's DEK. The caller holds the result in memory only —
    /// this method does not.
    /// </summary>
    [JSInvokable]
    public static async Task<string> UnlockDekAsync(string masterPassword, string saltBase64, int memoryKb, int iterations, int kdfVersion, string encryptedDekBase64)
    {
        var parameters = new Argon2Parameters(memoryKb, iterations, version: kdfVersion);
        using var kek = await KeyDerivation.DeriveKekAsync(masterPassword, Convert.FromBase64String(saltBase64), parameters);
        byte[] dek = Cipher.Decrypt(EncryptedBlob.FromBytes(Convert.FromBase64String(encryptedDekBase64)), kek.Key);
        return Convert.ToBase64String(dek);
    }

    /// <summary>Encrypts arbitrary plaintext bytes (a captured item's JSON payload) under a 32-byte key (the DEK, or an org vault's DEK).</summary>
    [JSInvokable]
    public static string Encrypt(string plaintextBase64, string keyBase64) =>
        Convert.ToBase64String(Cipher.Encrypt(Convert.FromBase64String(plaintextBase64), Convert.FromBase64String(keyBase64)).ToBytes());

    /// <summary>Decrypts a blob produced by <see cref="Encrypt"/> (or by the server-side/Web.Client counterpart — same <see cref="EncryptedBlob"/> format).</summary>
    [JSInvokable]
    public static string Decrypt(string encryptedBase64, string keyBase64) =>
        Convert.ToBase64String(Cipher.Decrypt(EncryptedBlob.FromBytes(Convert.FromBase64String(encryptedBase64)), Convert.FromBase64String(keyBase64)));

    /// <summary>
    /// Unwraps an organization vault's DEK (see docs/features/sharing-access-control.md), needed only
    /// when the user picks a vault they're not the sole personal owner of. <paramref name="ownEncryptedPrivateKeyBase64"/>
    /// is <c>User.EncryptedPrivateKey</c> (from <c>GET /api/auth/keypair</c>), itself encrypted with
    /// the caller's own DEK exactly like any other secret — decrypted here with <see cref="Decrypt"/>
    /// first, then used to unwrap the vault's own wrapped DEK via X25519 ECIES.
    /// </summary>
    [JSInvokable]
    public static string UnwrapVaultDek(string ephemeralPublicKeyBase64, string ownEncryptedPrivateKeyBase64, string ownDekBase64, string wrappedVaultDekBase64)
    {
        byte[] ownPrivateKey = Cipher.Decrypt(EncryptedBlob.FromBytes(Convert.FromBase64String(ownEncryptedPrivateKeyBase64)), Convert.FromBase64String(ownDekBase64));
        byte[] vaultDek = KeyExchange.UnwrapKey(
            Convert.FromBase64String(ephemeralPublicKeyBase64),
            ownPrivateKey,
            EncryptedBlob.FromBytes(Convert.FromBase64String(wrappedVaultDekBase64)));
        return Convert.ToBase64String(vaultDek);
    }
}
