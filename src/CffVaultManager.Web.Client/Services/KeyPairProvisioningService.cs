using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Silently generates and uploads the user's long-term X25519 keypair shortly after they unlock
/// their vault, if they don't have one yet — the prerequisite for any X25519-based sharing (see
/// docs/features/sharing-access-control.md). Runs once per unlocked session; a transient failure is
/// swallowed and simply retried on the next unlock, since the only consequence of not having a
/// keypair yet is that sharing isn't available, not that anything is broken.
/// </summary>
public sealed class KeyPairProvisioningService : IDisposable
{
    private readonly SessionState _session;
    private readonly AuthApiClient _authApi;
    private readonly IAsymmetricKeyExchangeService _keyExchange;
    private readonly IAeadCipherService _aeadCipher;
    private bool _checkedThisSession;

    public KeyPairProvisioningService(
        SessionState session, AuthApiClient authApi, IAsymmetricKeyExchangeService keyExchange, IAeadCipherService aeadCipher)
    {
        _session = session;
        _authApi = authApi;
        _keyExchange = keyExchange;
        _aeadCipher = aeadCipher;
        _session.Changed += OnSessionChanged;
        OnSessionChanged();
    }

    private void OnSessionChanged()
    {
        if (!_session.IsUnlocked)
        {
            _checkedThisSession = false;
            return;
        }

        if (_checkedThisSession)
        {
            return;
        }

        _checkedThisSession = true;
        _ = ProvisionIfNeededAsync();
    }

    private async Task ProvisionIfNeededAsync()
    {
        try
        {
            var profile = await _authApi.GetProfileAsync();
            if (profile is null || profile.HasKeyPair)
            {
                return;
            }

            var (publicKey, privateKey) = _keyExchange.GenerateKeyPair();
            byte[] dek = _session.RequireDek();
            byte[] encryptedPrivateKey = _aeadCipher.Encrypt(privateKey, dek).ToBytes();

            await _authApi.SetKeyPairAsync(publicKey, encryptedPrivateKey);
        }
        catch (Exception)
        {
            // Best-effort: never surfaces as a user-facing error. The next unlock retries.
        }
    }

    public void Dispose() => _session.Changed -= OnSessionChanged;
}
