namespace CffVaultManager.Crypto.Abstractions;

public interface IPasskeyDekWrapKeyService
{
    /// <summary>
    /// Derives the 32-byte key used to wrap/unwrap the DEK for passwordless passkey login, from a
    /// WebAuthn PRF extension output. See docs/security-model.md#sblocco-senza-password-via-passkey-webauthn-prf.
    /// </summary>
    /// <remarks>
    /// The PRF output never leaves the browser and is never sent to the server in any form — only
    /// the DEK wrapped with this derived key (via <see cref="IDekService.EncryptDek"/>) is.
    /// </remarks>
    byte[] DeriveKey(ReadOnlySpan<byte> prfOutput);
}
