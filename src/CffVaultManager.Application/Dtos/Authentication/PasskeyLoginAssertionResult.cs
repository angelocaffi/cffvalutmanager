namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Result of verifying a usernameless WebAuthn assertion — the user, discovered from the
/// assertion's credential id (never known upfront, unlike every other WebAuthn ceremony), together
/// with the ciphertext its DEK is wrapped in for this specific device
/// (docs/security-model.md#sblocco-senza-password-via-passkey-webauthn-prf).
/// </summary>
public sealed record PasskeyLoginAssertionResult(Guid UserId, byte[] PrfWrappedDek);
