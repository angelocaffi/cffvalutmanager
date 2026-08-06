using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// A registered WebAuthn/FIDO2 authenticator (platform authenticator like Windows Hello/Touch ID,
/// or a roaming one like a security key) — the analogue of <see cref="User.MfaSecret"/> for TOTP,
/// except a user may register several (one per device). Presence of any row for a user is what
/// makes <see cref="MfaFactor.WebAuthn"/> available at login; there is no separate "enabled" flag.
/// </summary>
public class WebAuthnCredential
{
    private WebAuthnCredential()
    {
        // Parameterless constructor for EF Core / serialization.
        CredentialId = null!;
        PublicKey = null!;
    }

    public WebAuthnCredential(
        Guid id,
        Guid userId,
        byte[] credentialId,
        byte[] publicKey,
        uint signCount,
        Guid aaGuid,
        string? nickname = null,
        string? transports = null,
        DateTimeOffset? createdAt = null,
        byte[]? prfWrappedDek = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        UserId = Guard.AgainstEmptyGuid(userId);
        CredentialId = Guard.AgainstNullOrEmpty(credentialId);
        PublicKey = Guard.AgainstNullOrEmpty(publicKey);
        SignCount = signCount;
        AaGuid = aaGuid;
        Nickname = nickname;
        Transports = transports;
        CreatedAt = createdAt ?? DateTimeOffset.UtcNow;
        PrfWrappedDek = prfWrappedDek;
    }

    public Guid Id { get; private set; }

    public Guid UserId { get; private set; }

    public User? User { get; set; }

    /// <summary>The authenticator-assigned credential ID (opaque, not a secret — public identifier).</summary>
    public byte[] CredentialId { get; private set; }

    /// <summary>COSE public key — in the clear by definition, same reasoning as <see cref="User.PublicKey"/>.</summary>
    public byte[] PublicKey { get; set; }

    /// <summary>
    /// The authenticator's signature counter, used for clone detection: a legitimate authenticator's
    /// counter only ever increases. Updated after every successful assertion.
    /// </summary>
    public uint SignCount { get; set; }

    /// <summary>Identifies the authenticator model; informational only.</summary>
    public Guid AaGuid { get; private set; }

    /// <summary>User-chosen label (e.g. "Windows Hello", "YubiKey") to tell registered devices apart.</summary>
    public string? Nickname { get; set; }

    /// <summary>Comma-joined transport hints (usb/nfc/ble/internal/hybrid) reported at registration; informational only.</summary>
    public string? Transports { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? LastUsedAt { get; set; }

    /// <summary>
    /// The DEK, wrapped with a key derived client-side from this credential's WebAuthn PRF output
    /// (see docs/security-model.md#sblocco-senza-password-via-passkey-webauthn-prf) — null unless
    /// this specific credential was registered as discoverable with passwordless enabled. Never
    /// decrypted server-side; cleared (not re-wrapped) by DekRotationService, since the PRF output
    /// isn't re-derivable without a fresh ceremony on this exact device.
    /// </summary>
    public byte[]? PrfWrappedDek { get; set; }
}
