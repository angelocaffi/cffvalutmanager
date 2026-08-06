namespace CffVaultManager.Domain.Enums;

/// <summary>Which WebAuthn ceremony a <see cref="Entities.WebAuthnCeremony"/> row's stored options belong to.</summary>
public enum WebAuthnCeremonyPurpose
{
    Registration,
    Assertion,

    /// <summary>A usernameless login assertion — no <see cref="Entities.WebAuthnCeremony.UserId"/> known yet at "begin" time.</summary>
    PasskeyLogin,
}
