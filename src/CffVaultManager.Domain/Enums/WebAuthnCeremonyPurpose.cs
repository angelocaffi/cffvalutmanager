namespace CffVaultManager.Domain.Enums;

/// <summary>Which WebAuthn ceremony a <see cref="Entities.WebAuthnCeremony"/> row's stored options belong to.</summary>
public enum WebAuthnCeremonyPurpose
{
    Registration,
    Assertion,
}
