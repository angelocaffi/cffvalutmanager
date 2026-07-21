using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// Server-side state for an in-progress WebAuthn ceremony (registration or assertion) — the
/// options object handed to <c>navigator.credentials.create()</c>/<c>get()</c> must be re-presented
/// unchanged when verifying the browser's response, so it is persisted here between the "begin"
/// and "complete" calls, the same short-lived-row pattern <see cref="OneTimeCode"/> already uses.
/// </summary>
public class WebAuthnCeremony
{
    private WebAuthnCeremony()
    {
        // Parameterless constructor for EF Core / serialization.
        OptionsJson = null!;
    }

    public WebAuthnCeremony(
        Guid id,
        Guid userId,
        WebAuthnCeremonyPurpose purpose,
        string optionsJson,
        DateTimeOffset expiresAt,
        DateTimeOffset? createdAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        UserId = Guard.AgainstEmptyGuid(userId);
        Purpose = purpose;
        OptionsJson = Guard.AgainstNullOrWhiteSpace(optionsJson);

        var created = createdAt ?? DateTimeOffset.UtcNow;
        if (expiresAt <= created)
        {
            throw new ArgumentException("ExpiresAt must be later than CreatedAt.", nameof(expiresAt));
        }

        CreatedAt = created;
        ExpiresAt = expiresAt;
    }

    public Guid Id { get; private set; }

    public Guid UserId { get; private set; }

    public User? User { get; set; }

    public WebAuthnCeremonyPurpose Purpose { get; private set; }

    /// <summary>The serialized <c>CredentialCreateOptions</c>/<c>AssertionOptions</c> to re-present at verification.</summary>
    public string OptionsJson { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset? ConsumedAt { get; set; }

    public DateTimeOffset CreatedAt { get; private set; }
}
