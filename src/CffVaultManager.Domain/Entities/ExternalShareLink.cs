namespace CffVaultManager.Domain.Entities;

/// <summary>
/// A time-limited, anonymous link to a single vault item's content, for sharing outside the tenant
/// with someone who has no account (see docs/features/sharing-access-control.md "Link di
/// condivisione esterna"). <see cref="EncryptedPayload"/> is a snapshot re-encrypted client-side with
/// a one-off symmetric key that never reaches the server: only the recipient, holding that key in
/// the URL fragment, can decrypt it. <see cref="Token"/> — not the database <see cref="Id"/> — is the
/// unguessable, high-entropy identifier used to look this row up anonymously.
/// </summary>
public class ExternalShareLink
{
    private ExternalShareLink()
    {
        // Parameterless constructor for EF Core.
        Token = null!;
        EncryptedPayload = null!;
    }

    public ExternalShareLink(
        Guid id,
        Guid tenantId,
        Guid vaultItemId,
        Guid createdByUserId,
        string token,
        byte[] encryptedPayload,
        DateTimeOffset expiresAt,
        DateTimeOffset? createdAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
        VaultItemId = Guard.AgainstEmptyGuid(vaultItemId);
        CreatedByUserId = Guard.AgainstEmptyGuid(createdByUserId);
        Token = Guard.AgainstNullOrWhiteSpace(token);
        EncryptedPayload = Guard.AgainstNullOrEmpty(encryptedPayload);
        ExpiresAt = expiresAt;
        CreatedAt = createdAt ?? DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Guid VaultItemId { get; private set; }

    public VaultItem? VaultItem { get; set; }

    public Guid CreatedByUserId { get; private set; }

    public User? CreatedByUser { get; set; }

    /// <summary>High-entropy random identifier used for anonymous lookup. Never the database Id.</summary>
    public string Token { get; private set; }

    /// <summary>Opaque ciphertext, cifrata client-side con una chiave monouso mai inviata al server.</summary>
    public byte[] EncryptedPayload { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    public bool IsExpiredOrRevoked(DateTimeOffset now) => RevokedAt is not null || ExpiresAt <= now;

    /// <summary>Marks this link revoked; the row is removed on its next access attempt regardless.</summary>
    public void Revoke() => RevokedAt = DateTimeOffset.UtcNow;
}
