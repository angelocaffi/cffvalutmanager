namespace CffVaultManager.Domain.Entities;

/// <summary>
/// A persisted refresh token. Only the hash of the token is stored, never the plaintext,
/// so a database leak cannot be replayed. Rotation is tracked via
/// <see cref="ReplacedByTokenId"/> so a whole token chain can be invalidated on reuse.
/// </summary>
public class RefreshToken
{
    private RefreshToken()
    {
        // Parameterless constructor for EF Core / serialization.
        TokenHash = null!;
    }

    public RefreshToken(
        Guid id,
        Guid userId,
        byte[] tokenHash,
        DateTimeOffset expiresAt,
        DateTimeOffset? createdAt = null,
        string? createdByIp = null,
        string? createdByUserAgent = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        UserId = Guard.AgainstEmptyGuid(userId);
        TokenHash = Guard.AgainstNullOrEmpty(tokenHash);

        var created = createdAt ?? DateTimeOffset.UtcNow;
        if (expiresAt <= created)
        {
            throw new ArgumentException("ExpiresAt must be later than CreatedAt.", nameof(expiresAt));
        }

        CreatedAt = created;
        ExpiresAt = expiresAt;
        CreatedByIp = createdByIp;
        CreatedByUserAgent = createdByUserAgent;
    }

    public Guid Id { get; private set; }

    public Guid UserId { get; private set; }

    public User? User { get; set; }

    public byte[] TokenHash { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public Guid? ReplacedByTokenId { get; set; }

    public string? CreatedByIp { get; private set; }

    public string? CreatedByUserAgent { get; private set; }

    /// <summary>True while the token is neither revoked nor expired.</summary>
    public bool IsActive => RevokedAt is null && ExpiresAt > DateTimeOffset.UtcNow;
}
