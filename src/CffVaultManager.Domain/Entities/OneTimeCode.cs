using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// A single-use one-time code (email verification, MFA login, recovery).
/// Only the hash of the code is persisted, never the plaintext code.
/// </summary>
public class OneTimeCode
{
    private OneTimeCode()
    {
        // Parameterless constructor for EF Core / serialization.
        CodeHash = null!;
    }

    public OneTimeCode(
        Guid id,
        Guid userId,
        OtpPurpose purpose,
        byte[] codeHash,
        DateTimeOffset expiresAt,
        int maxAttempts,
        DateTimeOffset? createdAt = null,
        string? ipAddress = null,
        string? userAgent = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        UserId = Guard.AgainstEmptyGuid(userId);
        Purpose = purpose;
        CodeHash = Guard.AgainstNullOrEmpty(codeHash);

        if (maxAttempts <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAttempts), maxAttempts, "MaxAttempts must be greater than zero.");
        }

        var created = createdAt ?? DateTimeOffset.UtcNow;
        if (expiresAt <= created)
        {
            throw new ArgumentException("ExpiresAt must be later than CreatedAt.", nameof(expiresAt));
        }

        MaxAttempts = maxAttempts;
        CreatedAt = created;
        ExpiresAt = expiresAt;
        IpAddress = ipAddress;
        UserAgent = userAgent;
    }

    public Guid Id { get; private set; }

    public Guid UserId { get; private set; }

    public User? User { get; set; }

    public OtpPurpose Purpose { get; private set; }

    public byte[] CodeHash { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset? ConsumedAt { get; set; }

    public int AttemptCount { get; set; }

    public int MaxAttempts { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public string? IpAddress { get; private set; }

    public string? UserAgent { get; private set; }
}
