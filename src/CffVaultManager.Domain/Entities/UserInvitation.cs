using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// A pending invitation for someone to join an existing tenant as a new user (see
/// docs/features/roles-permissions.md "Invito di nuovi utenti"). <see cref="Token"/> — not the
/// database <see cref="Id"/> — is the unguessable, high-entropy identifier used to look this row
/// up anonymously from the public accept-invitation flow, same trade-off already accepted for
/// <see cref="ExternalShareLink.Token"/> (stored in clear; 256 bits of entropy makes offline
/// guessing infeasible). No crypto material lives here: the invitee derives their own
/// AuthHash/EncryptedDek client-side only once they open the link and choose a master password —
/// an inviting Admin can never produce those on someone else's behalf.
/// </summary>
public class UserInvitation
{
    private UserInvitation()
    {
        // Parameterless constructor for EF Core.
        Email = null!;
        Token = null!;
    }

    public UserInvitation(
        Guid id,
        Guid tenantId,
        string email,
        UserRole role,
        Guid invitedByUserId,
        string token,
        DateTimeOffset expiresAt,
        DateTimeOffset? createdAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
        Email = Guard.AgainstNullOrWhiteSpace(email);
        Role = role;
        InvitedByUserId = Guard.AgainstEmptyGuid(invitedByUserId);
        Token = Guard.AgainstNullOrWhiteSpace(token);
        ExpiresAt = expiresAt;
        CreatedAt = createdAt ?? DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Tenant? Tenant { get; set; }

    public string Email { get; private set; }

    public UserRole Role { get; private set; }

    public Guid InvitedByUserId { get; private set; }

    public User? InvitedByUser { get; set; }

    /// <summary>High-entropy random identifier used for anonymous lookup. Never the database Id.</summary>
    public string Token { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    public bool IsExpiredOrRevoked(DateTimeOffset now) => RevokedAt is not null || ExpiresAt <= now;

    /// <summary>Marks this invitation revoked; a subsequent accept attempt is rejected regardless of expiry.</summary>
    public void Revoke() => RevokedAt = DateTimeOffset.UtcNow;
}
