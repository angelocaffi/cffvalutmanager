using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// Grants a user access to an organization <see cref="Vault"/> within the same tenant. The vault's
/// DEK is wrapped for this member client-side with an ECIES-style X25519 scheme (see
/// docs/features/sharing-access-control.md): <see cref="WrappedVaultDek"/> and
/// <see cref="EphemeralPublicKey"/> are opaque bytes the server only ever stores and returns — it
/// never performs any cryptography on them. A revoked membership keeps its row for audit but sets
/// <see cref="RevokedAt"/>; access is granted only while that is null.
/// </summary>
public class VaultMembership
{
    private VaultMembership()
    {
        // Parameterless constructor for EF Core / serialization.
        WrappedVaultDek = null!;
        EphemeralPublicKey = null!;
    }

    public VaultMembership(
        Guid id,
        Guid tenantId,
        Guid vaultId,
        Guid userId,
        VaultPermission permission,
        byte[] wrappedVaultDek,
        byte[] ephemeralPublicKey,
        Guid invitedByUserId,
        DateTimeOffset? createdAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
        VaultId = Guard.AgainstEmptyGuid(vaultId);
        UserId = Guard.AgainstEmptyGuid(userId);
        Permission = permission;
        WrappedVaultDek = Guard.AgainstNullOrEmpty(wrappedVaultDek);
        EphemeralPublicKey = Guard.AgainstNullOrEmpty(ephemeralPublicKey);
        InvitedByUserId = Guard.AgainstEmptyGuid(invitedByUserId);
        CreatedAt = createdAt ?? DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Guid VaultId { get; private set; }

    public Vault? Vault { get; set; }

    public Guid UserId { get; private set; }

    public User? User { get; set; }

    public VaultPermission Permission { get; private set; }

    /// <summary>The vault DEK wrapped for this member's public key. Opaque to the server.</summary>
    public byte[] WrappedVaultDek { get; private set; }

    /// <summary>The sender's ephemeral X25519 public key used to wrap the DEK. Opaque to the server.</summary>
    public byte[] EphemeralPublicKey { get; private set; }

    public Guid InvitedByUserId { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>Marks this membership revoked; the row is retained for audit.</summary>
    public void Revoke() => RevokedAt = DateTimeOffset.UtcNow;

    /// <summary>
    /// Replaces the wrapped DEK material for a remaining member after a DEK rotation (see the
    /// revoke flow in docs/features/sharing-access-control.md). The new bytes are again computed
    /// client-side; the server only stores them.
    /// </summary>
    public void UpdateWrappedDek(byte[] wrappedVaultDek, byte[] ephemeralPublicKey)
    {
        WrappedVaultDek = Guard.AgainstNullOrEmpty(wrappedVaultDek);
        EphemeralPublicKey = Guard.AgainstNullOrEmpty(ephemeralPublicKey);
    }
}
