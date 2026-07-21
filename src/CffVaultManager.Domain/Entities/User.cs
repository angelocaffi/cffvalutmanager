using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Domain.Entities;

/// <summary>
/// A platform user. A <see cref="UserRole.SuperAdmin"/> has no tenant
/// (<see cref="TenantId"/> is null); every other role belongs to exactly one tenant.
/// Instances are created through <see cref="CreateSuperAdmin"/> or
/// <see cref="CreateTenantUser"/> to keep the TenantId/Role invariant consistent.
/// </summary>
public class User
{
    private User()
    {
        // Parameterless constructor for EF Core / serialization.
        Email = null!;
        EncryptedDek = null!;
    }

    private User(
        Guid id,
        Guid? tenantId,
        string email,
        UserRole role,
        byte[] encryptedDek,
        byte[]? masterPasswordHash,
        byte[]? masterPasswordSalt,
        int? kdfMemoryKb,
        int? kdfIterations,
        int? kdfVersion,
        bool mfaEnabled,
        byte[]? mfaSecret,
        bool mfaEmailOtpEnabled,
        DateTimeOffset createdAt)
    {
        Id = Guard.AgainstEmptyGuid(id);
        Email = Guard.AgainstNullOrWhiteSpace(email);
        Role = role;
        TenantId = tenantId;
        EncryptedDek = Guard.AgainstNullOrEmpty(encryptedDek);
        MasterPasswordHash = masterPasswordHash;
        MasterPasswordSalt = masterPasswordSalt;
        KdfMemoryKb = kdfMemoryKb;
        KdfIterations = kdfIterations;
        KdfVersion = kdfVersion;
        MfaEnabled = mfaEnabled;
        MfaSecret = mfaSecret;
        MfaEmailOtpEnabled = mfaEmailOtpEnabled;
        CreatedAt = createdAt;
    }

    /// <summary>Creates a platform SuperAdmin, which is never bound to a tenant.</summary>
    public static User CreateSuperAdmin(
        Guid id,
        string email,
        byte[] encryptedDek,
        byte[]? masterPasswordHash = null,
        byte[]? masterPasswordSalt = null,
        int? kdfMemoryKb = null,
        int? kdfIterations = null,
        int? kdfVersion = null,
        bool mfaEnabled = false,
        byte[]? mfaSecret = null,
        bool mfaEmailOtpEnabled = false,
        DateTimeOffset? createdAt = null)
    {
        return new User(
            id,
            tenantId: null,
            email,
            UserRole.SuperAdmin,
            encryptedDek,
            masterPasswordHash,
            masterPasswordSalt,
            kdfMemoryKb,
            kdfIterations,
            kdfVersion,
            mfaEnabled,
            mfaSecret,
            mfaEmailOtpEnabled,
            createdAt ?? DateTimeOffset.UtcNow);
    }

    /// <summary>Creates a tenant-scoped user. The role must not be SuperAdmin.</summary>
    public static User CreateTenantUser(
        Guid id,
        Guid tenantId,
        string email,
        UserRole role,
        byte[] encryptedDek,
        byte[]? masterPasswordHash = null,
        byte[]? masterPasswordSalt = null,
        int? kdfMemoryKb = null,
        int? kdfIterations = null,
        int? kdfVersion = null,
        bool mfaEnabled = false,
        byte[]? mfaSecret = null,
        bool mfaEmailOtpEnabled = false,
        DateTimeOffset? createdAt = null)
    {
        if (role == UserRole.SuperAdmin)
        {
            throw new ArgumentException("A SuperAdmin cannot belong to a tenant.", nameof(role));
        }

        Guard.AgainstEmptyGuid(tenantId);

        return new User(
            id,
            tenantId,
            email,
            role,
            encryptedDek,
            masterPasswordHash,
            masterPasswordSalt,
            kdfMemoryKb,
            kdfIterations,
            kdfVersion,
            mfaEnabled,
            mfaSecret,
            mfaEmailOtpEnabled,
            createdAt ?? DateTimeOffset.UtcNow);
    }

    public Guid Id { get; private set; }

    public Guid? TenantId { get; private set; }

    public Tenant? Tenant { get; set; }

    public string Email { get; set; }

    public UserRole Role { get; private set; }

    public byte[]? MasterPasswordHash { get; set; }

    public byte[]? MasterPasswordSalt { get; set; }

    /// <summary>Argon2id memory cost (KiB) used to derive this user's KEK; the client needs it to re-derive at login.</summary>
    public int? KdfMemoryKb { get; set; }

    /// <summary>Argon2id iteration count used to derive this user's KEK.</summary>
    public int? KdfIterations { get; set; }

    /// <summary>Version of the Argon2id parameter set used, for future cost migration.</summary>
    public int? KdfVersion { get; set; }

    public byte[] EncryptedDek { get; set; }

    public bool MfaEnabled { get; set; }

    public byte[]? MfaSecret { get; set; }

    public bool MfaEmailOtpEnabled { get; set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? LastLoginAt { get; set; }

    /// <summary>Null until the user confirms ownership of their email via a one-time code (see docs/features/authentication.md "Verifica email in registrazione").</summary>
    public DateTimeOffset? EmailVerifiedAt { get; set; }

    /// <summary>Consecutive failed login attempts since the last success or the last lockout. Reset to 0 on either.</summary>
    public int FailedLoginAttempts { get; set; }

    /// <summary>While in the future, login is rejected outright regardless of credentials (see docs/features/authentication.md rate limiting).</summary>
    public DateTimeOffset? LockedUntil { get; set; }

    /// <summary>
    /// The user's long-term X25519 public key for organization-vault sharing. Null until the
    /// user's client generates a keypair (lazily on first login after this feature ships, or at
    /// registration for new users going forward). Public key material — not a secret.
    /// </summary>
    public byte[]? PublicKey { get; set; }

    /// <summary>
    /// The user's X25519 private key, wrapped client-side with the user's own DEK (not a separate
    /// KEK) exactly like any other secret they own, so the server never sees it in the clear. Null
    /// until the client generates a keypair.
    /// </summary>
    public byte[]? EncryptedPrivateKey { get; set; }

    public ICollection<OneTimeCode> OneTimeCodes { get; } = new List<OneTimeCode>();

    public ICollection<AuditLogEntry> AuditLogEntries { get; } = new List<AuditLogEntry>();

    public ICollection<Vault> OwnedVaults { get; } = new List<Vault>();
}
