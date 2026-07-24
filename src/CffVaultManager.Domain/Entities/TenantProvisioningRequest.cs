namespace CffVaultManager.Domain.Entities;

/// <summary>
/// A pending self-service tenant signup, awaiting email verification before the real Tenant/User
/// are created (see docs/multi-tenancy.md "Provisioning di un nuovo tenant"). Not tenant-scoped —
/// the tenant does not exist yet. Consumed (deleted) on successful confirmation; otherwise expires
/// and is purged periodically. Carries both the opaque client-side crypto material (never decrypted
/// server-side) and the plain billing/anagrafica data destined for TenantBillingProfile.
/// </summary>
public class TenantProvisioningRequest
{
    private TenantProvisioningRequest()
    {
        // Parameterless constructor for EF Core / serialization.
        TenantName = null!;
        TenantSlug = null!;
        AdminEmail = null!;
        AuthHash = null!;
        EncryptedDek = null!;
        MasterPasswordSalt = null!;
        LegalName = null!;
        AddressLine = null!;
        City = null!;
        PostalCode = null!;
        Province = null!;
        Country = null!;
        CodeHash = null!;
    }

    public TenantProvisioningRequest(
        Guid id,
        string tenantName,
        string tenantSlug,
        string adminEmail,
        byte[] authHash,
        byte[] encryptedDek,
        byte[] masterPasswordSalt,
        int kdfMemoryKb,
        int kdfIterations,
        int kdfVersion,
        string legalName,
        bool isBusiness,
        string addressLine,
        string city,
        string postalCode,
        string province,
        string country,
        byte[] codeHash,
        DateTimeOffset expiresAt,
        int maxAttempts,
        string? vatNumber = null,
        string? taxCode = null,
        string? sdiCode = null,
        string? pecAddress = null,
        string? phone = null,
        DateTimeOffset? createdAt = null,
        string? ipAddress = null,
        string? userAgent = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantName = Guard.AgainstNullOrWhiteSpace(tenantName);
        TenantSlug = Guard.AgainstNullOrWhiteSpace(tenantSlug);
        AdminEmail = Guard.AgainstNullOrWhiteSpace(adminEmail);
        AuthHash = Guard.AgainstNullOrEmpty(authHash);
        EncryptedDek = Guard.AgainstNullOrEmpty(encryptedDek);
        MasterPasswordSalt = Guard.AgainstNullOrEmpty(masterPasswordSalt);
        KdfMemoryKb = kdfMemoryKb;
        KdfIterations = kdfIterations;
        KdfVersion = kdfVersion;
        LegalName = Guard.AgainstNullOrWhiteSpace(legalName);
        IsBusiness = isBusiness;
        AddressLine = Guard.AgainstNullOrWhiteSpace(addressLine);
        City = Guard.AgainstNullOrWhiteSpace(city);
        PostalCode = Guard.AgainstNullOrWhiteSpace(postalCode);
        Province = Guard.AgainstNullOrWhiteSpace(province);
        Country = Guard.AgainstNullOrWhiteSpace(country);
        VatNumber = vatNumber;
        TaxCode = taxCode;
        SdiCode = sdiCode;
        PecAddress = pecAddress;
        Phone = phone;
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

    public string TenantName { get; private set; }

    public string TenantSlug { get; private set; }

    public string AdminEmail { get; private set; }

    public byte[] AuthHash { get; private set; }

    public byte[] EncryptedDek { get; private set; }

    public byte[] MasterPasswordSalt { get; private set; }

    public int KdfMemoryKb { get; private set; }

    public int KdfIterations { get; private set; }

    public int KdfVersion { get; private set; }

    public string LegalName { get; private set; }

    public bool IsBusiness { get; private set; }

    public string? VatNumber { get; private set; }

    public string? TaxCode { get; private set; }

    public string AddressLine { get; private set; }

    public string City { get; private set; }

    public string PostalCode { get; private set; }

    public string Province { get; private set; }

    public string Country { get; private set; }

    public string? SdiCode { get; private set; }

    public string? PecAddress { get; private set; }

    public string? Phone { get; private set; }

    public byte[] CodeHash { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public int AttemptCount { get; set; }

    public int MaxAttempts { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public string? IpAddress { get; private set; }

    public string? UserAgent { get; private set; }
}
