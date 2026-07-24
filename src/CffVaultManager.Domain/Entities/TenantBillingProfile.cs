namespace CffVaultManager.Domain.Entities;

/// <summary>
/// Anagrafica/fiscal billing data for a tenant, collected during provisioning (see
/// docs/multi-tenancy.md "Provisioning di un nuovo tenant") and kept for reuse once a paid plan is
/// introduced. At most one per tenant, never a prerequisite: a tenant provisioned without billing
/// data (e.g. directly by a SuperAdmin) simply has none. None of these fields are a secret — same
/// trust class as Tenant.Name/PlanName, see docs/security-model.md.
/// </summary>
public class TenantBillingProfile
{
    private TenantBillingProfile()
    {
        // Parameterless constructor for EF Core / serialization.
        LegalName = null!;
        AddressLine = null!;
        City = null!;
        PostalCode = null!;
        Province = null!;
        Country = null!;
    }

    public TenantBillingProfile(
        Guid id,
        Guid tenantId,
        string legalName,
        bool isBusiness,
        string addressLine,
        string city,
        string postalCode,
        string province,
        string country,
        string? vatNumber = null,
        string? taxCode = null,
        string? sdiCode = null,
        string? pecAddress = null,
        string? phone = null,
        DateTimeOffset? createdAt = null)
    {
        Id = Guard.AgainstEmptyGuid(id);
        TenantId = Guard.AgainstEmptyGuid(tenantId);
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
        var created = createdAt ?? DateTimeOffset.UtcNow;
        CreatedAt = created;
        UpdatedAt = created;
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public Tenant? Tenant { get; set; }

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

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }
}
