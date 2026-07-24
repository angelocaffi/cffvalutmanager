namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Public, anonymous request to start the gated tenant-provisioning flow (see
/// docs/multi-tenancy.md "Provisioning di un nuovo tenant"). Nothing is created yet — the server
/// only persists a pending <c>TenantProvisioningRequest</c> and emails a verification code;
/// confirming that code (via <c>ITenantProvisioningRequestService.ConfirmAsync</c>) is what
/// actually provisions the tenant.
/// Same opaque cryptographic fields as <see cref="ProvisionTenantRequest"/>, plus billing/anagrafica
/// data — never <c>PlanName</c>/<c>MaxUsers</c>/<c>MaxStorageBytes</c>, which stay SuperAdmin-only knobs.
/// </summary>
public sealed record RequestTenantProvisioningRequest(
    string TenantName,
    string TenantSlug,
    string AdminEmail,
    byte[] AuthHash,
    byte[] EncryptedDek,
    byte[] MasterPasswordSalt,
    int KdfMemoryKb,
    int KdfIterations,
    int KdfVersion,
    string LegalName,
    bool IsBusiness,
    string AddressLine,
    string City,
    string PostalCode,
    string Province,
    string Country,
    string? VatNumber = null,
    string? TaxCode = null,
    string? SdiCode = null,
    string? PecAddress = null,
    string? Phone = null);
