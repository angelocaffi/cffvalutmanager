namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Request to provision a brand-new tenant together with its first Admin user.
/// All cryptographic fields are produced on the client and stored as-is; the server
/// never sees the master password or the plaintext DEK.
///
/// <paramref name="EmailAlreadyVerified"/> is true only when the caller (the gated self-service
/// flow, see <c>ITenantProvisioningRequestService</c>) already proved ownership of
/// <paramref name="AdminEmail"/> before calling this method — it skips the post-hoc "verifica
/// email in registrazione" code and marks the admin verified immediately.
///
/// The billing/anagrafica fields (<paramref name="LegalName"/> onward, see
/// docs/data-model.md#tenantbillingprofile...) are optional: when <paramref name="LegalName"/> is
/// null/blank, no <c>TenantBillingProfile</c> row is created — this is optional metadata, not a
/// provisioning prerequisite (e.g. direct SuperAdmin provisioning supplies none of it).
/// </summary>
public sealed record ProvisionTenantRequest(
    string TenantName,
    string TenantSlug,
    string AdminEmail,
    byte[] AuthHash,
    byte[] EncryptedDek,
    byte[] MasterPasswordSalt,
    int KdfMemoryKb,
    int KdfIterations,
    int KdfVersion,
    string? PlanName = null,
    int? MaxUsers = null,
    long? MaxStorageBytes = null,
    bool EmailAlreadyVerified = false,
    string? LegalName = null,
    bool IsBusiness = false,
    string? VatNumber = null,
    string? TaxCode = null,
    string? AddressLine = null,
    string? City = null,
    string? PostalCode = null,
    string? Province = null,
    string? Country = null,
    string? SdiCode = null,
    string? PecAddress = null,
    string? Phone = null);
