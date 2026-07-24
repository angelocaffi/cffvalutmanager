using CffVaultManager.Application.Dtos.Authentication;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// The gated, two-phase self-service tenant signup (see docs/multi-tenancy.md "Provisioning di un
/// nuovo tenant"): a pending <c>TenantProvisioningRequest</c> must be confirmed with an emailed code
/// before <see cref="IProvisionTenantService"/> is actually invoked. Replaces anonymous,
/// uncontrolled tenant creation for the public self-service flow — <c>POST /api/tenants</c> itself
/// is unchanged and still used for direct/assisted provisioning.
/// </summary>
public interface ITenantProvisioningRequestService
{
    Task<RequestTenantProvisioningResult> RequestAsync(
        RequestTenantProvisioningRequest request, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>
    /// Returns null uniformly for an unknown request, an expired one, one whose attempts are
    /// exhausted, or a wrong code — the caller can never distinguish which case occurred. On
    /// success, provisions the tenant/admin/vault (and billing profile) atomically via
    /// <see cref="IProvisionTenantService"/>, then removes the pending request.
    /// </summary>
    Task<ProvisionTenantResult?> ConfirmAsync(
        Guid requestId, string code, string? ip, string? userAgent, CancellationToken ct = default);

    /// <summary>Deletes expired, never-confirmed pending requests. Returns the count removed.</summary>
    Task<int> PurgeExpiredAsync(CancellationToken ct = default);
}
