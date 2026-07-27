namespace CffVaultManager.Api.Authentication;

internal static class TenantClaimTypes
{
    public const string TenantId = "tenant_id";

    /// <summary>Present (value "true") only when the tenant's trial has ended with no active paid plan — see docs/features/billing.md.</summary>
    public const string ReadOnly = "tenant_read_only";
}
