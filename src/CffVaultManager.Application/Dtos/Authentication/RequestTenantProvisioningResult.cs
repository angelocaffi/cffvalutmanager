namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// Identifier of the pending request just created. Not a secret — presented back together with the
/// emailed code at confirmation time, the same role <c>WebAuthnCeremony.Id</c> plays between
/// begin/complete.
/// </summary>
public sealed record RequestTenantProvisioningResult(Guid RequestId);
