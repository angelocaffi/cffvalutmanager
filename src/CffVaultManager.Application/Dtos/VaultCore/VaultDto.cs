namespace CffVaultManager.Application.Dtos.VaultCore;

/// <summary>
/// Non-sensitive metadata about a vault. Never carries encrypted material or secrets.
/// </summary>
public sealed record VaultDto(Guid Id, string Name, bool IsOrganizationVault);

/// <summary>
/// Creates a new organization vault. <see cref="WrappedVaultDek"/>/<see cref="EphemeralPublicKey"/>
/// are the creator's own membership material, computed client-side exactly like any invitee's (see
/// docs/features/sharing-access-control.md).
/// </summary>
public sealed record CreateOrganizationVaultRequest(string Name, byte[] WrappedVaultDek, byte[] EphemeralPublicKey);
