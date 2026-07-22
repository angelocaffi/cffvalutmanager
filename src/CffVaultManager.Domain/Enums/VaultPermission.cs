namespace CffVaultManager.Domain.Enums;

public enum VaultPermission
{
    Read,
    ReadWrite,

    /// <summary>
    /// Everything <see cref="ReadWrite"/> grants, plus authority to invite/revoke this vault's
    /// membership (see <c>VaultMembershipService</c>) — the vault-level analog of
    /// <c>ItemSharePermission.Owner</c>.
    /// </summary>
    Owner,
}

public static class VaultPermissionExtensions
{
    /// <summary>True for any permission that may create/modify/delete vault content.</summary>
    public static bool CanWrite(this VaultPermission permission) =>
        permission is VaultPermission.ReadWrite or VaultPermission.Owner;
}
