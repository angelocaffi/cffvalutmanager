namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Resolves the right DEK to decrypt/encrypt a given vault's items with: the session DEK for a
/// personal vault, or the caller's own unwrapped share of the vault's DEK for an organization vault
/// (see docs/features/sharing-access-control.md). Every page that previously called
/// <see cref="SessionState.RequireDek"/> unconditionally should call <see cref="ResolveAsync"/>
/// instead — personal vaults behave identically to before, organization vaults now actually work.
/// </summary>
/// <remarks>
/// There is deliberately no separate "is this an organization vault" lookup: <c>GET
/// /api/vaults/{vaultId}/memberships/me</c> 404s for a personal vault exactly the same way it does
/// for an org vault the caller isn't a member of, so a single call answers both "which key" and
/// "is this an org vault, and what's my permission on it" (<see cref="VaultAccess.Permission"/> is
/// null only for personal vaults). Results are cached per vault for the lifetime of this instance
/// (effectively the whole app session, like <see cref="SessionState"/>) so navigating between a
/// vault's items/detail/trash/backup pages doesn't re-fetch and re-unwrap on every page.
/// </remarks>
public sealed class VaultDekResolver
{
    private readonly VaultMembershipApiClient _membershipApi;
    private readonly SessionState _session;
    private readonly ItemKeyResolver _itemKeyResolver;
    private readonly Dictionary<Guid, VaultAccess> _cache = new();

    public VaultDekResolver(VaultMembershipApiClient membershipApi, SessionState session, ItemKeyResolver itemKeyResolver)
    {
        _membershipApi = membershipApi;
        _session = session;
        _itemKeyResolver = itemKeyResolver;
    }

    public async Task<VaultAccess> ResolveAsync(Guid vaultId, CancellationToken ct = default)
    {
        if (_cache.TryGetValue(vaultId, out var cached))
        {
            return cached;
        }

        var membership = await _membershipApi.GetMyMembershipAsync(vaultId, ct);
        VaultAccess access;
        if (membership is null)
        {
            access = new VaultAccess(_session.RequireDek(), Permission: null);
        }
        else
        {
            byte[] dek = await _itemKeyResolver.UnwrapAsync(membership.WrappedVaultDek, membership.EphemeralPublicKey);
            access = new VaultAccess(dek, membership.Permission);
        }

        _cache[vaultId] = access;
        return access;
    }

    /// <summary>Overwrites the cached access for a vault right after this session itself changed it (e.g. just created it, or just rotated its DEK by revoking a member) — avoids an immediate redundant round trip.</summary>
    public void SetResolved(Guid vaultId, byte[] dek, string? permission) =>
        _cache[vaultId] = new VaultAccess(dek, permission);

    /// <summary>Drops any cached access for a vault, forcing the next <see cref="ResolveAsync"/> to fetch fresh (e.g. after being revoked from it elsewhere).</summary>
    public void Invalidate(Guid vaultId) => _cache.Remove(vaultId);
}

/// <summary>The DEK to use for a vault plus the caller's own <see cref="VaultPermission"/> on it as a string ("Read"/"ReadWrite"/"Owner") — null for a personal vault, which has no membership concept.</summary>
public sealed record VaultAccess(byte[] Dek, string? Permission)
{
    public bool IsOrganizationVault => Permission is not null;

    public bool IsOwner => Permission == "Owner";
}
