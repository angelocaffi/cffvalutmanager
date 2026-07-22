using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.VaultCore;

/// <summary>
/// Lists vaults visible to the caller: personal vaults they own, and organization vaults they hold
/// an active membership in. The two are exposed through separate methods.
/// </summary>
internal sealed class VaultService : IVaultService
{
    private readonly CffVaultManagerDbContext _db;

    public VaultService(CffVaultManagerDbContext db) => _db = db;

    public async Task<IReadOnlyList<VaultDto>> ListOwnedVaultsAsync(Guid callerId, CancellationToken ct = default)
    {
        return await _db.Vaults
            .Where(v => !v.IsOrganizationVault && v.OwnerUserId == callerId)
            .OrderBy(v => v.Name)
            .Select(v => new VaultDto(v.Id, v.Name, v.IsOrganizationVault))
            .ToListAsync(ct);
    }

    public async Task<IReadOnlyList<VaultDto>> ListAccessibleOrgVaultsAsync(Guid callerId, CancellationToken ct = default)
    {
        return await _db.VaultMemberships
            .Where(m => m.UserId == callerId && m.RevokedAt == null && m.Vault!.IsOrganizationVault)
            .Select(m => m.Vault!)
            .OrderBy(v => v.Name)
            .Select(v => new VaultDto(v.Id, v.Name, v.IsOrganizationVault))
            .ToListAsync(ct);
    }

    public async Task<VaultDto> CreateOrganizationVaultAsync(
        Guid callerId, Guid callerTenantId, CreateOrganizationVaultRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var vault = new Vault(Guid.NewGuid(), callerTenantId, request.Name, isOrganizationVault: true, ownerUserId: null);
        _db.Vaults.Add(vault);

        // The creator gets a membership row wrapped to their own public key exactly like any
        // invitee (see docs/features/sharing-access-control.md), but as Owner rather than plain
        // ReadWrite — otherwise nobody could ever invite a second member to a brand-new vault.
        var membership = new VaultMembership(
            Guid.NewGuid(),
            callerTenantId,
            vault.Id,
            callerId,
            VaultPermission.Owner,
            request.WrappedVaultDek,
            request.EphemeralPublicKey,
            invitedByUserId: callerId);
        _db.VaultMemberships.Add(membership);

        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), callerTenantId, callerId, AuditAction.Created));

        await _db.SaveChangesAsync(ct);

        return new VaultDto(vault.Id, vault.Name, vault.IsOrganizationVault);
    }
}
