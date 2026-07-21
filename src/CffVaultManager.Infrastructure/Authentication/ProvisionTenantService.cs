using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Creates a new tenant and its first Admin user atomically. The Admin's crypto material
/// (EncryptedDek, salt, KDF parameters) is stored exactly as received from the client and never
/// decrypted; only the auth hash is rehashed server-side before storage.
/// </summary>
internal sealed class ProvisionTenantService : IProvisionTenantService
{
    private readonly CffVaultManagerDbContext _db;
    private readonly IAuthHashHasher _authHashHasher;

    public ProvisionTenantService(CffVaultManagerDbContext db, IAuthHashHasher authHashHasher)
    {
        _db = db;
        _authHashHasher = authHashHasher;
    }

    public async Task<ProvisionTenantResult> ProvisionAsync(ProvisionTenantRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Proactive check (both Slug and Email are unique indexes): gives a clean 409 instead of
        // letting a duplicate surface as an unhandled DbUpdateException from the SQL constraint.
        // The IgnoreQueryFilters bypass on Users mirrors AuthenticationService's login lookup — the
        // tenant isn't known yet, so this is a legitimate cross-tenant existence check.
        if (await _db.Tenants.AnyAsync(t => t.Slug == request.TenantSlug, ct) ||
            await _db.Users.IgnoreQueryFilters().AnyAsync(u => u.Email == request.AdminEmail, ct))
        {
            throw new InvalidOperationException("A tenant with this slug, or a user with this email, already exists.");
        }

        var tenantId = Guid.NewGuid();
        var adminId = Guid.NewGuid();

        var tenant = new Tenant(
            tenantId,
            request.TenantName,
            request.TenantSlug,
            TenantStatus.Active,
            request.PlanName,
            request.MaxUsers,
            request.MaxStorageBytes);

        var admin = User.CreateTenantUser(
            adminId,
            tenantId,
            request.AdminEmail,
            UserRole.Admin,
            request.EncryptedDek,
            masterPasswordHash: _authHashHasher.Hash(request.AuthHash),
            masterPasswordSalt: request.MasterPasswordSalt,
            kdfMemoryKb: request.KdfMemoryKb,
            kdfIterations: request.KdfIterations,
            kdfVersion: request.KdfVersion);

        // The audit entry's TenantId is the tenant being created. It is a plain insert, so the
        // tenant query filter (which only rewrites queries, never writes) does not apply.
        var audit = new AuditLogEntry(Guid.NewGuid(), tenantId, adminId, AuditAction.TenantProvisioned);

        await using var tx = await _db.Database.BeginTransactionAsync(ct);
        _db.Tenants.Add(tenant);
        _db.Users.Add(admin);
        _db.AuditLogEntries.Add(audit);
        _db.Vaults.Add(new Vault(Guid.NewGuid(), tenantId, "Personale", isOrganizationVault: false, ownerUserId: adminId));

        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Closes the race between the proactive check above and this insert (the `using`
            // transaction rolls back automatically since it was never committed).
            throw new InvalidOperationException("A tenant with this slug, or a user with this email, already exists.");
        }

        await tx.CommitAsync(ct);

        return new ProvisionTenantResult(tenantId, adminId);
    }
}
