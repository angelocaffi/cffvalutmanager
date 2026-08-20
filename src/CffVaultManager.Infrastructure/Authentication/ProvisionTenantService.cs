using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

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
    private readonly IEmailVerificationService? _emailVerification;
    private readonly ILogger<ProvisionTenantService>? _logger;

    // emailVerification is optional so DI resolves it to the real service in production; tests
    // that don't care about email verification can omit it entirely (mirrors the
    // Argon2Parameters? convenience default on ServerAuthHashHasher).
    public ProvisionTenantService(
        CffVaultManagerDbContext db,
        IAuthHashHasher authHashHasher,
        IEmailVerificationService? emailVerification = null,
        ILogger<ProvisionTenantService>? logger = null)
    {
        _db = db;
        _authHashHasher = authHashHasher;
        _emailVerification = emailVerification;
        _logger = logger;
    }

    public async Task<ProvisionTenantResult> ProvisionAsync(ProvisionTenantRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Proactive check (both Slug and Email are unique indexes): gives a clean 409 instead of
        // letting a duplicate surface as an unhandled DbUpdateException from the SQL constraint.
        // The IgnoreQueryFilters bypass on Users mirrors AuthenticationService's login lookup — the
        // tenant isn't known yet, so this is a legitimate cross-tenant existence check.
        if (await _db.Tenants.AnyAsync(t => t.Slug == IdentifierNormalization.NormalizeSlug(request.TenantSlug), ct) ||
            await _db.Users.IgnoreQueryFilters().AnyAsync(u => u.Email == IdentifierNormalization.NormalizeEmail(request.AdminEmail), ct))
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

        // Set only when the caller (the gated self-service flow) already proved ownership of
        // AdminEmail before calling ProvisionAsync — skips the post-hoc email-verification code below.
        if (request.EmailAlreadyVerified)
        {
            admin.EmailVerifiedAt = DateTimeOffset.UtcNow;
        }

        // The audit entry's TenantId is the tenant being created. It is a plain insert, so the
        // tenant query filter (which only rewrites queries, never writes) does not apply.
        var audit = new AuditLogEntry(Guid.NewGuid(), tenantId, adminId, AuditAction.TenantProvisioned);

        await using var tx = await _db.Database.BeginTransactionAsync(ct);
        _db.Tenants.Add(tenant);
        _db.Users.Add(admin);
        _db.AuditLogEntries.Add(audit);
        _db.Vaults.Add(new Vault(Guid.NewGuid(), tenantId, "Personale", isOrganizationVault: false, ownerUserId: adminId));

        // Optional billing/anagrafica data (see docs/data-model.md#tenantbillingprofile...) —
        // a TenantBillingProfile is not a provisioning prerequisite, only created when supplied.
        if (!string.IsNullOrWhiteSpace(request.LegalName))
        {
            _db.TenantBillingProfiles.Add(new TenantBillingProfile(
                Guid.NewGuid(),
                tenantId,
                request.LegalName,
                request.IsBusiness,
                request.AddressLine ?? string.Empty,
                request.City ?? string.Empty,
                request.PostalCode ?? string.Empty,
                request.Province ?? string.Empty,
                request.Country ?? string.Empty,
                request.VatNumber,
                request.TaxCode,
                request.SdiCode,
                request.PecAddress,
                request.Phone));
        }

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

        // Best-effort, after the tenant/admin are durably committed — see docs/features/
        // authentication.md "Verifica email in registrazione". Skipped when the caller already
        // proved ownership of AdminEmail (the gated self-service flow) — admin.EmailVerifiedAt
        // was already set above. Genuinely best-effort: a failure here (e.g. the AdminEmail's
        // domain rejects mail) must not surface as a 500 to the caller — the tenant/admin/vault
        // already committed successfully above, and are real regardless of whether this email goes
        // out (see docs/pentest-report-2026-08-20.md, finding #3, where this previously bubbled up
        // as an unhandled exception on every provisioning attempt with an undeliverable address).
        if (!request.EmailAlreadyVerified && _emailVerification is not null)
        {
            try
            {
                await _emailVerification.RequestAsync(adminId, ip: null, userAgent: null, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger?.LogWarning(ex, "Best-effort verification email failed after provisioning tenant {TenantId}; the tenant/admin were still created successfully.", tenantId);
            }
        }

        return new ProvisionTenantResult(tenantId, adminId);
    }
}
