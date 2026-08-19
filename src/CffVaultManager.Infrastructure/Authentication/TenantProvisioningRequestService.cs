using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// The gated, two-phase self-service tenant signup — see docs/multi-tenancy.md "Provisioning di un
/// nuovo tenant". A pending <see cref="TenantProvisioningRequest"/> holds both the opaque client-side
/// crypto material and the billing/anagrafica data until the emailed code is confirmed, at which
/// point <see cref="IProvisionTenantService"/> atomically creates the real Tenant/Admin/Vault (and
/// billing profile). Mirrors the anti-bruteforce shape of <see cref="EmailVerificationService"/>,
/// but cannot reuse <see cref="Domain.Entities.OneTimeCode"/> directly: its UserId is mandatory and
/// no User exists yet at request time.
/// </summary>
internal sealed class TenantProvisioningRequestService : ITenantProvisioningRequestService
{
    private static readonly TimeSpan RequestLifetime = TimeSpan.FromHours(24);
    private const int MaxAttempts = 5;

    private readonly CffVaultManagerDbContext _db;
    private readonly IEmailSender _emailSender;
    private readonly IProvisionTenantService _provisionTenantService;

    public TenantProvisioningRequestService(
        CffVaultManagerDbContext db, IEmailSender emailSender, IProvisionTenantService provisionTenantService)
    {
        _db = db;
        _emailSender = emailSender;
        _provisionTenantService = provisionTenantService;
    }

    public async Task<RequestTenantProvisioningResult> RequestAsync(
        RequestTenantProvisioningRequest request, string? ip, string? userAgent, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Same proactive check as ProvisionTenantService — gives a clean 409 instead of only
        // discovering the clash at confirmation time, when the user has already left the form.
        if (await _db.Tenants.AnyAsync(t => t.Slug == IdentifierNormalization.NormalizeSlug(request.TenantSlug), ct) ||
            await _db.Users.IgnoreQueryFilters().AnyAsync(u => u.Email == IdentifierNormalization.NormalizeEmail(request.AdminEmail), ct))
        {
            throw new InvalidOperationException("A tenant with this slug, or a user with this email, already exists.");
        }

        string code = OneTimeCodeHasher.GenerateNumericCode();
        var pending = new TenantProvisioningRequest(
            Guid.NewGuid(),
            request.TenantName,
            request.TenantSlug,
            request.AdminEmail,
            request.AuthHash,
            request.EncryptedDek,
            request.MasterPasswordSalt,
            request.KdfMemoryKb,
            request.KdfIterations,
            request.KdfVersion,
            request.LegalName,
            request.IsBusiness,
            request.AddressLine,
            request.City,
            request.PostalCode,
            request.Province,
            request.Country,
            OneTimeCodeHasher.Hash(code),
            DateTimeOffset.UtcNow.Add(RequestLifetime),
            MaxAttempts,
            request.VatNumber,
            request.TaxCode,
            request.SdiCode,
            request.PecAddress,
            request.Phone,
            ipAddress: ip,
            userAgent: userAgent);

        _db.TenantProvisioningRequests.Add(pending);
        await _db.SaveChangesAsync(ct);

        // Best-effort, after the pending request is durably persisted — same tradeoff already
        // accepted in EmailVerificationService.GenerateAndSendAsync.
        await _emailSender.SendAsync(
            request.AdminEmail,
            "Conferma la creazione della tua organizzazione — CffVaultManager",
            $"Il tuo codice di conferma è: {code}\n\nScade tra {RequestLifetime.TotalHours:0} ore. Se non hai richiesto questa email, ignorala.",
            ct);

        return new RequestTenantProvisioningResult(pending.Id);
    }

    public async Task<ProvisionTenantResult?> ConfirmAsync(
        Guid requestId, string code, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var pending = await _db.TenantProvisioningRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct);
        if (pending is null || pending.ExpiresAt <= DateTimeOffset.UtcNow || pending.AttemptCount >= pending.MaxAttempts)
        {
            return null;
        }

        pending.AttemptCount++;

        if (!OneTimeCodeHasher.Verify(code, pending.CodeHash))
        {
            await _db.SaveChangesAsync(ct);
            return null;
        }

        var provisionRequest = new ProvisionTenantRequest(
            pending.TenantName,
            pending.TenantSlug,
            pending.AdminEmail,
            pending.AuthHash,
            pending.EncryptedDek,
            pending.MasterPasswordSalt,
            pending.KdfMemoryKb,
            pending.KdfIterations,
            pending.KdfVersion,
            EmailAlreadyVerified: true,
            LegalName: pending.LegalName,
            IsBusiness: pending.IsBusiness,
            VatNumber: pending.VatNumber,
            TaxCode: pending.TaxCode,
            AddressLine: pending.AddressLine,
            City: pending.City,
            PostalCode: pending.PostalCode,
            Province: pending.Province,
            Country: pending.Country,
            SdiCode: pending.SdiCode,
            PecAddress: pending.PecAddress,
            Phone: pending.Phone);

        var result = await _provisionTenantService.ProvisionAsync(provisionRequest, ct);

        // Not part of the atomic transaction above (which already committed): a leftover pending
        // row here is harmless — the slug/email are now taken, so it can never be replayed into a
        // second tenant, and it will still be swept up by PurgeExpiredAsync once it expires.
        _db.TenantProvisioningRequests.Remove(pending);
        await _db.SaveChangesAsync(ct);

        return result;
    }

    public async Task<int> PurgeExpiredAsync(CancellationToken ct = default)
    {
        // Materialized before filtering: EF Core's SQLite provider (used in tests) cannot
        // translate relational comparisons on a DateTimeOffset column to SQL — same fix as
        // EmailVerificationService.ResendAsync and VaultItemService.ListAsync.
        var now = DateTimeOffset.UtcNow;
        var expired = (await _db.TenantProvisioningRequests.ToListAsync(ct))
            .Where(r => r.ExpiresAt < now)
            .ToList();
        if (expired.Count == 0)
        {
            return 0;
        }

        _db.TenantProvisioningRequests.RemoveRange(expired);
        await _db.SaveChangesAsync(ct);
        return expired.Count;
    }
}
