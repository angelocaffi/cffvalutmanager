using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>See <see cref="IUserInvitationService"/> and docs/features/roles-permissions.md "Invito di nuovi utenti".</summary>
internal sealed class UserInvitationService : IUserInvitationService
{
    private static readonly TimeSpan InvitationLifetime = TimeSpan.FromDays(7);

    private readonly CffVaultManagerDbContext _db;
    private readonly IAuthHashHasher _authHashHasher;
    private readonly IEmailSender _emailSender;
    private readonly string _publicUrl;

    public UserInvitationService(CffVaultManagerDbContext db, IAuthHashHasher authHashHasher, IEmailSender emailSender, IConfiguration configuration)
    {
        _db = db;
        _authHashHasher = authHashHasher;
        _emailSender = emailSender;
        _publicUrl = configuration["App:PublicUrl"] ?? string.Empty;
    }

    public async Task<UserInvitationDto> InviteAsync(string email, UserRole role, Guid callerId, Guid callerTenantId, CancellationToken ct = default)
    {
        if (role == UserRole.SuperAdmin)
        {
            throw new ArgumentException("Cannot invite a user as SuperAdmin.", nameof(role));
        }

        // Emails are globally unique (see UserConfiguration) — proactive check for a clean error
        // instead of only discovering the clash at accept time, same reasoning already used by
        // TenantProvisioningRequestService.RequestAsync.
        if (await _db.Users.IgnoreQueryFilters().AnyAsync(u => u.Email == email, ct))
        {
            throw new InvalidOperationException("A user with this email already exists.");
        }

        var tenant = await _db.Tenants.FirstOrDefaultAsync(t => t.Id == callerTenantId, ct)
            ?? throw new KeyNotFoundException("Tenant not found.");

        var invitation = new UserInvitation(
            Guid.NewGuid(), callerTenantId, email, role, callerId, GenerateToken(),
            DateTimeOffset.UtcNow.Add(InvitationLifetime));

        _db.UserInvitations.Add(invitation);
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), callerTenantId, callerId, AuditAction.UserInvited));
        await _db.SaveChangesAsync(ct);

        // Best-effort, after the pending invitation is durably persisted — same tradeoff already
        // accepted in TenantProvisioningRequestService.RequestAsync/EmailVerificationService.
        string link = $"{_publicUrl}/invite/{invitation.Token}";
        await _emailSender.SendAsync(
            email,
            $"Sei stato invitato a unirti a {tenant.Name} — CffVaultManager",
            $"Sei stato invitato a unirti all'organizzazione \"{tenant.Name}\" su CffVaultManager.\n\nApri questo link per creare il tuo account: {link}\n\nIl link scade tra {InvitationLifetime.TotalDays:0} giorni. Se non ti aspettavi questo invito, ignora questa email.",
            ct);

        return new UserInvitationDto(invitation.Id, invitation.Email, invitation.Role, invitation.CreatedAt, invitation.ExpiresAt);
    }

    public async Task<IReadOnlyList<UserInvitationDto>> ListPendingAsync(Guid callerTenantId, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        // Materialized before filtering: EF Core's SQLite provider (used in tests) cannot
        // translate relational comparisons on a DateTimeOffset column to SQL — same fix already
        // applied in TenantProvisioningRequestService.PurgeExpiredAsync.
        return (await _db.UserInvitations.Where(i => i.TenantId == callerTenantId).ToListAsync(ct))
            .Where(i => !i.IsExpiredOrRevoked(now))
            .OrderByDescending(i => i.CreatedAt)
            .Select(i => new UserInvitationDto(i.Id, i.Email, i.Role, i.CreatedAt, i.ExpiresAt))
            .ToList();
    }

    public async Task<IReadOnlyList<TenantUserSummaryDto>> ListTenantUsersAsync(Guid callerTenantId, CancellationToken ct = default) =>
        await _db.Users
            .Where(u => u.TenantId == callerTenantId)
            .OrderBy(u => u.Email)
            .Select(u => new TenantUserSummaryDto(u.Id, u.Email, u.Role, u.CreatedAt))
            .ToListAsync(ct);

    public async Task RevokeAsync(Guid invitationId, Guid callerTenantId, CancellationToken ct = default)
    {
        var invitation = await _db.UserInvitations.FirstOrDefaultAsync(i => i.Id == invitationId && i.TenantId == callerTenantId, ct)
            ?? throw new KeyNotFoundException("Invitation not found.");

        invitation.Revoke();
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), callerTenantId, invitation.InvitedByUserId, AuditAction.UserInvitationRevoked));
        await _db.SaveChangesAsync(ct);
    }

    public async Task<InvitationPreviewDto?> GetPreviewAsync(string token, CancellationToken ct = default)
    {
        var invitation = await _db.UserInvitations.IgnoreQueryFilters()
            .Include(i => i.Tenant)
            .Include(i => i.InvitedByUser)
            .FirstOrDefaultAsync(i => i.Token == token, ct);

        if (invitation is null || invitation.IsExpiredOrRevoked(DateTimeOffset.UtcNow))
        {
            return null;
        }

        return new InvitationPreviewDto(invitation.Tenant!.Name, invitation.Role, invitation.InvitedByUser!.Email);
    }

    public async Task<Guid?> AcceptAsync(
        string token,
        byte[] authHash,
        byte[] encryptedDek,
        byte[] masterPasswordSalt,
        int kdfMemoryKb,
        int kdfIterations,
        int kdfVersion,
        CancellationToken ct = default)
    {
        var invitation = await _db.UserInvitations.IgnoreQueryFilters().FirstOrDefaultAsync(i => i.Token == token, ct);
        if (invitation is null || invitation.IsExpiredOrRevoked(DateTimeOffset.UtcNow))
        {
            return null;
        }

        // Defense in depth against a race with another invitation/registration for the same
        // email between preview and accept — the unique index on Users.Email is the final backstop.
        if (await _db.Users.IgnoreQueryFilters().AnyAsync(u => u.Email == invitation.Email, ct))
        {
            return null;
        }

        var userId = Guid.NewGuid();
        // Deliberately not reusing UserRegistrationService.RegisterInTenantAsync — same principle
        // as AccountRecoveryService duplicating AuthenticationService's MFA dispatch rather than
        // risking a change to sensitive, already-tested code. The duplicated logic here is minimal.
        var user = User.CreateTenantUser(
            userId,
            invitation.TenantId,
            invitation.Email,
            invitation.Role,
            encryptedDek,
            masterPasswordHash: _authHashHasher.Hash(authHash),
            masterPasswordSalt: masterPasswordSalt,
            kdfMemoryKb: kdfMemoryKb,
            kdfIterations: kdfIterations,
            kdfVersion: kdfVersion);

        _db.Users.Add(user);
        _db.Vaults.Add(new Vault(Guid.NewGuid(), invitation.TenantId, "Personale", isOrganizationVault: false, ownerUserId: userId));
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), invitation.TenantId, userId, AuditAction.UserInvitationAccepted));

        // Not needed after a successful accept — mirrors TenantProvisioningRequestService.ConfirmAsync
        // (the email is now taken, so the row can never be replayed).
        _db.UserInvitations.Remove(invitation);

        await _db.SaveChangesAsync(ct);
        return userId;
    }

    public async Task<int> PurgeExpiredAsync(CancellationToken ct = default)
    {
        // Materialized before filtering — same SQLite-provider limitation noted above.
        var now = DateTimeOffset.UtcNow;
        var expired = (await _db.UserInvitations.IgnoreQueryFilters().ToListAsync(ct))
            .Where(i => i.ExpiresAt < now)
            .ToList();
        if (expired.Count == 0)
        {
            return 0;
        }

        _db.UserInvitations.RemoveRange(expired);
        await _db.SaveChangesAsync(ct);
        return expired.Count;
    }

    // URL-safe base64 (unlike Convert.ToBase64String, which can emit '/' — a literal '/' inside a
    // single Blazor route parameter like /invite/{Token} would break route matching for that
    // token). Same 256 bits of entropy/plaintext-at-rest tradeoff already accepted for
    // ExternalShareLink.Token.
    private static string GenerateToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
}
