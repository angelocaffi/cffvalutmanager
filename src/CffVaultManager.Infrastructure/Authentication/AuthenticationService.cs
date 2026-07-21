using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Zero-knowledge login: verifies the server-rehashed auth hash, then optionally a TOTP second
/// factor, and only on full success hands back the crypto material the client needs to unwrap its
/// vault. All failures are indistinguishable to the caller (anti-enumeration).
/// </summary>
internal sealed class AuthenticationService : IAuthenticationService
{
    private static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan MfaChallengeLifetime = TimeSpan.FromMinutes(5);

    // Shared between wrong-password and wrong-MFA-code attempts: both represent the same "this
    // account is under attack" signal (see docs/features/authentication.md rate limiting). The
    // lockout window is fixed from the triggering attempt, not extended by further attempts made
    // while already locked out.
    private const int MaxFailedLoginAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private readonly CffVaultManagerDbContext _db;
    private readonly IAuthHashHasher _authHashHasher;
    private readonly IJwtTokenService _jwt;
    private readonly IRefreshTokenService _refreshTokens;
    private readonly ITotpService _totp;
    private readonly ISecretProtector _secretProtector;

    // A syntactically valid but never-matching stored hash, used so an unknown-email login pays
    // the same Argon2id cost as a wrong-password attempt against a real account — otherwise
    // response latency alone lets an attacker distinguish "no such account" from "wrong password"
    // (timing side-channel; see docs/security-model.md threat #4). Computed via the real hasher
    // (so its length always matches whatever IAuthHashHasher implementation is in play) but only
    // ONCE for the process lifetime and cached statically: AuthenticationService itself is
    // constructed per-request (it holds a scoped DbContext), and paying a full Argon2id cost in
    // every constructor call — even for requests that never hit the unknown-email branch — would
    // slow down every login/refresh/MFA-verify call, not just the one path this exists to protect.
    private static byte[]? _cachedDummyStoredHash;
    private static readonly object DummyStoredHashLock = new();

    private readonly byte[] _dummyStoredHash;

    public AuthenticationService(
        CffVaultManagerDbContext db,
        IAuthHashHasher authHashHasher,
        IJwtTokenService jwt,
        IRefreshTokenService refreshTokens,
        ITotpService totp,
        ISecretProtector secretProtector)
    {
        _db = db;
        _authHashHasher = authHashHasher;
        _jwt = jwt;
        _refreshTokens = refreshTokens;
        _totp = totp;
        _secretProtector = secretProtector;
        _dummyStoredHash = GetOrCreateDummyStoredHash(authHashHasher);
    }

    private static byte[] GetOrCreateDummyStoredHash(IAuthHashHasher hasher)
    {
        if (_cachedDummyStoredHash is { } cached)
        {
            return cached;
        }

        lock (DummyStoredHashLock)
        {
            return _cachedDummyStoredHash ??= hasher.Hash(RandomNumberGenerator.GetBytes(32));
        }
    }

    public async Task<LoginResult> LoginAsync(string email, byte[] authHash, string? ip, string? userAgent, CancellationToken ct = default)
    {
        // The tenant is not known before authentication, so this is the one legitimate place to
        // bypass the tenant query filter: the user is looked up by their globally-unique email.
        var user = await _db.Users
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(u => u.Email == email, ct);

        if (user is null)
        {
            // Unknown email leaves no audit trace, but still pays the same Argon2id cost a real
            // wrong-password attempt would, against a dummy hash whose result is discarded — a
            // fast-path return here would otherwise let response latency alone reveal which emails
            // are registered.
            _authHashHasher.Verify(authHash, _dummyStoredHash);
            return LoginResult.Failure();
        }

        if (IsLockedOut(user))
        {
            // Rejected without even checking the password: the account is under a fixed lockout
            // window from an earlier trigger, not extended by further attempts (see docs/features/
            // authentication.md). Still audited so the attempt is visible.
            await WriteAuditAsync(user, AuditAction.LoginFailed, ip, userAgent, ct);
            return LoginResult.Failure();
        }

        if (user.MasterPasswordHash is null || !_authHashHasher.Verify(authHash, user.MasterPasswordHash))
        {
            await RegisterFailedAttemptAsync(user, ip, userAgent, ct);
            return LoginResult.Failure();
        }

        ResetLockoutState(user);

        if (user.MfaEnabled)
        {
            await WriteAuditAsync(user, AuditAction.MfaChallenge, ip, userAgent, ct);
            string challenge = _jwt.CreateMfaChallengeToken(user.Id, MfaChallengeLifetime);
            return LoginResult.MfaRequired(challenge);
        }

        return await IssueSessionAsync(user, ip, userAgent, ct);
    }

    public async Task<LoginResult> VerifyMfaAsync(string challengeToken, string totpCode, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var claims = await _jwt.ValidateAsync(challengeToken, JwtTokenService.MfaChallengePurpose);
        if (claims is null)
        {
            return LoginResult.Failure();
        }

        var user = await _db.Users
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(u => u.Id == claims.UserId, ct);

        if (user is null || !user.MfaEnabled || user.MfaSecret is null)
        {
            return LoginResult.Failure();
        }

        if (IsLockedOut(user))
        {
            await WriteAuditAsync(user, AuditAction.LoginFailed, ip, userAgent, ct);
            return LoginResult.Failure();
        }

        byte[] secret = _secretProtector.Unprotect(user.MfaSecret);
        if (!_totp.ValidateCode(secret, totpCode))
        {
            // No dedicated "MfaFailed" audit action exists; LoginFailed is reused for a failed
            // second factor to avoid introducing new enum values in this round. A wrong TOTP code
            // counts toward the same lockout as a wrong password — the attacker already cleared the
            // password check to get here, and a 6-digit code is brute-forceable without this.
            await RegisterFailedAttemptAsync(user, ip, userAgent, ct);
            return LoginResult.Failure();
        }

        ResetLockoutState(user);

        return await IssueSessionAsync(user, ip, userAgent, ct);
    }

    public async Task<LoginResult> RefreshAsync(string refreshToken, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var rotated = await _refreshTokens.ValidateAndRotateAsync(refreshToken, ip, userAgent, ct);
        if (rotated is null)
        {
            return LoginResult.Failure("Invalid refresh token.");
        }

        // The tenant is not known from an opaque refresh token alone, so this is another
        // legitimate bypass of the tenant query filter (mirrors the lookup in LoginAsync).
        var user = await _db.Users
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(u => u.Id == rotated.Entity.UserId, ct);

        if (user is null)
        {
            return LoginResult.Failure("Invalid refresh token.");
        }

        if (await IsTenantSuspendedAsync(user.TenantId, ct))
        {
            return LoginResult.Failure("Tenant is suspended.");
        }

        string access = _jwt.CreateAccessToken(user.Id, user.TenantId, user.Role, AccessTokenLifetime);
        var materials = new CryptoMaterials(
            user.EncryptedDek,
            user.MasterPasswordSalt,
            user.KdfMemoryKb,
            user.KdfIterations,
            user.KdfVersion);

        return LoginResult.Authenticated(access, rotated.PlainToken, materials);
    }

    private async Task<LoginResult> IssueSessionAsync(User user, string? ip, string? userAgent, CancellationToken ct)
    {
        if (await IsTenantSuspendedAsync(user.TenantId, ct))
        {
            return LoginResult.Failure("Tenant is suspended.");
        }

        string access = _jwt.CreateAccessToken(user.Id, user.TenantId, user.Role, AccessTokenLifetime);
        var refresh = await _refreshTokens.IssueAsync(user.Id, ip, userAgent, ct);

        user.LastLoginAt = DateTimeOffset.UtcNow;
        await WriteAuditAsync(user, AuditAction.LoginSuccess, ip, userAgent, ct);

        var materials = new CryptoMaterials(
            user.EncryptedDek,
            user.MasterPasswordSalt,
            user.KdfMemoryKb,
            user.KdfIterations,
            user.KdfVersion);

        return LoginResult.Authenticated(access, refresh.PlainToken, materials);
    }

    private static bool IsLockedOut(User user) => user.LockedUntil is not null && user.LockedUntil > DateTimeOffset.UtcNow;

    private static void ResetLockoutState(User user)
    {
        user.FailedLoginAttempts = 0;
        user.LockedUntil = null;
    }

    private async Task RegisterFailedAttemptAsync(User user, string? ip, string? userAgent, CancellationToken ct)
    {
        user.FailedLoginAttempts++;

        if (user.FailedLoginAttempts >= MaxFailedLoginAttempts)
        {
            user.FailedLoginAttempts = 0;
            user.LockedUntil = DateTimeOffset.UtcNow.Add(LockoutDuration);
            await WriteAuditAsync(user, AuditAction.LoginFailed, ip, userAgent, ct);
            await WriteAuditAsync(user, AuditAction.AccountLocked, ip, userAgent, ct);
            return;
        }

        await WriteAuditAsync(user, AuditAction.LoginFailed, ip, userAgent, ct);
    }

    // SuperAdmin (TenantId == null) is never subject to tenant suspension.
    private async Task<bool> IsTenantSuspendedAsync(Guid? tenantId, CancellationToken ct)
    {
        if (tenantId is null)
        {
            return false;
        }

        var status = await _db.Tenants.IgnoreQueryFilters()
            .Where(t => t.Id == tenantId)
            .Select(t => (TenantStatus?)t.Status)
            .FirstOrDefaultAsync(ct);

        return status == TenantStatus.Suspended;
    }

    private async Task WriteAuditAsync(User user, AuditAction action, string? ip, string? userAgent, CancellationToken ct)
    {
        _db.AuditLogEntries.Add(new AuditLogEntry(
            Guid.NewGuid(),
            user.TenantId,
            user.Id,
            action,
            ipAddress: ip,
            userAgent: userAgent));

        await _db.SaveChangesAsync(ct);
    }
}
