using System.Security.Cryptography;
using System.Text;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Crypto;
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
    private readonly IEmailOtpMfaService _emailOtpMfa;
    private readonly IWebAuthnService _webAuthn;
    private readonly ISecurityNotificationService? _securityNotifications;

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

    // Process-lifetime secret used only to derive a stable fake salt for PreloginAsync's
    // unknown-email branch (see there): same reasoning and same caching pattern as
    // _cachedDummyStoredHash above, just for a different anti-enumeration endpoint.
    private static byte[]? _cachedPreloginPepper;
    private static readonly object PreloginPepperLock = new();

    private readonly byte[] _dummyStoredHash;

    public AuthenticationService(
        CffVaultManagerDbContext db,
        IAuthHashHasher authHashHasher,
        IJwtTokenService jwt,
        IRefreshTokenService refreshTokens,
        ITotpService totp,
        ISecretProtector secretProtector,
        IEmailOtpMfaService emailOtpMfa,
        IWebAuthnService webAuthn,
        ISecurityNotificationService? securityNotifications = null)
    {
        _db = db;
        _authHashHasher = authHashHasher;
        _jwt = jwt;
        _refreshTokens = refreshTokens;
        _totp = totp;
        _secretProtector = secretProtector;
        _emailOtpMfa = emailOtpMfa;
        _webAuthn = webAuthn;
        _securityNotifications = securityNotifications;
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

    public async Task<PreloginResult> PreloginAsync(string email, CancellationToken ct = default)
    {
        // The tenant is not known before authentication — same legitimate bypass as LoginAsync.
        var user = await _db.Users
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(u => u.Email == email, ct);

        if (user?.MasterPasswordSalt is null || user.KdfMemoryKb is null || user.KdfIterations is null || user.KdfVersion is null)
        {
            // Unknown email (or a SuperAdmin with no master password at all): return a fake salt
            // that is stable for this email across every call for this process's lifetime — a
            // fresh random salt on every call would itself be a tell (a real user's salt never
            // changes between requests), and an error/empty response would leak non-existence
            // outright. Default (production) KDF parameters keep the shape identical to a real
            // response.
            byte[] fakeSalt = HMACSHA256.HashData(GetOrCreatePreloginPepper(), Encoding.UTF8.GetBytes(email))[..16];
            var defaults = Argon2Parameters.Default;
            return new PreloginResult(fakeSalt, defaults.MemoryKb, defaults.Iterations, defaults.Version);
        }

        return new PreloginResult(user.MasterPasswordSalt, user.KdfMemoryKb.Value, user.KdfIterations.Value, user.KdfVersion.Value);
    }

    private static byte[] GetOrCreatePreloginPepper()
    {
        if (_cachedPreloginPepper is { } cached)
        {
            return cached;
        }

        lock (PreloginPepperLock)
        {
            return _cachedPreloginPepper ??= RandomNumberGenerator.GetBytes(32);
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

        var availableFactors = await AvailableFactorsAsync(user, ct);
        if (availableFactors.Count > 0)
        {
            await WriteAuditAsync(user, AuditAction.MfaChallenge, ip, userAgent, ct);
            string challenge = _jwt.CreateMfaChallengeToken(user.Id, MfaChallengeLifetime);
            return LoginResult.MfaRequired(challenge, availableFactors);
        }

        return await IssueSessionAsync(user, ip, userAgent, ct);
    }

    public async Task<LoginResult> VerifyMfaAsync(string challengeToken, string code, MfaFactor factor, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var claims = await _jwt.ValidateAsync(challengeToken, JwtTokenService.MfaChallengePurpose);
        if (claims is null)
        {
            return LoginResult.Failure();
        }

        var user = await _db.Users
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(u => u.Id == claims.UserId, ct);

        if (user is null)
        {
            return LoginResult.Failure();
        }

        if (IsLockedOut(user))
        {
            await WriteAuditAsync(user, AuditAction.LoginFailed, ip, userAgent, ct);
            return LoginResult.Failure();
        }

        // No dedicated "MfaFailed" audit action exists for TOTP; LoginFailed is reused for a
        // failed second factor (a wrong Email OTP code is separately audited as EmailOtpFailed by
        // EmailOtpMfaService itself). A wrong code counts toward the same lockout as a wrong
        // password — the attacker already cleared the password check to get here, and a 6-digit
        // code is brute-forceable without this.
        bool valid = factor switch
        {
            MfaFactor.Totp => user.MfaEnabled && user.MfaSecret is not null
                && _totp.ValidateCode(_secretProtector.Unprotect(user.MfaSecret), code),
            MfaFactor.EmailOtp => await _emailOtpMfa.VerifyChallengeCodeAsync(user.Id, code, ip, userAgent, ct),
            _ => false,
        };

        if (!valid)
        {
            await RegisterFailedAttemptAsync(user, ip, userAgent, ct);
            return LoginResult.Failure();
        }

        ResetLockoutState(user);

        return await IssueSessionAsync(user, ip, userAgent, ct);
    }

    /// <summary>
    /// Sends an Email OTP code for an in-progress MFA challenge (see docs/features/authentication.md
    /// "Email OTP come fattore MFA"). Unlike TOTP, whose code lives on the user's own device, Email
    /// OTP requires an explicit send step before the user has anything to enter.
    /// </summary>
    public async Task<bool> RequestMfaEmailOtpAsync(string challengeToken, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var claims = await _jwt.ValidateAsync(challengeToken, JwtTokenService.MfaChallengePurpose);
        if (claims is null)
        {
            return false;
        }

        // Uniform response regardless of whether the user actually has this factor enabled — see
        // EmailOtpMfaService.SendChallengeCodeAsync, which no-ops in that case.
        await _emailOtpMfa.SendChallengeCodeAsync(claims.UserId, ip, userAgent, ct);
        return true;
    }

    /// <summary>
    /// Starts a WebAuthn assertion for an in-progress MFA challenge (see docs/features/authentication.md
    /// "WebAuthn/Passkey"). Unlike Email OTP's uniform-response send, this returns null both for an
    /// invalid challenge token and for a user with no registered credential — the client needs the
    /// actual options to call <c>navigator.credentials.get()</c>, so there is no meaningful uniform
    /// response to give it in either case.
    /// </summary>
    public async Task<string?> RequestWebAuthnAssertionOptionsAsync(string challengeToken, CancellationToken ct = default)
    {
        var claims = await _jwt.ValidateAsync(challengeToken, JwtTokenService.MfaChallengePurpose);
        return claims is null ? null : await _webAuthn.BeginAssertionAsync(claims.UserId, ct);
    }

    public async Task<LoginResult> VerifyWebAuthnAsync(string challengeToken, string assertionResponseJson, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var claims = await _jwt.ValidateAsync(challengeToken, JwtTokenService.MfaChallengePurpose);
        if (claims is null)
        {
            return LoginResult.Failure();
        }

        var user = await _db.Users
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(u => u.Id == claims.UserId, ct);

        if (user is null)
        {
            return LoginResult.Failure();
        }

        if (IsLockedOut(user))
        {
            await WriteAuditAsync(user, AuditAction.LoginFailed, ip, userAgent, ct);
            return LoginResult.Failure();
        }

        if (!await _webAuthn.CompleteAssertionAsync(user.Id, assertionResponseJson, ct))
        {
            await RegisterFailedAttemptAsync(user, ip, userAgent, ct);
            return LoginResult.Failure();
        }

        ResetLockoutState(user);

        return await IssueSessionAsync(user, ip, userAgent, ct);
    }

    private async Task<IReadOnlyList<MfaFactor>> AvailableFactorsAsync(User user, CancellationToken ct)
    {
        var factors = new List<MfaFactor>();
        if (user.MfaEnabled)
        {
            factors.Add(MfaFactor.Totp);
        }

        if (user.MfaEmailOtpEnabled)
        {
            factors.Add(MfaFactor.EmailOtp);
        }

        // No single on/off flag for WebAuthn (unlike the other two factors): a user may register
        // several credentials, and any of them makes the factor available.
        if (await _db.WebAuthnCredentials.AnyAsync(c => c.UserId == user.Id, ct))
        {
            factors.Add(MfaFactor.WebAuthn);
        }

        return factors;
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

        // Before this login's own audit entry is written below, so "any prior LoginSuccess from
        // this IP" correctly excludes the attempt currently in progress.
        if (_securityNotifications is not null)
        {
            await _securityNotifications.NotifyLoginIfNewIpAsync(user.Id, ip, userAgent, ct);
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
