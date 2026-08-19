using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Crypto;
using CffVaultManager.Domain;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// The optional, opt-in recovery-kit flow — see docs/security-model.md#recovery-kit. Deliberately
/// a separate service from <see cref="AuthenticationService"/> rather than an extension of it: it
/// duplicates a small amount of MFA-dispatch logic (see <see cref="VerifyMfaAsync"/>) instead of
/// reusing <c>AuthenticationService.VerifyMfaAsync</c>, because that method always ends by issuing a
/// full login session — reusing it here would make it easy to accidentally grant a session without
/// consuming the kit, revoking other sessions, or notifying the account owner.
/// </summary>
internal sealed class AccountRecoveryService : IAccountRecoveryService
{
    private static readonly TimeSpan MfaChallengeLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RecoveryTokenLifetime = TimeSpan.FromMinutes(5);

    // Fixed length of a real RecoveryEncryptedDek (EncryptedBlob wrapping a 32-byte DEK): version
    // byte + nonce + ciphertext (same length as the 32-byte plaintext) + tag. StartAsync's fake
    // blob must match this exactly, or its length alone would reveal that no real kit exists.
    private const int EncryptedDekBlobLength =
        1 + CryptoConstants.GcmNonceLengthBytes + CryptoConstants.KeyLengthBytes + CryptoConstants.GcmTagLengthBytes;

    // Same anti-enumeration reasoning and caching pattern as AuthenticationService's own
    // _cachedDummyStoredHash/_cachedPreloginPepper — separate static fields, not shared with that
    // class, since this is a different service verifying a different secret.
    private static byte[]? _cachedDummyRecoveryKeyHash;
    private static readonly object DummyRecoveryKeyHashLock = new();
    private static byte[]? _cachedFakeBlobIkm;
    private static readonly object FakeBlobIkmLock = new();

    private readonly CffVaultManagerDbContext _db;
    private readonly IAuthHashHasher _authHashHasher;
    private readonly IJwtTokenService _jwt;
    private readonly IRefreshTokenService _refreshTokens;
    private readonly ITotpService _totp;
    private readonly ISecretProtector _secretProtector;
    private readonly IEmailOtpMfaService _emailOtpMfa;
    private readonly IWebAuthnService _webAuthn;
    private readonly ISecurityNotificationService? _securityNotifications;
    private readonly byte[] _dummyRecoveryKeyHash;

    public AccountRecoveryService(
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
        _dummyRecoveryKeyHash = GetOrCreateDummyRecoveryKeyHash(authHashHasher);
    }

    private static byte[] GetOrCreateDummyRecoveryKeyHash(IAuthHashHasher hasher)
    {
        if (_cachedDummyRecoveryKeyHash is { } cached)
        {
            return cached;
        }

        lock (DummyRecoveryKeyHashLock)
        {
            return _cachedDummyRecoveryKeyHash ??= hasher.Hash(RandomNumberGenerator.GetBytes(32));
        }
    }

    private static byte[] GetOrCreateFakeBlobIkm()
    {
        if (_cachedFakeBlobIkm is { } cached)
        {
            return cached;
        }

        lock (FakeBlobIkmLock)
        {
            return _cachedFakeBlobIkm ??= RandomNumberGenerator.GetBytes(32);
        }
    }

    public async Task<bool> GenerateKitAsync(Guid userId, GenerateRecoveryKitRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Runs post-authentication, so the tenant query filter already scopes this to the caller's
        // own user record (mirrors ChangeMasterPasswordService/MfaSetupService).
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return false;
        }

        // Overwrites any prior kit unconditionally — regenerating is always allowed, no re-proof
        // of the current master password required (same convention as /api/auth/mfa/setup and
        // /api/auth/keypair: the caller already has an unlocked, authenticated session).
        user.RecoveryEncryptedDek = request.RecoveryEncryptedDek;
        user.RecoveryKeyHash = _authHashHasher.Hash(request.RecoveryAuthHash);
        user.RecoveryKitGeneratedAt = DateTimeOffset.UtcNow;

        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.RecoveryKitGenerated));
        await _db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<byte[]> StartAsync(string email, CancellationToken ct = default)
    {
        // Pre-authentication: the tenant is not known yet, same legitimate bypass as
        // AuthenticationService.LoginAsync/PreloginAsync.
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email == IdentifierNormalization.NormalizeEmail(email), ct);
        if (user?.RecoveryEncryptedDek is { } real)
        {
            return real;
        }

        // Unknown email or a real account with no kit: return a blob that is stable for this email
        // across every call, of exactly the same length as a real one — a fresh random blob on
        // every call, or one of a different length, would itself reveal which case occurred.
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, GetOrCreateFakeBlobIkm(), EncryptedDekBlobLength, info: System.Text.Encoding.UTF8.GetBytes(email));
    }

    public async Task<RecoveryVerifyResult> VerifyAsync(string email, byte[] recoveryAuthHash, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email == IdentifierNormalization.NormalizeEmail(email), ct);

        if (user?.RecoveryKeyHash is null)
        {
            // Same reasoning as AuthenticationService.LoginAsync's unknown-email branch: pay the
            // same hashing cost so response latency alone can't distinguish "no such account" or
            // "account exists but has no kit" from "wrong recovery key".
            _authHashHasher.Verify(recoveryAuthHash, _dummyRecoveryKeyHash);
            return RecoveryVerifyResult.Failure();
        }

        if (!_authHashHasher.Verify(recoveryAuthHash, user.RecoveryKeyHash))
        {
            return RecoveryVerifyResult.Failure();
        }

        var availableFactors = await AvailableFactorsAsync(user, ct);
        if (availableFactors.Count > 0)
        {
            string challenge = _jwt.CreateMfaChallengeToken(user.Id, MfaChallengeLifetime, JwtTokenService.RecoveryMfaChallengePurpose);
            return RecoveryVerifyResult.MfaRequired(challenge, availableFactors);
        }

        return RecoveryVerifyResult.Authorized(_jwt.CreateRecoveryAuthorizedToken(user.Id, RecoveryTokenLifetime));
    }

    public async Task<RecoveryVerifyResult> VerifyMfaAsync(string challengeToken, string code, MfaFactor factor, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var claims = await _jwt.ValidateAsync(challengeToken, JwtTokenService.RecoveryMfaChallengePurpose);
        if (claims is null)
        {
            return RecoveryVerifyResult.Failure();
        }

        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == claims.UserId, ct);
        if (user is null)
        {
            return RecoveryVerifyResult.Failure();
        }

        // Same dispatch as AuthenticationService.VerifyMfaAsync, duplicated deliberately (see the
        // class doc comment) rather than reused. No lockout counter, no failed-attempt audit here:
        // brute-forcing this code already requires having passed the RecoveryAuthHash check first
        // (a 256-bit secret), so a dedicated lockout mechanism wouldn't close a real threat.
        bool valid = factor switch
        {
            MfaFactor.Totp => ValidateTotp(user, code),
            MfaFactor.EmailOtp => await _emailOtpMfa.VerifyChallengeCodeAsync(user.Id, code, ip, userAgent, ct),
            _ => false,
        };

        if (!valid)
        {
            return RecoveryVerifyResult.Failure();
        }

        return RecoveryVerifyResult.Authorized(_jwt.CreateRecoveryAuthorizedToken(user.Id, RecoveryTokenLifetime));
    }

    public async Task<bool> RequestMfaEmailOtpAsync(string challengeToken, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var claims = await _jwt.ValidateAsync(challengeToken, JwtTokenService.RecoveryMfaChallengePurpose);
        if (claims is null)
        {
            return false;
        }

        // Uniform response regardless of whether the user actually has this factor enabled — see
        // EmailOtpMfaService.SendChallengeCodeAsync, which no-ops in that case.
        await _emailOtpMfa.SendChallengeCodeAsync(claims.UserId, ip, userAgent, ct);
        return true;
    }

    public async Task<string?> RequestWebAuthnAssertionOptionsAsync(string challengeToken, CancellationToken ct = default)
    {
        var claims = await _jwt.ValidateAsync(challengeToken, JwtTokenService.RecoveryMfaChallengePurpose);
        return claims is null ? null : await _webAuthn.BeginAssertionAsync(claims.UserId, ct);
    }

    public async Task<RecoveryVerifyResult> VerifyWebAuthnAsync(string challengeToken, string assertionResponseJson, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var claims = await _jwt.ValidateAsync(challengeToken, JwtTokenService.RecoveryMfaChallengePurpose);
        if (claims is null)
        {
            return RecoveryVerifyResult.Failure();
        }

        if (!await _webAuthn.CompleteAssertionAsync(claims.UserId, assertionResponseJson, ct))
        {
            return RecoveryVerifyResult.Failure();
        }

        return RecoveryVerifyResult.Authorized(_jwt.CreateRecoveryAuthorizedToken(claims.UserId, RecoveryTokenLifetime));
    }

    public async Task<bool> CompleteAsync(RecoveryCompleteRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var claims = await _jwt.ValidateAsync(request.RecoveryToken, JwtTokenService.RecoveryAuthorizedPurpose);
        if (claims is null)
        {
            return false;
        }

        // Pre-authentication (no session exists yet — that's the whole point of recovery), same
        // bypass as everywhere else in this class.
        var user = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == claims.UserId, ct);
        if (user is null)
        {
            return false;
        }

        // Mirrors ChangeMasterPasswordService's field mutation exactly, minus the CurrentAuthHash
        // check — already proven by the validated RecoveryToken.
        user.MasterPasswordHash = _authHashHasher.Hash(request.NewAuthHash);
        user.EncryptedDek = request.NewEncryptedDek;
        user.MasterPasswordSalt = request.NewMasterPasswordSalt;
        user.KdfMemoryKb = request.NewKdfMemoryKb;
        user.KdfIterations = request.NewKdfIterations;
        user.KdfVersion = request.NewKdfVersion;

        // Consumes the kit (one-time use): clears the two crypto fields but deliberately keeps
        // RecoveryKitGeneratedAt, so /security can show "invalidated, regenerate" rather than
        // "never had one" — see User.RecoveryKitGeneratedAt's own doc comment.
        user.RecoveryEncryptedDek = null;
        user.RecoveryKeyHash = null;

        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, user.Id, AuditAction.AccountRecovered));
        await _db.SaveChangesAsync(ct);

        await _refreshTokens.RevokeAllSessionsAsync(user.Id, user.TenantId, ct);

        if (_securityNotifications is not null)
        {
            await _securityNotifications.NotifyAccountRecoveredAsync(user.Id, ct);
        }

        return true;
    }

    // Duplicated from AuthenticationService deliberately (see the class doc comment on why the
    // whole MFA dispatch is duplicated rather than shared).
    private bool ValidateTotp(User user, string code)
    {
        if (!user.MfaEnabled || user.MfaSecret is null)
        {
            return false;
        }

        try
        {
            return _totp.ValidateCode(_secretProtector.Unprotect(user.MfaSecret), code);
        }
        catch (CryptographicException)
        {
            return false;
        }
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

        if (await _db.WebAuthnCredentials.AnyAsync(c => c.UserId == user.Id, ct))
        {
            factors.Add(MfaFactor.WebAuthn);
        }

        return factors;
    }
}
