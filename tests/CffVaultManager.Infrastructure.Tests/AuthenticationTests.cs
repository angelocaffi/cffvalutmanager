using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Crypto;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// End-to-end coverage of the authentication/provisioning services against an in-memory SQLite
/// database, wiring the real crypto/token services (with a cheap Argon2 cost to stay fast).
/// </summary>
public sealed class AuthenticationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IDataProtectionProvider _dataProtection;
    private readonly IJwtTokenService _jwt;
    private readonly IAuthHashHasher _authHashHasher;
    private readonly ITotpService _totp;
    private readonly ISecretProtector _secretProtector;

    // Deliberately tiny Argon2 cost: security is validated in the Crypto tests; here we only need
    // the salted-rehash behaviour to work, not a production cost.
    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);

    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    public AuthenticationTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            ctx.Database.EnsureCreated();
        }

        _dataProtection = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider()
            .GetRequiredService<IDataProtectionProvider>();
        _authHashHasher = new ServerAuthHashHasher(new Argon2KeyDerivationService(), CheapKdf);
        _totp = new TotpService();
        _secretProtector = new SecretProtector(_dataProtection);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SigningKey"] = "test-signing-key-that-is-comfortably-long-enough-0123456789abcdef",
            })
            .Build();
        _jwt = new JwtTokenService(config);
    }

    public void Dispose() => _connection.Dispose();

    // ---- Tests ------------------------------------------------------------------------------

    [Fact]
    public async Task Provisioning_creates_tenant_and_admin_with_rehashed_authhash_and_audit()
    {
        var authHash = RandomAuthHash();

        ProvisionTenantResult result;
        using (var ctx = CreateContext(Unresolved()))
        {
            var service = new ProvisionTenantService(ctx, _authHashHasher);
            result = await service.ProvisionAsync(NewProvisionRequest(authHash));
        }

        using var verify = CreateContext(SuperAdmin());
        var admin = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == result.AdminUserId);

        Assert.Equal(result.TenantId, admin.TenantId);
        Assert.Equal(UserRole.Admin, admin.Role);
        Assert.NotNull(admin.MasterPasswordHash);
        // The persisted hash must NOT be the raw auth hash: it was rehashed with a random salt.
        Assert.False(admin.MasterPasswordHash!.SequenceEqual(authHash));
        // And it must still verify.
        Assert.True(_authHashHasher.Verify(authHash, admin.MasterPasswordHash));

        var audit = await verify.AuditLogEntries.IgnoreQueryFilters()
            .SingleAsync(a => a.TenantId == result.TenantId && a.Action == AuditAction.TenantProvisioned);
        Assert.Equal(result.AdminUserId, audit.UserId);
    }

    [Fact]
    public async Task Login_with_correct_credentials_without_mfa_succeeds_with_crypto_materials()
    {
        var authHash = RandomAuthHash();
        var (tenantId, _) = await ProvisionAsync(authHash);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var result = await auth.LoginAsync("admin@x.com", authHash, "1.2.3.4", "agent");

        Assert.True(result.Success);
        Assert.False(result.RequiresMfa);
        Assert.NotNull(result.AccessToken);
        Assert.NotNull(result.RefreshToken);
        Assert.NotNull(result.CryptoMaterials);
        Assert.True(result.CryptoMaterials!.EncryptedDek.SequenceEqual(Dek));

        var claims = await _jwt.ValidateAsync(result.AccessToken!);
        Assert.NotNull(claims);
        Assert.Equal(tenantId, claims!.TenantId);
        Assert.Equal(UserRole.Admin, claims.Role);

        var success = await ctx.AuditLogEntries.IgnoreQueryFilters()
            .CountAsync(a => a.Action == AuditAction.LoginSuccess);
        Assert.Equal(1, success);
    }

    [Fact]
    public async Task Login_with_wrong_authhash_fails_generically_and_audits_loginfailed()
    {
        var authHash = RandomAuthHash();
        await ProvisionAsync(authHash);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var result = await auth.LoginAsync("admin@x.com", RandomAuthHash(), null, null);

        Assert.False(result.Success);
        Assert.False(result.RequiresMfa);
        Assert.Null(result.AccessToken);
        Assert.Null(result.CryptoMaterials);
        Assert.NotNull(result.FailureReason);

        var failed = await ctx.AuditLogEntries.IgnoreQueryFilters()
            .CountAsync(a => a.Action == AuditAction.LoginFailed);
        Assert.Equal(1, failed);
    }

    [Fact]
    public async Task Login_after_five_wrong_attempts_locks_the_account()
    {
        var authHash = RandomAuthHash();
        await ProvisionAsync(authHash);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        for (int i = 0; i < 5; i++)
        {
            var attempt = await auth.LoginAsync("admin@x.com", RandomAuthHash(), null, null);
            Assert.False(attempt.Success);
        }

        var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Email == "admin@x.com");
        Assert.NotNull(user.LockedUntil);
        Assert.True(user.LockedUntil > DateTimeOffset.UtcNow);
        Assert.Equal(0, user.FailedLoginAttempts);

        Assert.Equal(1, await ctx.AuditLogEntries.IgnoreQueryFilters().CountAsync(a => a.Action == AuditAction.AccountLocked));
    }

    [Fact]
    public async Task Login_while_locked_fails_even_with_the_correct_password()
    {
        var authHash = RandomAuthHash();
        await ProvisionAsync(authHash);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        for (int i = 0; i < 5; i++)
        {
            await auth.LoginAsync("admin@x.com", RandomAuthHash(), null, null);
        }

        // Correct credentials, but the account is locked — must still fail.
        var result = await auth.LoginAsync("admin@x.com", authHash, null, null);

        Assert.False(result.Success);
        Assert.Null(result.AccessToken);
    }

    [Fact]
    public async Task Login_after_lockout_expires_succeeds_with_correct_password()
    {
        var authHash = RandomAuthHash();
        var (_, adminId) = await ProvisionAsync(authHash);

        using (var ctx = CreateContext(SuperAdmin()))
        {
            var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == adminId);
            user.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(-1); // already expired
            await ctx.SaveChangesAsync();
        }

        using var verifyCtx = CreateContext(Unresolved());
        var auth = CreateAuthService(verifyCtx);

        var result = await auth.LoginAsync("admin@x.com", authHash, null, null);

        Assert.True(result.Success);
        Assert.NotNull(result.AccessToken);
    }

    [Fact]
    public async Task Login_success_resets_the_failed_attempt_counter()
    {
        var authHash = RandomAuthHash();
        await ProvisionAsync(authHash);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        await auth.LoginAsync("admin@x.com", RandomAuthHash(), null, null);
        await auth.LoginAsync("admin@x.com", RandomAuthHash(), null, null);

        var result = await auth.LoginAsync("admin@x.com", authHash, null, null);
        Assert.True(result.Success);

        var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Email == "admin@x.com");
        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.LockedUntil);
    }

    [Fact]
    public async Task VerifyMfa_after_five_wrong_codes_locks_the_account()
    {
        var authHash = RandomAuthHash();
        var (tenantId, adminId) = await ProvisionAsync(authHash);
        var secret = _totp.GenerateSecret();
        await EnableMfaAsync(tenantId, adminId, secret);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var challenge = (await auth.LoginAsync("admin@x.com", authHash, null, null)).MfaChallengeToken!;

        for (int i = 0; i < 5; i++)
        {
            await auth.VerifyMfaAsync(challenge, "000000", null, null);
        }

        var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == adminId);
        Assert.NotNull(user.LockedUntil);
        Assert.True(user.LockedUntil > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task VerifyMfa_while_locked_fails_even_with_the_correct_code()
    {
        var authHash = RandomAuthHash();
        var (tenantId, adminId) = await ProvisionAsync(authHash);
        var secret = _totp.GenerateSecret();
        await EnableMfaAsync(tenantId, adminId, secret);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var challenge = (await auth.LoginAsync("admin@x.com", authHash, null, null)).MfaChallengeToken!;

        for (int i = 0; i < 5; i++)
        {
            await auth.VerifyMfaAsync(challenge, "000000", null, null);
        }

        var code = new OtpNet.Totp(secret).ComputeTotp();
        var result = await auth.VerifyMfaAsync(challenge, code, null, null);

        Assert.False(result.Success);
        Assert.Null(result.AccessToken);
    }

    [Fact]
    public async Task Login_with_unknown_email_fails_without_audit()
    {
        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var result = await auth.LoginAsync("nobody@x.com", RandomAuthHash(), null, null);

        Assert.False(result.Success);
        Assert.Null(result.AccessToken);
        Assert.Equal(0, await ctx.AuditLogEntries.IgnoreQueryFilters().CountAsync());
    }

    [Fact]
    public async Task Login_with_mfa_enabled_returns_only_challenge()
    {
        var authHash = RandomAuthHash();
        var (tenantId, adminId) = await ProvisionAsync(authHash);
        var secret = _totp.GenerateSecret();
        await EnableMfaAsync(tenantId, adminId, secret);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var result = await auth.LoginAsync("admin@x.com", authHash, null, null);

        Assert.False(result.Success);
        Assert.True(result.RequiresMfa);
        Assert.NotNull(result.MfaChallengeToken);
        Assert.Null(result.AccessToken);
        Assert.Null(result.CryptoMaterials);

        var challengeClaims = await _jwt.ValidateAsync(result.MfaChallengeToken!, JwtTokenService.MfaChallengePurpose);
        Assert.NotNull(challengeClaims);
        Assert.Null(challengeClaims!.TenantId);
        Assert.Null(challengeClaims.Role);
    }

    [Fact]
    public async Task VerifyMfa_with_correct_code_succeeds_with_crypto_materials()
    {
        var authHash = RandomAuthHash();
        var (tenantId, adminId) = await ProvisionAsync(authHash);
        var secret = _totp.GenerateSecret();
        await EnableMfaAsync(tenantId, adminId, secret);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var challenge = (await auth.LoginAsync("admin@x.com", authHash, null, null)).MfaChallengeToken!;
        var code = new OtpNet.Totp(secret).ComputeTotp();

        var result = await auth.VerifyMfaAsync(challenge, code, null, null);

        Assert.True(result.Success);
        Assert.NotNull(result.AccessToken);
        Assert.NotNull(result.RefreshToken);
        Assert.NotNull(result.CryptoMaterials);
    }

    [Fact]
    public async Task VerifyMfa_with_wrong_code_fails()
    {
        var authHash = RandomAuthHash();
        var (tenantId, adminId) = await ProvisionAsync(authHash);
        var secret = _totp.GenerateSecret();
        await EnableMfaAsync(tenantId, adminId, secret);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var challenge = (await auth.LoginAsync("admin@x.com", authHash, null, null)).MfaChallengeToken!;

        var result = await auth.VerifyMfaAsync(challenge, "000000", null, null);

        Assert.False(result.Success);
        Assert.Null(result.AccessToken);
        Assert.Null(result.CryptoMaterials);
    }

    [Fact]
    public async Task Login_when_tenant_is_suspended_fails()
    {
        var authHash = RandomAuthHash();
        var (tenantId, _) = await ProvisionAsync(authHash);
        await SuspendTenantAsync(tenantId);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var result = await auth.LoginAsync("admin@x.com", authHash, null, null);

        Assert.False(result.Success);
        Assert.Null(result.AccessToken);
        Assert.Null(result.CryptoMaterials);
    }

    [Fact]
    public async Task VerifyMfa_when_tenant_is_suspended_after_challenge_fails()
    {
        var authHash = RandomAuthHash();
        var (tenantId, adminId) = await ProvisionAsync(authHash);
        var secret = _totp.GenerateSecret();
        await EnableMfaAsync(tenantId, adminId, secret);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var challenge = (await auth.LoginAsync("admin@x.com", authHash, null, null)).MfaChallengeToken!;
        await SuspendTenantAsync(tenantId);
        var code = new OtpNet.Totp(secret).ComputeTotp();

        var result = await auth.VerifyMfaAsync(challenge, code, null, null);

        Assert.False(result.Success);
        Assert.Null(result.AccessToken);
    }

    [Fact]
    public async Task RefreshAsync_when_tenant_is_suspended_fails()
    {
        var authHash = RandomAuthHash();
        var (tenantId, _) = await ProvisionAsync(authHash);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var login = await auth.LoginAsync("admin@x.com", authHash, null, null);
        await SuspendTenantAsync(tenantId);

        var refreshed = await auth.RefreshAsync(login.RefreshToken!, null, null);

        Assert.False(refreshed.Success);
        Assert.Null(refreshed.AccessToken);
    }

    [Fact]
    public async Task Login_after_reactivation_succeeds_again()
    {
        var authHash = RandomAuthHash();
        var (tenantId, _) = await ProvisionAsync(authHash);
        await SuspendTenantAsync(tenantId);

        using (var ctx = CreateContext(SuperAdmin()))
        {
            var tenant = await ctx.Tenants.IgnoreQueryFilters().SingleAsync(t => t.Id == tenantId);
            tenant.Status = TenantStatus.Active;
            await ctx.SaveChangesAsync();
        }

        using var verifyCtx = CreateContext(Unresolved());
        var auth = CreateAuthService(verifyCtx);

        var result = await auth.LoginAsync("admin@x.com", authHash, null, null);

        Assert.True(result.Success);
        Assert.NotNull(result.AccessToken);
    }

    [Fact]
    public async Task RefreshAsync_with_valid_token_issues_new_session()
    {
        var authHash = RandomAuthHash();
        var (tenantId, _) = await ProvisionAsync(authHash);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var login = await auth.LoginAsync("admin@x.com", authHash, null, null);

        var refreshed = await auth.RefreshAsync(login.RefreshToken!, "1.2.3.4", "agent");

        Assert.True(refreshed.Success);
        Assert.NotNull(refreshed.AccessToken);
        Assert.NotNull(refreshed.RefreshToken);
        Assert.NotEqual(login.RefreshToken, refreshed.RefreshToken);
        Assert.NotNull(refreshed.CryptoMaterials);

        var claims = await _jwt.ValidateAsync(refreshed.AccessToken!);
        Assert.NotNull(claims);
        Assert.Equal(tenantId, claims!.TenantId);
        Assert.Equal(UserRole.Admin, claims.Role);
    }

    [Fact]
    public async Task RefreshAsync_with_already_rotated_token_fails()
    {
        var authHash = RandomAuthHash();
        await ProvisionAsync(authHash);

        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var login = await auth.LoginAsync("admin@x.com", authHash, null, null);
        await auth.RefreshAsync(login.RefreshToken!, null, null);

        // Reusing the original (already-rotated) refresh token must fail.
        var reused = await auth.RefreshAsync(login.RefreshToken!, null, null);

        Assert.False(reused.Success);
        Assert.Null(reused.AccessToken);
    }

    [Fact]
    public async Task RefreshAsync_with_unknown_token_fails()
    {
        using var ctx = CreateContext(Unresolved());
        var auth = CreateAuthService(ctx);

        var result = await auth.RefreshAsync("not-a-real-token", null, null);

        Assert.False(result.Success);
        Assert.Null(result.AccessToken);
    }

    [Fact]
    public async Task RefreshToken_cannot_be_rotated_twice()
    {
        var authHash = RandomAuthHash();
        var (_, adminId) = await ProvisionAsync(authHash);

        using var ctx = CreateContext(Unresolved());
        var service = new RefreshTokenService(ctx);

        var issued = await service.IssueAsync(adminId, null, null);

        var first = await service.ValidateAndRotateAsync(issued.PlainToken, null, null);
        Assert.NotNull(first);

        // Reusing the already-rotated token must fail.
        var second = await service.ValidateAndRotateAsync(issued.PlainToken, null, null);
        Assert.Null(second);
    }

    [Fact]
    public async Task ListActiveSessionsAsync_returns_only_active_sessions_newest_first()
    {
        var (_, adminId) = await ProvisionAsync(RandomAuthHash());

        using var ctx = CreateContext(Unresolved());
        var service = new RefreshTokenService(ctx);

        var first = await service.IssueAsync(adminId, "1.1.1.1", "agent-1");
        var second = await service.IssueAsync(adminId, "2.2.2.2", "agent-2");
        var revoked = await service.IssueAsync(adminId, "3.3.3.3", "agent-3");
        await service.RevokeSessionAsync(adminId, null, revoked.Entity.Id);

        var sessions = await service.ListActiveSessionsAsync(adminId);

        Assert.Equal(2, sessions.Count);
        Assert.DoesNotContain(sessions, s => s.Id == revoked.Entity.Id);
        Assert.Contains(sessions, s => s.Id == first.Entity.Id && s.CreatedByIp == "1.1.1.1");
        Assert.Contains(sessions, s => s.Id == second.Entity.Id && s.CreatedByIp == "2.2.2.2");
    }

    [Fact]
    public async Task RevokeSessionAsync_prevents_the_session_from_being_refreshed_again()
    {
        var (tenantId, adminId) = await ProvisionAsync(RandomAuthHash());

        using var ctx = CreateContext(Unresolved());
        var service = new RefreshTokenService(ctx);

        var issued = await service.IssueAsync(adminId, null, null);
        await service.RevokeSessionAsync(adminId, tenantId, issued.Entity.Id);

        var rotated = await service.ValidateAndRotateAsync(issued.PlainToken, null, null);
        Assert.Null(rotated);
    }

    [Fact]
    public async Task RevokeSessionAsync_writes_a_SessionsRevoked_audit_entry()
    {
        var (tenantId, adminId) = await ProvisionAsync(RandomAuthHash());

        using var ctx = CreateContext(Unresolved());
        var service = new RefreshTokenService(ctx);

        var issued = await service.IssueAsync(adminId, null, null);
        await service.RevokeSessionAsync(adminId, tenantId, issued.Entity.Id);

        Assert.True(await ctx.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.UserId == adminId && a.Action == AuditAction.SessionsRevoked));
    }

    [Fact]
    public async Task RevokeSessionAsync_for_a_session_owned_by_another_user_throws_KeyNotFoundException()
    {
        var authHash = RandomAuthHash();
        var (tenantId, adminId) = await ProvisionAsync(authHash);
        var operatorId = await RegisterOperatorAsync(tenantId, adminId);

        using var ctx = CreateContext(Unresolved());
        var service = new RefreshTokenService(ctx);

        var adminSession = await service.IssueAsync(adminId, null, null);

        // operatorId does not own adminSession — must not be able to revoke it.
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            service.RevokeSessionAsync(operatorId, tenantId, adminSession.Entity.Id));
    }

    [Fact]
    public async Task RevokeSessionAsync_for_a_nonexistent_session_throws_KeyNotFoundException()
    {
        var (_, adminId) = await ProvisionAsync(RandomAuthHash());

        using var ctx = CreateContext(Unresolved());
        var service = new RefreshTokenService(ctx);

        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            service.RevokeSessionAsync(adminId, null, Guid.NewGuid()));
    }

    [Fact]
    public async Task RevokeSessionAsync_is_idempotent_for_an_already_revoked_session()
    {
        var (tenantId, adminId) = await ProvisionAsync(RandomAuthHash());

        using var ctx = CreateContext(Unresolved());
        var service = new RefreshTokenService(ctx);

        var issued = await service.IssueAsync(adminId, null, null);
        await service.RevokeSessionAsync(adminId, tenantId, issued.Entity.Id);

        // Revoking again must not throw.
        await service.RevokeSessionAsync(adminId, tenantId, issued.Entity.Id);
    }

    [Fact]
    public async Task RevokeAllSessionsAsync_revokes_every_active_session_but_not_another_users()
    {
        var authHash = RandomAuthHash();
        var (tenantId, adminId) = await ProvisionAsync(authHash);
        var operatorId = await RegisterOperatorAsync(tenantId, adminId);

        using var ctx = CreateContext(Unresolved());
        var service = new RefreshTokenService(ctx);

        var adminSession1 = await service.IssueAsync(adminId, null, null);
        var adminSession2 = await service.IssueAsync(adminId, null, null);
        var operatorSession = await service.IssueAsync(operatorId, null, null);

        await service.RevokeAllSessionsAsync(adminId, tenantId);

        Assert.Null(await service.ValidateAndRotateAsync(adminSession1.PlainToken, null, null));
        Assert.Null(await service.ValidateAndRotateAsync(adminSession2.PlainToken, null, null));

        // The operator's own session is untouched.
        Assert.NotNull(await service.ValidateAndRotateAsync(operatorSession.PlainToken, null, null));
    }

    [Fact]
    public async Task Admin_can_register_user_in_own_tenant()
    {
        var authHash = RandomAuthHash();
        var (tenantId, adminId) = await ProvisionAsync(authHash);

        Guid newUserId;
        using (var ctx = CreateContext(Tenant(tenantId, adminId)))
        {
            var service = new UserRegistrationService(ctx, _authHashHasher);
            newUserId = await service.RegisterInTenantAsync(
                NewRegisterRequest("operator@x.com", UserRole.Operator),
                adminId, UserRole.Admin, tenantId);
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == newUserId);
        Assert.Equal(tenantId, user.TenantId);
        Assert.Equal(UserRole.Operator, user.Role);
    }

    [Fact]
    public async Task Operator_cannot_register_user()
    {
        var authHash = RandomAuthHash();
        var (tenantId, _) = await ProvisionAsync(authHash);

        using var ctx = CreateContext(Tenant(tenantId, Guid.NewGuid()));
        var service = new UserRegistrationService(ctx, _authHashHasher);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.RegisterInTenantAsync(
                NewRegisterRequest("nope@x.com", UserRole.Operator),
                Guid.NewGuid(), UserRole.Operator, tenantId));
    }

    // ---- Helpers ----------------------------------------------------------------------------

    private CffVaultManagerDbContext CreateContext(ITenantContext tenantContext)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlite(_connection)
            .Options;
        return new CffVaultManagerDbContext(options, tenantContext);
    }

    private AuthenticationService CreateAuthService(CffVaultManagerDbContext ctx) =>
        new(ctx, _authHashHasher, _jwt, new RefreshTokenService(ctx), _totp, _secretProtector);

    private async Task<(Guid TenantId, Guid AdminId)> ProvisionAsync(byte[] authHash)
    {
        using var ctx = CreateContext(Unresolved());
        var service = new ProvisionTenantService(ctx, _authHashHasher);
        var result = await service.ProvisionAsync(NewProvisionRequest(authHash));
        return (result.TenantId, result.AdminUserId);
    }

    private async Task<Guid> RegisterOperatorAsync(Guid tenantId, Guid adminId)
    {
        using var ctx = CreateContext(Tenant(tenantId, adminId));
        var service = new UserRegistrationService(ctx, _authHashHasher);
        return await service.RegisterInTenantAsync(
            NewRegisterRequest("operator@x.com", UserRole.Operator), adminId, UserRole.Admin, tenantId);
    }

    private async Task SuspendTenantAsync(Guid tenantId)
    {
        using var ctx = CreateContext(SuperAdmin());
        var tenant = await ctx.Tenants.IgnoreQueryFilters().SingleAsync(t => t.Id == tenantId);
        tenant.Status = TenantStatus.Suspended;
        await ctx.SaveChangesAsync();
    }

    private async Task EnableMfaAsync(Guid tenantId, Guid userId, byte[] secret)
    {
        using var ctx = CreateContext(SuperAdmin());
        var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        user.MfaSecret = _secretProtector.Protect(secret);
        user.MfaEnabled = true;
        await ctx.SaveChangesAsync();
    }

    private static ProvisionTenantRequest NewProvisionRequest(byte[] authHash) => new(
        TenantName: "Acme",
        TenantSlug: "acme",
        AdminEmail: "admin@x.com",
        AuthHash: authHash,
        EncryptedDek: Dek,
        MasterPasswordSalt: Salt,
        KdfMemoryKb: 65536,
        KdfIterations: 3,
        KdfVersion: 1);

    private static RegisterUserRequest NewRegisterRequest(string email, UserRole role) => new(
        Email: email,
        Role: role,
        AuthHash: RandomAuthHash(),
        EncryptedDek: Dek,
        MasterPasswordSalt: Salt,
        KdfMemoryKb: 65536,
        KdfIterations: 3,
        KdfVersion: 1);

    private static byte[] RandomAuthHash() => System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

    private static ITenantContext Unresolved() => new TenantContext();

    private static ITenantContext Tenant(Guid tenantId, Guid userId)
    {
        var c = new TenantContext();
        c.SetTenant(tenantId, userId);
        return c;
    }

    private static ITenantContext SuperAdmin()
    {
        var c = new TenantContext();
        c.SetSuperAdmin(Guid.NewGuid());
        return c;
    }
}
