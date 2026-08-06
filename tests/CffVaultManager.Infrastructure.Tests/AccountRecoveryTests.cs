using System.Security.Cryptography;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Application.Dtos.VaultCore;
using CffVaultManager.Crypto;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using Fido2NetLib;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Coverage for the recovery-kit flow (see docs/security-model.md#recovery-kit) against an
/// in-memory SQLite database, mirroring the setup style of AuthenticationTests/DekRotationTests.
/// </summary>
public sealed class AccountRecoveryTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;
    private readonly IJwtTokenService _jwt;
    private readonly ITotpService _totp = new TotpService();
    private readonly ISecretProtector _secretProtector;
    private readonly IFido2 _fido2 = WebAuthnTestConfig.CreateFido2();

    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);
    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    public AccountRecoveryTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using (var ctx = CreateContext(SuperAdmin()))
        {
            ctx.Database.EnsureCreated();
        }

        _authHashHasher = new ServerAuthHashHasher(new Argon2KeyDerivationService(), CheapKdf);

        var dataProtection = new ServiceCollection()
            .AddDataProtection()
            .Services
            .BuildServiceProvider()
            .GetRequiredService<IDataProtectionProvider>();
        _secretProtector = new SecretProtector(dataProtection);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SigningKey"] = "test-signing-key-that-is-comfortably-long-enough-0123456789abcdef",
            })
            .Build();
        _jwt = new JwtTokenService(config);
    }

    public void Dispose() => _connection.Dispose();

    [Fact]
    public async Task GenerateKitAsync_sets_all_three_fields_and_writes_audit()
    {
        var (tenantId, userId) = await ProvisionAsync();
        byte[] recoveryEncryptedDek = RandomBytes(61);
        byte[] recoveryAuthHash = RandomBytes(32);

        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            bool result = await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(recoveryEncryptedDek, recoveryAuthHash));
            Assert.True(result);
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        Assert.Equal(recoveryEncryptedDek, user.RecoveryEncryptedDek);
        Assert.NotNull(user.RecoveryKeyHash);
        Assert.NotNull(user.RecoveryKitGeneratedAt);
        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.UserId == userId && a.Action == AuditAction.RecoveryKitGenerated));
    }

    [Fact]
    public async Task GenerateKitAsync_called_twice_overwrites_the_first_kit()
    {
        var (tenantId, userId) = await ProvisionAsync();
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(RandomBytes(61), RandomBytes(32)));
        }

        byte[] secondBlob = RandomBytes(61);
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(secondBlob, RandomBytes(32)));
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        Assert.Equal(secondBlob, user.RecoveryEncryptedDek);
    }

    [Fact]
    public async Task StartAsync_for_a_real_kit_returns_the_real_blob()
    {
        var (tenantId, userId) = await ProvisionAsync();
        byte[] realBlob = RandomBytes(61);
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(realBlob, RandomBytes(32)));
        }

        using var verify = CreateContext(Unresolved());
        byte[] result = await CreateService(verify).StartAsync("admin@x.com");
        Assert.Equal(realBlob, result);
    }

    [Fact]
    public async Task StartAsync_for_unknown_email_and_for_a_real_account_without_a_kit_return_same_length_fake_blobs()
    {
        await ProvisionAsync();

        using var ctx = CreateContext(Unresolved());
        var service = CreateService(ctx);
        byte[] unknownEmailBlob = await service.StartAsync("nobody@nowhere.test");
        byte[] noKitBlob = await service.StartAsync("admin@x.com");

        Assert.Equal(unknownEmailBlob.Length, noKitBlob.Length);
        Assert.NotEmpty(unknownEmailBlob);
    }

    [Fact]
    public async Task VerifyAsync_with_correct_hash_and_no_mfa_returns_Authorized_with_a_valid_token()
    {
        var (tenantId, userId) = await ProvisionAsync();
        byte[] recoveryAuthHash = RandomBytes(32);
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(RandomBytes(61), recoveryAuthHash));
        }

        using var verify = CreateContext(Unresolved());
        var result = await CreateService(verify).VerifyAsync("admin@x.com", recoveryAuthHash, null, null);

        Assert.True(result.Success);
        Assert.False(result.RequiresMfa);
        Assert.NotNull(result.RecoveryToken);

        var claims = await _jwt.ValidateAsync(result.RecoveryToken!, JwtTokenService.RecoveryAuthorizedPurpose);
        Assert.NotNull(claims);
        Assert.Equal(userId, claims!.UserId);
    }

    [Fact]
    public async Task VerifyAsync_with_wrong_hash_returns_Failure_for_both_known_and_unknown_email()
    {
        var (tenantId, userId) = await ProvisionAsync();
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(RandomBytes(61), RandomBytes(32)));
        }

        using var verify = CreateContext(Unresolved());
        var service = CreateService(verify);

        var knownWrong = await service.VerifyAsync("admin@x.com", RandomBytes(32), null, null);
        var unknown = await service.VerifyAsync("nobody@nowhere.test", RandomBytes(32), null, null);

        Assert.False(knownWrong.Success);
        Assert.False(knownWrong.RequiresMfa);
        Assert.False(unknown.Success);
        Assert.False(unknown.RequiresMfa);
    }

    [Fact]
    public async Task VerifyAsync_for_a_user_with_totp_enabled_returns_MfaRequired_and_the_token_only_validates_with_the_recovery_purpose()
    {
        var (tenantId, userId) = await ProvisionAsync();
        byte[] recoveryAuthHash = RandomBytes(32);
        byte[] totpSecret = _totp.GenerateSecret();

        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(RandomBytes(61), recoveryAuthHash));
        }

        using (var ctx = CreateContext(SuperAdmin()))
        {
            var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
            user.MfaEnabled = true;
            user.MfaSecret = _secretProtector.Protect(totpSecret);
            await ctx.SaveChangesAsync();
        }

        using var verify = CreateContext(Unresolved());
        var result = await CreateService(verify).VerifyAsync("admin@x.com", recoveryAuthHash, null, null);

        Assert.True(result.RequiresMfa);
        Assert.Contains(MfaFactor.Totp, result.AvailableMfaFactors);
        Assert.NotNull(result.MfaChallengeToken);

        // Regression test: a recovery-minted challenge must never validate as a login challenge,
        // and vice versa — see the plan's "purpose separation" fix.
        Assert.Null(await _jwt.ValidateAsync(result.MfaChallengeToken!, JwtTokenService.MfaChallengePurpose));
        Assert.NotNull(await _jwt.ValidateAsync(result.MfaChallengeToken!, JwtTokenService.RecoveryMfaChallengePurpose));
    }

    [Fact]
    public async Task VerifyMfaAsync_with_correct_totp_code_returns_Authorized()
    {
        var (tenantId, userId) = await ProvisionAsync();
        byte[] recoveryAuthHash = RandomBytes(32);
        byte[] totpSecret = _totp.GenerateSecret();

        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(RandomBytes(61), recoveryAuthHash));
        }

        using (var ctx = CreateContext(SuperAdmin()))
        {
            var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
            user.MfaEnabled = true;
            user.MfaSecret = _secretProtector.Protect(totpSecret);
            await ctx.SaveChangesAsync();
        }

        string challengeToken;
        using (var ctx = CreateContext(Unresolved()))
        {
            var verifyResult = await CreateService(ctx).VerifyAsync("admin@x.com", recoveryAuthHash, null, null);
            challengeToken = verifyResult.MfaChallengeToken!;
        }

        string code = new OtpNet.Totp(totpSecret).ComputeTotp();
        using var verify = CreateContext(Unresolved());
        var result = await CreateService(verify).VerifyMfaAsync(challengeToken, code, MfaFactor.Totp, null, null);

        Assert.True(result.Success);
        Assert.NotNull(result.RecoveryToken);
    }

    [Fact]
    public async Task VerifyMfaAsync_with_wrong_code_returns_Failure_and_does_not_touch_FailedLoginAttempts()
    {
        var (tenantId, userId) = await ProvisionAsync();
        byte[] recoveryAuthHash = RandomBytes(32);
        byte[] totpSecret = _totp.GenerateSecret();

        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(RandomBytes(61), recoveryAuthHash));
        }

        using (var ctx = CreateContext(SuperAdmin()))
        {
            var user = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
            user.MfaEnabled = true;
            user.MfaSecret = _secretProtector.Protect(totpSecret);
            await ctx.SaveChangesAsync();
        }

        string challengeToken;
        using (var ctx = CreateContext(Unresolved()))
        {
            var verifyResult = await CreateService(ctx).VerifyAsync("admin@x.com", recoveryAuthHash, null, null);
            challengeToken = verifyResult.MfaChallengeToken!;
        }

        using (var ctx = CreateContext(Unresolved()))
        {
            var result = await CreateService(ctx).VerifyMfaAsync(challengeToken, "000000", MfaFactor.Totp, null, null);
            Assert.False(result.Success);
        }

        using var verify = CreateContext(SuperAdmin());
        var user2 = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        Assert.Equal(0, user2.FailedLoginAttempts);
    }

    [Fact]
    public async Task CompleteAsync_with_valid_token_replaces_master_password_material_consumes_kit_and_revokes_sessions()
    {
        var (tenantId, userId) = await ProvisionAsync();
        byte[] recoveryAuthHash = RandomBytes(32);

        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(RandomBytes(61), recoveryAuthHash));
            await new RefreshTokenService(ctx).IssueAsync(userId, null, null);
        }

        string recoveryToken;
        using (var ctx = CreateContext(Unresolved()))
        {
            var verifyResult = await CreateService(ctx).VerifyAsync("admin@x.com", recoveryAuthHash, null, null);
            recoveryToken = verifyResult.RecoveryToken!;
        }

        byte[] newAuthHash = RandomBytes(32);
        byte[] newEncryptedDek = RandomBytes(48);
        byte[] newSalt = RandomBytes(16);

        using (var ctx = CreateContext(Unresolved()))
        {
            bool completed = await CreateService(ctx).CompleteAsync(
                new RecoveryCompleteRequest(recoveryToken, newAuthHash, newEncryptedDek, newSalt, 65536, 3, 1));
            Assert.True(completed);
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        Assert.Equal(newEncryptedDek, user.EncryptedDek);
        Assert.Equal(newSalt, user.MasterPasswordSalt);
        Assert.True(_authHashHasher.Verify(newAuthHash, user.MasterPasswordHash!));

        // Kit consumed: crypto fields cleared, but RecoveryKitGeneratedAt kept (see the /security
        // three-state UI design — "invalidated, regenerate" vs "never had one").
        Assert.Null(user.RecoveryEncryptedDek);
        Assert.Null(user.RecoveryKeyHash);
        Assert.NotNull(user.RecoveryKitGeneratedAt);

        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.UserId == userId && a.Action == AuditAction.AccountRecovered));

        var sessions = await new RefreshTokenService(verify).ListActiveSessionsAsync(userId);
        Assert.Empty(sessions);
    }

    [Fact]
    public async Task CompleteAsync_with_an_invalid_token_returns_false_and_makes_no_changes()
    {
        var (tenantId, userId) = await ProvisionAsync();

        using (var ctx = CreateContext(Unresolved()))
        {
            bool completed = await CreateService(ctx).CompleteAsync(
                new RecoveryCompleteRequest("not-a-real-token", RandomBytes(32), RandomBytes(48), RandomBytes(16), 65536, 3, 1));
            Assert.False(completed);
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        Assert.Equal(Dek, user.EncryptedDek);
    }

    [Fact]
    public async Task DekRotation_invalidates_an_existing_kit_and_writes_audit_and_notification()
    {
        var (tenantId, userId) = await ProvisionAsync();
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(RandomBytes(61), RandomBytes(32)));
        }

        var notifications = new RecordingSecurityNotificationService();
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await new DekRotationService(ctx, notifications).RotateDekAsync(userId, new RotateDekRequest(RandomBytes(48), []));
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        Assert.Null(user.RecoveryEncryptedDek);
        Assert.Null(user.RecoveryKeyHash);
        Assert.NotNull(user.RecoveryKitGeneratedAt);
        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.UserId == userId && a.Action == AuditAction.RecoveryKitInvalidated));
        Assert.True(notifications.RecoveryKitInvalidatedCalled);
    }

    [Fact]
    public async Task DekRotation_without_a_kit_does_not_write_RecoveryKitInvalidated_audit_or_notify()
    {
        var (tenantId, userId) = await ProvisionAsync();

        var notifications = new RecordingSecurityNotificationService();
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await new DekRotationService(ctx, notifications).RotateDekAsync(userId, new RotateDekRequest(RandomBytes(48), []));
        }

        using var verify = CreateContext(SuperAdmin());
        Assert.False(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.UserId == userId && a.Action == AuditAction.RecoveryKitInvalidated));
        Assert.False(notifications.RecoveryKitInvalidatedCalled);
    }

    [Fact]
    public async Task DekRotation_clearsPrfWrappedDekOnEveryCredential_andWritesAuditAndNotification()
    {
        var (tenantId, userId) = await ProvisionAsync();

        Guid passwordlessCredentialId = Guid.NewGuid();
        Guid mfaOnlyCredentialId = Guid.NewGuid();
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            // One passwordless-enabled credential (has PrfWrappedDek) and one plain MFA-only
            // credential (doesn't) — only the former should be touched by rotation.
            ctx.WebAuthnCredentials.Add(new WebAuthnCredential(
                passwordlessCredentialId, userId, RandomBytes(32), RandomBytes(64), signCount: 1, aaGuid: Guid.NewGuid(),
                prfWrappedDek: RandomBytes(48)));
            ctx.WebAuthnCredentials.Add(new WebAuthnCredential(
                mfaOnlyCredentialId, userId, RandomBytes(32), RandomBytes(64), signCount: 1, aaGuid: Guid.NewGuid()));
            await ctx.SaveChangesAsync();
        }

        var notifications = new RecordingSecurityNotificationService();
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await new DekRotationService(ctx, notifications).RotateDekAsync(userId, new RotateDekRequest(RandomBytes(48), []));
        }

        using var verify = CreateContext(SuperAdmin());
        var passwordlessCredential = await verify.WebAuthnCredentials.IgnoreQueryFilters().SingleAsync(c => c.Id == passwordlessCredentialId);
        var mfaOnlyCredential = await verify.WebAuthnCredentials.IgnoreQueryFilters().SingleAsync(c => c.Id == mfaOnlyCredentialId);
        Assert.Null(passwordlessCredential.PrfWrappedDek);
        Assert.Null(mfaOnlyCredential.PrfWrappedDek); // was already null; rotation must not fail touching it

        Assert.True(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.UserId == userId && a.Action == AuditAction.PasskeyLoginInvalidatedByRotation));
        Assert.True(notifications.PasskeyLoginInvalidatedCalled);
    }

    [Fact]
    public async Task DekRotation_withNoPasswordlessCredentials_doesNotWritePasskeyLoginInvalidatedAuditOrNotify()
    {
        var (tenantId, userId) = await ProvisionAsync();

        var notifications = new RecordingSecurityNotificationService();
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await new DekRotationService(ctx, notifications).RotateDekAsync(userId, new RotateDekRequest(RandomBytes(48), []));
        }

        using var verify = CreateContext(SuperAdmin());
        Assert.False(await verify.AuditLogEntries.IgnoreQueryFilters()
            .AnyAsync(a => a.UserId == userId && a.Action == AuditAction.PasskeyLoginInvalidatedByRotation));
        Assert.False(notifications.PasskeyLoginInvalidatedCalled);
    }

    [Fact]
    public async Task ChangeMasterPassword_does_not_touch_recovery_fields()
    {
        var (tenantId, userId) = await ProvisionAsync();
        byte[] recoveryEncryptedDek = RandomBytes(61);
        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            await CreateService(ctx).GenerateKitAsync(userId, new GenerateRecoveryKitRequest(recoveryEncryptedDek, RandomBytes(32)));
        }

        using (var ctx = CreateContext(Tenant(tenantId, userId)))
        {
            var service = new ChangeMasterPasswordService(ctx, _authHashHasher, new RefreshTokenService(ctx));
            bool changed = await service.ChangeMasterPasswordAsync(userId, new ChangeMasterPasswordRequest(
                ProvisionAuthHash, RandomBytes(32), RandomBytes(48), RandomBytes(16), 65536, 3, 1));
            Assert.True(changed);
        }

        using var verify = CreateContext(SuperAdmin());
        var user = await verify.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == userId);
        Assert.Equal(recoveryEncryptedDek, user.RecoveryEncryptedDek);
        Assert.NotNull(user.RecoveryKeyHash);
    }

    // ---- Helpers ------------------------------------------------------------------------------

    private static readonly byte[] ProvisionAuthHash = RandomNumberGenerator.GetBytes(32);

    private CffVaultManagerDbContext CreateContext(ITenantContext tenantContext)
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlite(_connection)
            .Options;
        return new CffVaultManagerDbContext(options, tenantContext);
    }

    private AccountRecoveryService CreateService(CffVaultManagerDbContext ctx) =>
        new(ctx, _authHashHasher, _jwt, new RefreshTokenService(ctx), _totp, _secretProtector,
            new EmailOtpMfaService(ctx, new NoOpEmailSender()), new WebAuthnService(ctx, _fido2));

    private async Task<(Guid TenantId, Guid AdminId)> ProvisionAsync()
    {
        using var ctx = CreateContext(Unresolved());
        var service = new ProvisionTenantService(ctx, _authHashHasher);
        var result = await service.ProvisionAsync(new ProvisionTenantRequest(
            "Acme", "acme", "admin@x.com", ProvisionAuthHash, Dek, Salt, 65536, 3, 1));
        return (result.TenantId, result.AdminUserId);
    }

    private static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

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

    private sealed class NoOpEmailSender : IEmailSender
    {
        public Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class RecordingSecurityNotificationService : ISecurityNotificationService
    {
        public bool RecoveryKitInvalidatedCalled { get; private set; }

        public Task NotifyLoginIfNewIpAsync(Guid userId, string? ip, string? userAgent, CancellationToken ct = default) => Task.CompletedTask;

        public Task NotifyMasterPasswordChangedAsync(Guid userId, CancellationToken ct = default) => Task.CompletedTask;

        public Task NotifyMfaFactorDisabledAsync(Guid userId, string factorDescription, CancellationToken ct = default) => Task.CompletedTask;

        public Task NotifyAccountRecoveredAsync(Guid userId, CancellationToken ct = default) => Task.CompletedTask;

        public Task NotifyRecoveryKitInvalidatedAsync(Guid userId, CancellationToken ct = default)
        {
            RecoveryKitInvalidatedCalled = true;
            return Task.CompletedTask;
        }

        public bool PasskeyLoginInvalidatedCalled { get; private set; }

        public Task NotifyPasskeyLoginInvalidatedAsync(Guid userId, CancellationToken ct = default)
        {
            PasskeyLoginInvalidatedCalled = true;
            return Task.CompletedTask;
        }
    }
}
