using System.Security.Cryptography;
using System.Text.RegularExpressions;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Crypto;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Infrastructure.Authentication;
using CffVaultManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>
/// Coverage for the gated self-service tenant signup (see docs/multi-tenancy.md "Provisioning di un
/// nuovo tenant") against an in-memory SQLite database — mirrors the setup style of
/// AuthenticationTests, but self-contained since these tests only need TenantProvisioningRequestService.
/// </summary>
public sealed class TenantProvisioningRequestTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IAuthHashHasher _authHashHasher;
    private readonly FakeEmailSender _emailSender = new();

    // Deliberately tiny Argon2 cost: security is validated in the Crypto tests.
    private static readonly Argon2Parameters CheapKdf = new(memoryKb: 1024, iterations: 1);

    private static readonly byte[] Dek = { 10, 20, 30, 40 };
    private static readonly byte[] Salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    public TenantProvisioningRequestTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using (var ctx = CreateContext())
        {
            ctx.Database.EnsureCreated();
        }

        _authHashHasher = new ServerAuthHashHasher(new Argon2KeyDerivationService(), CheapKdf);
    }

    public void Dispose() => _connection.Dispose();

    [Fact]
    public async Task RequestAsync_creates_only_a_pending_row_no_tenant_or_user_yet()
    {
        using var ctx = CreateContext();
        var service = CreateService(ctx);

        var result = await service.RequestAsync(NewRequest(), ip: null, userAgent: null);

        Assert.NotEqual(Guid.Empty, result.RequestId);
        Assert.Equal(0, await ctx.Tenants.IgnoreQueryFilters().CountAsync());
        Assert.Equal(0, await ctx.Users.IgnoreQueryFilters().CountAsync());
        Assert.Equal(1, await ctx.TenantProvisioningRequests.CountAsync());
        Assert.Equal(1, _emailSender.SendCount);
        Assert.Equal("admin@acme.test", _emailSender.LastToEmail);
    }

    [Fact]
    public async Task RequestAsync_with_a_slug_or_email_already_in_use_throws_InvalidOperationException()
    {
        using var ctx = CreateContext();
        var provisionService = new ProvisionTenantService(ctx, _authHashHasher);
        await provisionService.ProvisionAsync(new ProvisionTenantRequest(
            "Acme", "acme", "admin@acme.test", RandomAuthHash(), Dek, Salt, 65536, 3, 1));

        var service = CreateService(ctx);
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.RequestAsync(NewRequest(), null, null));
    }

    [Fact]
    public async Task ConfirmAsync_with_the_correct_code_provisions_tenant_admin_vault_and_billing_profile()
    {
        using var ctx = CreateContext();
        var service = CreateService(ctx);
        var requested = await service.RequestAsync(NewRequest(), null, null);
        string code = ExtractCode(_emailSender.LastBody!);

        var result = await service.ConfirmAsync(requested.RequestId, code, null, null);

        Assert.NotNull(result);
        var admin = await ctx.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == result!.AdminUserId);
        Assert.NotNull(admin.EmailVerifiedAt);

        var billing = await ctx.TenantBillingProfiles.IgnoreQueryFilters().SingleAsync(b => b.TenantId == result.TenantId);
        Assert.Equal("Mario Rossi", billing.LegalName);
        Assert.Equal("Milano", billing.City);

        Assert.Equal(0, await ctx.TenantProvisioningRequests.CountAsync());
    }

    [Fact]
    public async Task ConfirmAsync_with_the_wrong_code_returns_null_and_increments_attempt_count_without_creating_anything()
    {
        using var ctx = CreateContext();
        var service = CreateService(ctx);
        var requested = await service.RequestAsync(NewRequest(), null, null);

        var result = await service.ConfirmAsync(requested.RequestId, "000000", null, null);

        Assert.Null(result);
        Assert.Equal(0, await ctx.Tenants.IgnoreQueryFilters().CountAsync());
        var pending = await ctx.TenantProvisioningRequests.SingleAsync(r => r.Id == requested.RequestId);
        Assert.Equal(1, pending.AttemptCount);
    }

    [Fact]
    public async Task ConfirmAsync_for_an_expired_request_returns_null_even_with_the_correct_code()
    {
        using var ctx = CreateContext();
        string code = "123456";
        var pending = new TenantProvisioningRequest(
            Guid.NewGuid(), "Acme", "acme", "admin@acme.test", RandomAuthHash(), Dek, Salt, 65536, 3, 1,
            "Mario Rossi", isBusiness: false, "Via Roma 1", "Milano", "20100", "MI", "IT",
            OneTimeCodeHasher.Hash(code),
            expiresAt: DateTimeOffset.UtcNow.AddDays(-1),
            maxAttempts: 5,
            createdAt: DateTimeOffset.UtcNow.AddDays(-2));
        ctx.TenantProvisioningRequests.Add(pending);
        await ctx.SaveChangesAsync();

        var service = CreateService(ctx);
        var result = await service.ConfirmAsync(pending.Id, code, null, null);

        Assert.Null(result);
    }

    [Fact]
    public async Task ConfirmAsync_for_an_unknown_request_id_returns_null()
    {
        using var ctx = CreateContext();
        var service = CreateService(ctx);

        var result = await service.ConfirmAsync(Guid.NewGuid(), "123456", null, null);

        Assert.Null(result);
    }

    [Fact]
    public async Task ConfirmAsync_returns_null_once_attempts_are_exhausted_even_with_the_correct_code()
    {
        using var ctx = CreateContext();
        var service = CreateService(ctx);
        var requested = await service.RequestAsync(NewRequest(), null, null);
        string code = ExtractCode(_emailSender.LastBody!);

        for (int i = 0; i < 5; i++)
        {
            await service.ConfirmAsync(requested.RequestId, "000000", null, null);
        }

        var result = await service.ConfirmAsync(requested.RequestId, code, null, null);

        Assert.Null(result);
    }

    [Fact]
    public async Task PurgeExpiredAsync_removes_only_expired_requests()
    {
        using var ctx = CreateContext();
        var service = CreateService(ctx);
        var fresh = await service.RequestAsync(NewRequest(), null, null);

        var expired = new TenantProvisioningRequest(
            Guid.NewGuid(), "Beta", "beta", "admin@beta.test", RandomAuthHash(), Dek, Salt, 65536, 3, 1,
            "Beta Srl", isBusiness: true, "Via Milano 2", "Roma", "00100", "RM", "IT",
            OneTimeCodeHasher.Hash("654321"),
            expiresAt: DateTimeOffset.UtcNow.AddDays(-1),
            maxAttempts: 5,
            createdAt: DateTimeOffset.UtcNow.AddDays(-2));
        ctx.TenantProvisioningRequests.Add(expired);
        await ctx.SaveChangesAsync();

        int purged = await service.PurgeExpiredAsync();

        Assert.Equal(1, purged);
        Assert.Equal(1, await ctx.TenantProvisioningRequests.CountAsync());
        Assert.Equal(fresh.RequestId, (await ctx.TenantProvisioningRequests.SingleAsync()).Id);
    }

    // ---- Helpers ------------------------------------------------------------------------------

    private CffVaultManagerDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<CffVaultManagerDbContext>()
            .UseSqlite(_connection)
            .Options;
        return new CffVaultManagerDbContext(options, new TenantContext());
    }

    private TenantProvisioningRequestService CreateService(CffVaultManagerDbContext ctx) =>
        new(ctx, _emailSender, new ProvisionTenantService(ctx, _authHashHasher));

    private static RequestTenantProvisioningRequest NewRequest() => new(
        TenantName: "Acme",
        TenantSlug: "acme",
        AdminEmail: "admin@acme.test",
        AuthHash: RandomAuthHash(),
        EncryptedDek: Dek,
        MasterPasswordSalt: Salt,
        KdfMemoryKb: 65536,
        KdfIterations: 3,
        KdfVersion: 1,
        LegalName: "Mario Rossi",
        IsBusiness: false,
        AddressLine: "Via Roma 1",
        City: "Milano",
        PostalCode: "20100",
        Province: "MI",
        Country: "IT");

    private static byte[] RandomAuthHash() => RandomNumberGenerator.GetBytes(32);

    private static string ExtractCode(string body) => Regex.Match(body, @"\d{6}").Value;

    private sealed class FakeEmailSender : IEmailSender
    {
        public string? LastToEmail;
        public string? LastBody;
        public int SendCount;

        public Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
        {
            LastToEmail = toEmail;
            LastBody = body;
            SendCount++;
            return Task.CompletedTask;
        }
    }
}
