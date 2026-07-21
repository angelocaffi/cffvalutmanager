using System.Net;

namespace CffVaultManager.Crypto.Tests;

public class HibpBreachCheckServiceTests
{
    // SHA1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 (well-known, verified independently).
    private const string PasswordShaPrefix = "5BAA6";
    private const string PasswordShaSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    [Fact]
    public async Task CheckPasswordAsync_WithNull_Throws()
    {
        var service = new HibpBreachCheckService(new HttpClient(new FakeHttpMessageHandler("")));

        await Assert.ThrowsAsync<ArgumentNullException>(() => service.CheckPasswordAsync(null!));
    }

    [Fact]
    public async Task CheckPasswordAsync_OnlySendsTheHashPrefix_NeverThePasswordOrFullHash()
    {
        var handler = new FakeHttpMessageHandler($"{PasswordShaSuffix}:3730471");
        var service = new HibpBreachCheckService(new HttpClient(handler));

        await service.CheckPasswordAsync("password");

        Assert.NotNull(handler.LastRequest);
        string requestUri = handler.LastRequest!.RequestUri!.ToString();
        Assert.Equal($"https://api.pwnedpasswords.com/range/{PasswordShaPrefix}", requestUri);
    }

    [Fact]
    public async Task CheckPasswordAsync_RequestsPaddingForPrivacy()
    {
        var handler = new FakeHttpMessageHandler($"{PasswordShaSuffix}:1");
        var service = new HibpBreachCheckService(new HttpClient(handler));

        await service.CheckPasswordAsync("password");

        Assert.True(handler.LastRequest!.Headers.TryGetValues("Add-Padding", out var values));
        Assert.Equal("true", values!.Single());
    }

    [Fact]
    public async Task CheckPasswordAsync_WhenTheSuffixMatches_ReturnsTheReportedCount()
    {
        string body = $"AAAA1111111111111111111111111111111:5\n{PasswordShaSuffix}:3730471\nBBBB2222222222222222222222222222222:9";
        var service = new HibpBreachCheckService(new HttpClient(new FakeHttpMessageHandler(body)));

        long count = await service.CheckPasswordAsync("password");

        Assert.Equal(3730471, count);
    }

    [Fact]
    public async Task CheckPasswordAsync_SuffixComparisonIsCaseInsensitive()
    {
        string body = $"{PasswordShaSuffix.ToLowerInvariant()}:42";
        var service = new HibpBreachCheckService(new HttpClient(new FakeHttpMessageHandler(body)));

        long count = await service.CheckPasswordAsync("password");

        Assert.Equal(42, count);
    }

    [Fact]
    public async Task CheckPasswordAsync_WhenNoSuffixMatches_ReturnsZero()
    {
        string body = "AAAA1111111111111111111111111111111:5\nBBBB2222222222222222222222222222222:9";
        var service = new HibpBreachCheckService(new HttpClient(new FakeHttpMessageHandler(body)));

        long count = await service.CheckPasswordAsync("a-password-that-was-never-breached");

        Assert.Equal(0, count);
    }

    [Fact]
    public async Task CheckPasswordAsync_OnHttpFailure_Throws()
    {
        var service = new HibpBreachCheckService(new HttpClient(new FakeHttpMessageHandler("", HttpStatusCode.InternalServerError)));

        await Assert.ThrowsAsync<HttpRequestException>(() => service.CheckPasswordAsync("password"));
    }
}
