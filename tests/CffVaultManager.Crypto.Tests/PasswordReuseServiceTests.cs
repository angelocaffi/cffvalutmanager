namespace CffVaultManager.Crypto.Tests;

public class PasswordReuseServiceTests
{
    private readonly PasswordReuseService _service = new();

    [Fact]
    public void FindReusedGroups_WithNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.FindReusedGroups(null!));
    }

    [Fact]
    public void FindReusedGroups_WithNoDuplicates_ReturnsEmpty()
    {
        var passwords = new Dictionary<Guid, string>
        {
            [Guid.NewGuid()] = "alpha",
            [Guid.NewGuid()] = "beta",
            [Guid.NewGuid()] = "gamma",
        };

        var result = _service.FindReusedGroups(passwords);

        Assert.Empty(result);
    }

    [Fact]
    public void FindReusedGroups_WithASharedPassword_GroupsTheMatchingItems()
    {
        var sharedId1 = Guid.NewGuid();
        var sharedId2 = Guid.NewGuid();
        var uniqueId = Guid.NewGuid();
        var passwords = new Dictionary<Guid, string>
        {
            [sharedId1] = "hunter2",
            [sharedId2] = "hunter2",
            [uniqueId] = "different",
        };

        var result = _service.FindReusedGroups(passwords);

        var group = Assert.Single(result);
        Assert.Equal(new HashSet<Guid> { sharedId1, sharedId2 }, group.ToHashSet());
    }

    [Fact]
    public void FindReusedGroups_IsCaseSensitive()
    {
        var passwords = new Dictionary<Guid, string>
        {
            [Guid.NewGuid()] = "Password1",
            [Guid.NewGuid()] = "password1",
        };

        var result = _service.FindReusedGroups(passwords);

        Assert.Empty(result);
    }

    [Fact]
    public void FindReusedGroups_WithMultipleDistinctReusedGroups_ReturnsAllOfThem()
    {
        var passwords = new Dictionary<Guid, string>
        {
            [Guid.NewGuid()] = "alpha",
            [Guid.NewGuid()] = "alpha",
            [Guid.NewGuid()] = "beta",
            [Guid.NewGuid()] = "beta",
            [Guid.NewGuid()] = "unique",
        };

        var result = _service.FindReusedGroups(passwords);

        Assert.Equal(2, result.Count);
        Assert.All(result, group => Assert.Equal(2, group.Count));
    }

    [Fact]
    public void FindReusedGroups_WithEmptyInput_ReturnsEmpty()
    {
        var result = _service.FindReusedGroups(new Dictionary<Guid, string>());

        Assert.Empty(result);
    }
}
