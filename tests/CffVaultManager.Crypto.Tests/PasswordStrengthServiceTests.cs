namespace CffVaultManager.Crypto.Tests;

public class PasswordStrengthServiceTests
{
    private readonly PasswordStrengthService _service = new();

    [Fact]
    public void EstimateStrength_WithNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.EstimateStrength(null!));
    }

    [Fact]
    public void EstimateStrength_WithEmptyPassword_ReturnsZeroBitsAndVeryWeak()
    {
        var result = _service.EstimateStrength("");

        Assert.Equal(0, result.EstimatedBitsOfEntropy);
        Assert.Equal(PasswordStrengthLevel.VeryWeak, result.Level);
    }

    [Theory]
    [InlineData("abc")] // short, single character class
    [InlineData("1234")]
    public void EstimateStrength_WithShortSingleClassPasswords_ReturnsVeryWeak(string password)
    {
        var result = _service.EstimateStrength(password);

        Assert.Equal(PasswordStrengthLevel.VeryWeak, result.Level);
    }

    [Fact]
    public void EstimateStrength_WithLongMixedCasePassword_ReturnsAtLeastFair()
    {
        var result = _service.EstimateStrength("correcthorsebattery");

        Assert.True(result.Level >= PasswordStrengthLevel.Fair);
    }

    [Fact]
    public void EstimateStrength_WithLongPasswordUsingAllCharacterClasses_ReturnsVeryStrong()
    {
        var result = _service.EstimateStrength("Tr0ub4dor&3xtraLongPassphrase!");

        Assert.Equal(PasswordStrengthLevel.VeryStrong, result.Level);
    }

    [Fact]
    public void EstimateStrength_MoreCharacterClasses_YieldsHigherEntropyThanFewer()
    {
        var lowercaseOnly = _service.EstimateStrength("abcdefgh");
        var mixedClasses = _service.EstimateStrength("abcdEFG1");

        Assert.True(mixedClasses.EstimatedBitsOfEntropy > lowercaseOnly.EstimatedBitsOfEntropy);
    }

    [Fact]
    public void EstimateStrength_LongerPassword_YieldsHigherEntropyThanShorterWithSamePool()
    {
        var shorter = _service.EstimateStrength("abcdefgh");
        var longer = _service.EstimateStrength("abcdefghabcdefgh");

        Assert.True(longer.EstimatedBitsOfEntropy > shorter.EstimatedBitsOfEntropy);
    }
}
