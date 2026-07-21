namespace CffVaultManager.Crypto.Tests;

public class PasswordGeneratorServiceTests
{
    private readonly PasswordGeneratorService _generator = new();

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(64)]
    public void GeneratePassword_HasExactRequestedLength(int length)
    {
        string password = _generator.GeneratePassword(new PasswordGeneratorOptions(Length: length));
        Assert.Equal(length, password.Length);
    }

    [Fact]
    public void GeneratePassword_WithAllCategoriesEnabled_ContainsAtLeastOneOfEach()
    {
        string password = _generator.GeneratePassword(new PasswordGeneratorOptions(Length: 32));

        Assert.Contains(password, c => char.IsUpper(c));
        Assert.Contains(password, c => char.IsLower(c));
        Assert.Contains(password, c => char.IsDigit(c));
        Assert.Contains(password, c => !char.IsLetterOrDigit(c));
    }

    [Fact]
    public void GeneratePassword_WithOnlyLowercaseEnabled_UsesOnlyLowercase()
    {
        var options = new PasswordGeneratorOptions(
            Length: 20, IncludeUppercase: false, IncludeLowercase: true, IncludeDigits: false, IncludeSymbols: false);

        string password = _generator.GeneratePassword(options);

        Assert.All(password, c => Assert.True(char.IsLower(c)));
    }

    [Fact]
    public void GeneratePassword_WithNoCategoriesEnabled_Throws()
    {
        var options = new PasswordGeneratorOptions(
            IncludeUppercase: false, IncludeLowercase: false, IncludeDigits: false, IncludeSymbols: false);

        Assert.Throws<ArgumentException>(() => _generator.GeneratePassword(options));
    }

    [Fact]
    public void GeneratePassword_WithLengthShorterThanCategoryCount_Throws()
    {
        // 4 categories enabled (the default) but only 2 characters requested.
        var options = new PasswordGeneratorOptions(Length: 2);

        Assert.Throws<ArgumentException>(() => _generator.GeneratePassword(options));
    }

    [Fact]
    public void GeneratePassword_WithExcludeAmbiguous_NeverContainsAmbiguousCharacters()
    {
        var options = new PasswordGeneratorOptions(Length: 40, ExcludeAmbiguousCharacters: true);

        for (int i = 0; i < 50; i++)
        {
            string password = _generator.GeneratePassword(options);
            Assert.DoesNotContain(password, c => "0O1lI".Contains(c));
        }
    }

    [Fact]
    public void GeneratePassword_ProducesDistinctValues()
    {
        var options = new PasswordGeneratorOptions(Length: 24);
        var seen = new HashSet<string>();

        for (int i = 0; i < 100; i++)
        {
            Assert.True(seen.Add(_generator.GeneratePassword(options)), "GeneratePassword produced a duplicate value.");
        }
    }

    [Fact]
    public void GeneratePassphrase_HasRequestedWordCountAndSeparator()
    {
        var options = new PassphraseGeneratorOptions(WordCount: 4, Separator: "-", IncludeNumber: false);

        string passphrase = _generator.GeneratePassphrase(options);

        Assert.Equal(4, passphrase.Split('-').Length);
    }

    [Fact]
    public void GeneratePassphrase_WithIncludeNumber_AppendsTwoDigitNumberAsExtraSegment()
    {
        var options = new PassphraseGeneratorOptions(WordCount: 3, Separator: "-", IncludeNumber: true);

        string passphrase = _generator.GeneratePassphrase(options);
        var segments = passphrase.Split('-');

        Assert.Equal(4, segments.Length);
        Assert.Matches("^[0-9]{2}$", segments[^1]);
    }

    [Fact]
    public void GeneratePassphrase_WithCapitalize_CapitalizesEachWord()
    {
        var options = new PassphraseGeneratorOptions(WordCount: 5, Capitalize: true, IncludeNumber: false);

        string passphrase = _generator.GeneratePassphrase(options);

        Assert.All(passphrase.Split('-'), word => Assert.True(char.IsUpper(word[0])));
    }

    [Fact]
    public void GeneratePassphrase_WithCustomSeparator_UsesIt()
    {
        var options = new PassphraseGeneratorOptions(WordCount: 3, Separator: " ", IncludeNumber: false);

        string passphrase = _generator.GeneratePassphrase(options);

        Assert.Equal(3, passphrase.Split(' ').Length);
        Assert.DoesNotContain('-', passphrase);
    }

    [Fact]
    public void GeneratePassphrase_WithZeroWordCount_Throws()
    {
        Assert.Throws<ArgumentException>(() => _generator.GeneratePassphrase(new PassphraseGeneratorOptions(WordCount: 0)));
    }

    [Fact]
    public void GeneratePassphrase_ProducesDistinctValues()
    {
        var options = new PassphraseGeneratorOptions(WordCount: 6);
        var seen = new HashSet<string>();

        for (int i = 0; i < 100; i++)
        {
            Assert.True(seen.Add(_generator.GeneratePassphrase(options)), "GeneratePassphrase produced a duplicate value.");
        }
    }
}
