using System.Reflection;
using System.Security.Cryptography;
using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

/// <summary>
/// Generates passwords and passphrases using <see cref="RandomNumberGenerator"/> exclusively —
/// never <see cref="Random"/> — per docs/features/password-manager.md. Runs entirely client-side
/// (this assembly is referenced by the Blazor WASM client); nothing here ever touches the server.
/// </summary>
public sealed class PasswordGeneratorService : IPasswordGeneratorService
{
    private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    private const string DigitChars = "0123456789";
    private const string SymbolChars = "!@#$%^&*()-_=+[]{}<>?/";

    // Characters that are easily confused with one another in common fonts: zero/O, one/l/I.
    private const string AmbiguousChars = "0O1lI";

    private const int MaxGenerationAttempts = 1000;

    private static readonly string[] WordList = LoadWordList();

    public string GeneratePassword(PasswordGeneratorOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var categories = new List<string>(4);
        if (options.IncludeUppercase) categories.Add(Filter(UppercaseChars, options.ExcludeAmbiguousCharacters));
        if (options.IncludeLowercase) categories.Add(Filter(LowercaseChars, options.ExcludeAmbiguousCharacters));
        if (options.IncludeDigits) categories.Add(Filter(DigitChars, options.ExcludeAmbiguousCharacters));
        if (options.IncludeSymbols) categories.Add(SymbolChars);

        if (categories.Count == 0)
        {
            throw new ArgumentException("At least one character set must be enabled.", nameof(options));
        }

        if (options.Length < categories.Count)
        {
            throw new ArgumentException(
                $"Length ({options.Length}) must be at least {categories.Count} to fit one character from each selected set.",
                nameof(options));
        }

        string alphabet = string.Concat(categories);

        // Every position is drawn uniformly from the combined alphabet (no fixed "must-include"
        // slots, which would leak structure); category coverage is enforced by rejection
        // sampling instead, regenerating the whole string until all categories appear.
        for (int attempt = 0; attempt < MaxGenerationAttempts; attempt++)
        {
            char[] candidate = new char[options.Length];
            for (int i = 0; i < candidate.Length; i++)
            {
                candidate[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
            }

            if (categories.All(category => candidate.Any(category.Contains)))
            {
                return new string(candidate);
            }
        }

        throw new InvalidOperationException("Failed to generate a password satisfying all character-set requirements.");
    }

    public string GeneratePassphrase(PassphraseGeneratorOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.WordCount < 1)
        {
            throw new ArgumentException("WordCount must be at least 1.", nameof(options));
        }

        var words = new string[options.WordCount];
        for (int i = 0; i < words.Length; i++)
        {
            string word = WordList[RandomNumberGenerator.GetInt32(WordList.Length)];
            words[i] = options.Capitalize ? Capitalize(word) : word;
        }

        string passphrase = string.Join(options.Separator, words);

        if (options.IncludeNumber)
        {
            passphrase += options.Separator + RandomNumberGenerator.GetInt32(100).ToString("D2");
        }

        return passphrase;
    }

    private static string Filter(string source, bool excludeAmbiguous) =>
        excludeAmbiguous ? new string(source.Where(c => !AmbiguousChars.Contains(c)).ToArray()) : source;

    private static string Capitalize(string word) =>
        $"{char.ToUpperInvariant(word[0])}{word[1..]}";

    private static string[] LoadWordList()
    {
        var assembly = typeof(PasswordGeneratorService).Assembly;
        const string resourceName = "CffVaultManager.Crypto.PassphraseWordList.txt";
        using Stream stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Embedded resource '{resourceName}' not found.");
        using var reader = new StreamReader(stream);

        var words = new List<string>();
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                words.Add(line.Trim());
            }
        }

        return words.ToArray();
    }
}
