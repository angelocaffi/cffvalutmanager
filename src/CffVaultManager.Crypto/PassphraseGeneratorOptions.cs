namespace CffVaultManager.Crypto;

/// <summary>
/// Configuration for <see cref="Abstractions.IPasswordGeneratorService.GeneratePassphrase"/>.
/// </summary>
public sealed record PassphraseGeneratorOptions(
    int WordCount = 5,
    string Separator = "-",
    bool Capitalize = false,
    bool IncludeNumber = true);
