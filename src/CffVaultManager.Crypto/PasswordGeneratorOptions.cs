namespace CffVaultManager.Crypto;

/// <summary>
/// Configuration for <see cref="Abstractions.IPasswordGeneratorService.GeneratePassword"/>. At
/// least one character-set flag must be <c>true</c>.
/// </summary>
public sealed record PasswordGeneratorOptions(
    int Length = 16,
    bool IncludeUppercase = true,
    bool IncludeLowercase = true,
    bool IncludeDigits = true,
    bool IncludeSymbols = true,
    bool ExcludeAmbiguousCharacters = false);
