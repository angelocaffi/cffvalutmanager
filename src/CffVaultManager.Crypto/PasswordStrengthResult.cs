namespace CffVaultManager.Crypto;

public sealed record PasswordStrengthResult(double EstimatedBitsOfEntropy, PasswordStrengthLevel Level);
