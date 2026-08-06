using System.Runtime.CompilerServices;

namespace CffVaultManager.Domain;

/// <summary>
/// Small internal guard helpers used by domain entity constructors to reject
/// obviously invalid state. Not a general-purpose validation framework:
/// business rules live in the Application layer.
/// </summary>
internal static class Guard
{
    public static Guid AgainstEmptyGuid(Guid value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Value must not be an empty GUID.", paramName);
        }

        return value;
    }

    /// <summary>Same as <see cref="AgainstEmptyGuid(Guid, string?)"/>, but a null value passes through unchanged (a WebAuthn ceremony with no identified user yet — see <c>WebAuthnCeremonyPurpose.PasskeyLogin</c>).</summary>
    public static Guid? AgainstEmptyGuid(Guid? value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        if (value is { } notNull)
        {
            AgainstEmptyGuid(notNull, paramName);
        }

        return value;
    }

    public static string AgainstNullOrWhiteSpace(string? value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value must not be null, empty or whitespace.", paramName);
        }

        return value;
    }

    public static byte[] AgainstNullOrEmpty(byte[]? value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        if (value is null || value.Length == 0)
        {
            throw new ArgumentException("Byte array must not be null or empty.", paramName);
        }

        return value;
    }
}
