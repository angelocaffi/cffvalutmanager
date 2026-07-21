namespace CffVaultManager.Web.Client.Models;

/// <summary>
/// Mutable, two-way-bindable form state for a vault item editor — converted to/from the immutable
/// wire-format <c>*Payload</c> record only at load/save time. Blazor's <c>@bind</c> needs a
/// settable property to write to, which an immutable record's constructor-only properties don't
/// offer.
/// </summary>
public sealed class PasswordFormModel
{
    public string Title { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Notes { get; set; } = string.Empty;
    public List<string> PasswordHistory { get; set; } = [];

    public static PasswordFormModel FromPayload(PasswordPayload payload) => new()
    {
        Title = payload.Title,
        Username = payload.Username ?? string.Empty,
        Password = payload.Password,
        Url = payload.Url ?? string.Empty,
        Notes = payload.Notes ?? string.Empty,
        PasswordHistory = [.. payload.PasswordHistory],
    };

    public PasswordPayload ToPayload() => new(
        Title, NullIfBlank(Username), Password, NullIfBlank(Url), NullIfBlank(Notes), PasswordHistory);

    private static string? NullIfBlank(string value) => string.IsNullOrWhiteSpace(value) ? null : value;
}

public sealed class CreditCardFormModel
{
    public string Title { get; set; } = string.Empty;
    public string CardholderName { get; set; } = string.Empty;
    public string CardNumber { get; set; } = string.Empty;
    public int? ExpiryMonth { get; set; }
    public int? ExpiryYear { get; set; }
    public string Cvv { get; set; } = string.Empty;
    public string? Brand { get; set; }
    public string Notes { get; set; } = string.Empty;

    public static CreditCardFormModel FromPayload(CreditCardPayload payload) => new()
    {
        Title = payload.Title,
        CardholderName = payload.CardholderName,
        CardNumber = payload.CardNumber,
        ExpiryMonth = payload.ExpiryMonth,
        ExpiryYear = payload.ExpiryYear,
        Cvv = payload.Cvv,
        Brand = payload.Brand,
        Notes = payload.Notes ?? string.Empty,
    };

    public CreditCardPayload ToPayload() => new(
        Title, CardholderName, CardNumber, ExpiryMonth, ExpiryYear, Cvv, Brand,
        string.IsNullOrWhiteSpace(Notes) ? null : Notes);
}

public sealed class CryptoWalletFormModel
{
    public string Label { get; set; } = string.Empty;
    public string? Network { get; set; }
    public List<string> Addresses { get; set; } = [string.Empty];
    public string PrivateKey { get; set; } = string.Empty;
    public string Mnemonic { get; set; } = string.Empty;
    public string Notes { get; set; } = string.Empty;

    public static CryptoWalletFormModel FromPayload(CryptoWalletPayload payload) => new()
    {
        Label = payload.Label,
        Network = payload.Network,
        Addresses = payload.Addresses.Count > 0 ? [.. payload.Addresses] : [string.Empty],
        PrivateKey = payload.PrivateKey ?? string.Empty,
        Mnemonic = payload.Mnemonic ?? string.Empty,
        Notes = payload.Notes ?? string.Empty,
    };

    public CryptoWalletPayload ToPayload() => new(
        Label,
        Network,
        [.. Addresses.Where(a => !string.IsNullOrWhiteSpace(a))],
        string.IsNullOrWhiteSpace(PrivateKey) ? null : PrivateKey,
        string.IsNullOrWhiteSpace(Mnemonic) ? null : Mnemonic,
        string.IsNullOrWhiteSpace(Notes) ? null : Notes);
}

public sealed class SecureNoteFormModel
{
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;

    public static SecureNoteFormModel FromPayload(SecureNotePayload payload) => new()
    {
        Title = payload.Title,
        Content = payload.Content ?? string.Empty,
    };

    public SecureNotePayload ToPayload() => new(Title, string.IsNullOrWhiteSpace(Content) ? null : Content);
}

/// <summary>One row of a <see cref="GenericSecretFormModel"/>'s field list — a mutable class so a <c>@for</c>-rendered row can bind directly to it.</summary>
public sealed class KeyValueFieldModel
{
    public string Key { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}

public sealed class GenericSecretFormModel
{
    public string Title { get; set; } = string.Empty;
    public List<KeyValueFieldModel> Fields { get; set; } = [new()];
    public string Notes { get; set; } = string.Empty;

    public static GenericSecretFormModel FromPayload(GenericSecretPayload payload) => new()
    {
        Title = payload.Title,
        Fields = payload.Fields.Count > 0
            ? [.. payload.Fields.Select(f => new KeyValueFieldModel { Key = f.Key, Value = f.Value })]
            : [new()],
        Notes = payload.Notes ?? string.Empty,
    };

    public GenericSecretPayload ToPayload() => new(
        Title,
        [.. Fields.Where(f => !string.IsNullOrWhiteSpace(f.Key)).Select(f => new GenericSecretField(f.Key, f.Value))],
        string.IsNullOrWhiteSpace(Notes) ? null : Notes);
}
