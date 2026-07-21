namespace CffVaultManager.Web.Client.Models;

/// <summary>
/// Plaintext shapes serialized to JSON and then AES-256-GCM encrypted under the vault's DEK before
/// ever leaving the client (see docs/data-model.md "VaultItem"). The server never sees these types
/// — only the resulting ciphertext bytes.
/// </summary>
public sealed record PasswordPayload(
    string Title,
    string? Username,
    string Password,
    string? Url,
    string? Notes,
    IReadOnlyList<string> PasswordHistory)
{
    public static PasswordPayload Empty { get; } = new(string.Empty, null, string.Empty, null, null, []);
}

// Title isn't in docs/data-model.md's field list for this payload, but every item type needs a
// user-chosen display label distinct from any single field (a user may hold several cards for the
// same cardholder) — same role Title/Label already plays for Password/CryptoWallet.
public sealed record CreditCardPayload(
    string Title,
    string CardholderName,
    string CardNumber,
    int? ExpiryMonth,
    int? ExpiryYear,
    string Cvv,
    string? Brand,
    string? Notes)
{
    public static CreditCardPayload Empty { get; } = new(string.Empty, string.Empty, string.Empty, null, null, string.Empty, null, null);
}

public sealed record CryptoWalletPayload(
    string Label,
    string? Network,
    IReadOnlyList<string> Addresses,
    string? PrivateKey,
    string? Mnemonic,
    string? Notes)
{
    public static CryptoWalletPayload Empty { get; } = new(string.Empty, null, [], null, null, null);
}

public sealed record SecureNotePayload(string Title, string? Content)
{
    public static SecureNotePayload Empty { get; } = new(string.Empty, null);
}

/// <summary>A user-defined key/value pair (API key, SSH key, PIN, etc.) — see docs/features/vault-core.md "Secrets generici", which deliberately has no fixed schema.</summary>
public sealed record GenericSecretField(string Key, string Value);

public sealed record GenericSecretPayload(string Title, IReadOnlyList<GenericSecretField> Fields, string? Notes)
{
    public static GenericSecretPayload Empty { get; } = new(string.Empty, [], null);
}
