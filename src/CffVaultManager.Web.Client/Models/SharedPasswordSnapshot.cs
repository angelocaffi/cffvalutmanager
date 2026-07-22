namespace CffVaultManager.Web.Client.Models;

/// <summary>
/// The minimal, read-only content exposed through an external share link (see
/// docs/features/sharing-access-control.md "Link di condivisione esterna") — deliberately narrower
/// than <see cref="PasswordFormModel"/> (no password history, no notes) since this is meant for a
/// one-off external hand-off, not a full vault entry. Serialized, then encrypted with a one-off key
/// that never reaches the server; produced by <c>Shared/PasswordFields.razor</c> and consumed by
/// <c>Pages/SharedItemView.razor</c>.
/// </summary>
public sealed record SharedPasswordSnapshot(string Title, string? Username, string Password, string? Url);
