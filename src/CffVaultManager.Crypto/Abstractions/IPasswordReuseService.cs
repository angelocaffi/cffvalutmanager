namespace CffVaultManager.Crypto.Abstractions;

/// <summary>
/// Client-side password reuse detection (see docs/features/password-health.md). The client already
/// holds every decrypted password to render the vault; this just groups them by identical value.
/// Nothing here ever touches the server.
/// </summary>
public interface IPasswordReuseService
{
    /// <summary>
    /// Groups vault item IDs that share the exact same (decrypted) password. Only groups with more
    /// than one member represent actual reuse — a password held by only one item is never
    /// returned.
    /// </summary>
    IReadOnlyList<IReadOnlyList<Guid>> FindReusedGroups(IReadOnlyDictionary<Guid, string> passwordsByItemId);
}
