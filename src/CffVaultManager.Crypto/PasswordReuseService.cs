using CffVaultManager.Crypto.Abstractions;

namespace CffVaultManager.Crypto;

/// <summary>See <see cref="IPasswordReuseService"/>.</summary>
public sealed class PasswordReuseService : IPasswordReuseService
{
    public IReadOnlyList<IReadOnlyList<Guid>> FindReusedGroups(IReadOnlyDictionary<Guid, string> passwordsByItemId)
    {
        ArgumentNullException.ThrowIfNull(passwordsByItemId);

        return passwordsByItemId
            .GroupBy(kv => kv.Value, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => (IReadOnlyList<Guid>)group.Select(kv => kv.Key).ToList())
            .ToList();
    }
}
