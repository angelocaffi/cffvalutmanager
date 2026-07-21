namespace CffVaultManager.Domain;

/// <summary>
/// Thrown when a caller has access to a vault but lacks the permission required for the requested
/// operation (e.g. a Read member attempting a write). Distinct from "not found": the caller is a
/// legitimate member, so this maps to 403 Forbidden rather than 404.
/// </summary>
public sealed class InsufficientVaultPermissionException : Exception
{
    public InsufficientVaultPermissionException()
        : base("The caller does not have sufficient permission on this vault.")
    {
    }

    public InsufficientVaultPermissionException(string message)
        : base(message)
    {
    }
}
