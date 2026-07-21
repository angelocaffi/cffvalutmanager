using CffVaultManager.Domain;

namespace CffVaultManager.Api.Endpoints;

/// <summary>
/// Shared exception-to-HTTP mapping for the vault-core endpoints: ownership/scope mismatches
/// (<see cref="KeyNotFoundException"/>) become 404, insufficient permission on an accessible vault
/// (<see cref="InsufficientVaultPermissionException"/>) becomes 403, and business-state conflicts
/// (<see cref="InvalidOperationException"/>) become 409 with the message as the error body.
/// </summary>
internal static class VaultCoreEndpointHelpers
{
    public static async Task<IResult> ExecuteAsync(Func<Task<IResult>> action)
    {
        try
        {
            return await action();
        }
        catch (KeyNotFoundException)
        {
            return Results.NotFound();
        }
        catch (InsufficientVaultPermissionException)
        {
            // A custom Bearer scheme (no challenge) is in use, so Results.Forbid() would not behave
            // correctly here — return the status code directly. See BearerTokenAuthenticationHandler.
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
        catch (InvalidOperationException ex)
        {
            return Results.Conflict(new { error = ex.Message });
        }
    }
}
