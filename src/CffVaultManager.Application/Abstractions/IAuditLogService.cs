using CffVaultManager.Application.Dtos.Audit;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Reads the tenant's audit trail. Visibility follows docs/features/roles-permissions.md: an
/// Admin sees every entry in the tenant, an Operator sees only entries for their own actions.
/// </summary>
public interface IAuditLogService
{
    Task<IReadOnlyList<AuditLogEntryDto>> ListAsync(
        Guid callerId, UserRole callerRole, AuditLogQuery query, CancellationToken ct = default);
}
