using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Invites a new user into an existing tenant (see docs/features/roles-permissions.md "Invito di
/// nuovi utenti"). Deliberately separate from <see cref="IUserRegistrationService"/>: that service
/// assumes the caller already holds the new user's crypto material in the same request, which only
/// works when the Admin and the new user are the same synchronous call — never true in practice.
/// This service instead splits invite (Admin, email + role only) from accept (public, token-driven,
/// crypto material supplied by the invitee themselves once they choose their own master password).
/// </summary>
public interface IUserInvitationService
{
    /// <summary>
    /// Creates a pending invitation and emails a link to <paramref name="email"/>. Throws
    /// <see cref="InvalidOperationException"/> if that email already belongs to a user anywhere
    /// (emails are globally unique — see <c>UserConfiguration</c>).
    /// </summary>
    Task<UserInvitationDto> InviteAsync(string email, UserRole role, Guid callerId, Guid callerTenantId, CancellationToken ct = default);

    /// <summary>Pending (not expired/revoked) invitations for the caller's own tenant.</summary>
    Task<IReadOnlyList<UserInvitationDto>> ListPendingAsync(Guid callerTenantId, CancellationToken ct = default);

    /// <summary>Existing users of the caller's own tenant.</summary>
    Task<IReadOnlyList<TenantUserSummaryDto>> ListTenantUsersAsync(Guid callerTenantId, CancellationToken ct = default);

    /// <summary>Throws <see cref="KeyNotFoundException"/> if the invitation doesn't exist or belongs to another tenant.</summary>
    Task RevokeAsync(Guid invitationId, Guid callerTenantId, CancellationToken ct = default);

    /// <summary>Null for an unknown/expired/revoked token — callers must not distinguish the three cases (anti-enumeration).</summary>
    Task<InvitationPreviewDto?> GetPreviewAsync(string token, CancellationToken ct = default);

    /// <summary>
    /// Creates the real <c>User</c> (+ personal <c>Vault</c>) from a valid, unexpired, unrevoked
    /// invitation and consumes it. Returns null on any invalid state (unknown/expired/revoked
    /// token, or the email was claimed by someone else in the meantime) — same anti-enumeration
    /// discipline as <see cref="GetPreviewAsync"/>.
    /// </summary>
    Task<Guid?> AcceptAsync(
        string token,
        byte[] authHash,
        byte[] encryptedDek,
        byte[] masterPasswordSalt,
        int kdfMemoryKb,
        int kdfIterations,
        int kdfVersion,
        CancellationToken ct = default);

    /// <summary>Removes invitations past <c>ExpiresAt</c> that were never accepted (accepted ones are removed immediately by <see cref="AcceptAsync"/>). Returns the count removed.</summary>
    Task<int> PurgeExpiredAsync(CancellationToken ct = default);
}
