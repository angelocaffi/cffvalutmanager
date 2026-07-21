using System.Security.Cryptography;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// The single source of truth for "is the vault unlocked right now" for this browser tab.
/// Everything here lives in memory only — a hard page reload (not SPA navigation) always drops
/// it, requiring a fresh login. The unwrapped DEK in particular must never be persisted (not to
/// localStorage/sessionStorage, not anywhere): that is the whole point of the zero-knowledge
/// design in docs/security-model.md.
/// </summary>
public sealed class SessionState
{
    private byte[]? _dek;

    public string? AccessToken { get; private set; }

    public string? RefreshToken { get; private set; }

    public string? Email { get; private set; }

    public Guid? UserId { get; private set; }

    public Guid? TenantId { get; private set; }

    public string? Role { get; private set; }

    /// <summary>True once a session has been established AND the DEK has been unwrapped — both are required to show any vault content.</summary>
    public bool IsUnlocked => AccessToken is not null && _dek is not null;

    /// <summary>Raised whenever the session is established or torn down, so components (in particular the auth state provider) can react.</summary>
    public event Action? Changed;

    public void Establish(string accessToken, string refreshToken, byte[] dek, string email, Guid userId, Guid? tenantId, string role)
    {
        AccessToken = accessToken;
        RefreshToken = refreshToken;
        _dek = dek;
        Email = email;
        UserId = userId;
        TenantId = tenantId;
        Role = role;
        Changed?.Invoke();
    }

    /// <summary>Updates the access/refresh token pair after a silent refresh, without touching the unlocked DEK.</summary>
    public void UpdateTokens(string accessToken, string refreshToken)
    {
        AccessToken = accessToken;
        RefreshToken = refreshToken;
        Changed?.Invoke();
    }

    public byte[] RequireDek() => _dek ?? throw new InvalidOperationException("The vault is locked.");

    /// <summary>Tears down the whole session (logout, or any failure that leaves the session unusable) and zeroes the DEK.</summary>
    public void Clear()
    {
        if (_dek is not null)
        {
            CryptographicOperations.ZeroMemory(_dek);
        }

        _dek = null;
        AccessToken = null;
        RefreshToken = null;
        Email = null;
        UserId = null;
        TenantId = null;
        Role = null;
        Changed?.Invoke();
    }
}
