using CffVaultManager.Application.Abstractions;
using Microsoft.AspNetCore.DataProtection;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Server-held protection for the TOTP shared secret, using ASP.NET Core Data Protection.
/// This is a server-side secret (unlike zero-knowledge vault material) because the server must
/// be able to recompute TOTP codes to verify them.
/// </summary>
internal sealed class SecretProtector : ISecretProtector
{
    private readonly IDataProtector _protector;

    public SecretProtector(IDataProtectionProvider provider) =>
        _protector = provider.CreateProtector("CffVaultManager.MfaSecret.v1");

    public byte[] Protect(byte[] plaintext) => _protector.Protect(plaintext);

    public byte[] Unprotect(byte[] protectedData) => _protector.Unprotect(protectedData);
}
