namespace CffVaultManager.Application.Abstractions;

/// <summary>
/// Symmetric, server-held protection for low-volume secrets such as the TOTP shared secret.
/// Backed by a key the server controls (ASP.NET Core Data Protection); this is deliberately
/// distinct from the zero-knowledge vault material, which the server can never decrypt.
/// </summary>
public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext);

    byte[] Unprotect(byte[] protectedData);
}
