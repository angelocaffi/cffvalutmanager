using System.Security.Cryptography;

namespace CffVaultManager.Crypto;

/// <summary>
/// Result of a key-derivation operation (a 32-byte KEK). Wraps the key material and
/// zeroes it on <see cref="Dispose"/> to keep it out of memory once the KEK is no longer needed.
/// </summary>
public sealed class DerivedKey : IDisposable
{
    private readonly byte[] _key;
    private bool _disposed;

    public DerivedKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
    }

    public ReadOnlySpan<byte> Key
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key;
        }
    }

    public int Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key.Length;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_key);
        _disposed = true;
    }
}
