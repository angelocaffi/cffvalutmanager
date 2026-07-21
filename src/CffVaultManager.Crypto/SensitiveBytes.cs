using System.Security.Cryptography;

namespace CffVaultManager.Crypto;

/// <summary>
/// Owns a byte buffer holding secret material and zeroes it on <see cref="Dispose"/>
/// so key bytes do not linger in managed memory longer than necessary.
/// </summary>
public sealed class SensitiveBytes : IDisposable
{
    private readonly byte[] _buffer;
    private bool _disposed;

    public SensitiveBytes(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        _buffer = buffer;
    }

    public SensitiveBytes(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        _buffer = new byte[length];
    }

    public int Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer.Length;
        }
    }

    public Span<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    public ReadOnlySpan<byte> ReadOnlySpan
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_buffer);
        _disposed = true;
    }
}
