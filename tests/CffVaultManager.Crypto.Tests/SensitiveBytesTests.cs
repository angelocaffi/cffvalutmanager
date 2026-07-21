using CffVaultManager.Crypto;

namespace CffVaultManager.Crypto.Tests;

public class SensitiveBytesTests
{
    [Fact]
    public void Dispose_ZeroesUnderlyingBuffer()
    {
        byte[] buffer = [1, 2, 3, 4, 5, 6, 7, 8];
        var sensitive = new SensitiveBytes(buffer);

        sensitive.Dispose();

        Assert.All(buffer, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Span_AfterDispose_Throws()
    {
        var sensitive = new SensitiveBytes(8);
        sensitive.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
        {
            _ = sensitive.Span.Length;
        });
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var sensitive = new SensitiveBytes(8);
        sensitive.Dispose();
        sensitive.Dispose();
    }
}
