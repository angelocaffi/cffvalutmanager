namespace CffVaultManager.Crypto;

/// <summary>
/// Argon2id cost parameters.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="DegreeOfParallelism"/> is always coerced to 1: under Blazor WASM the
/// thread-pool based parallelism Argon2 relies on is not reliable, so the cost target
/// (300-500 ms) must be reached through memory and iterations instead of lanes.
/// The derivation service enforces 1 regardless of the value stored here (defense in depth),
/// and this record refuses to hold any other value.
/// </para>
/// <para>
/// The default cost values below are indicative and MUST be recalibrated with a real
/// benchmark on target hardware to hit the 300-500 ms target.
/// </para>
/// </remarks>
public sealed record Argon2Parameters
{
    public const int EnforcedDegreeOfParallelism = 1;

    public Argon2Parameters(
        int memoryKb = 65536,
        int iterations = 3,
        int degreeOfParallelism = EnforcedDegreeOfParallelism,
        int version = 1)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(memoryKb, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(version, 1);

        MemoryKb = memoryKb;
        Iterations = iterations;
        // Any requested value is ignored; the record only ever exposes the enforced lane count.
        DegreeOfParallelism = EnforcedDegreeOfParallelism;
        Version = version;
    }

    /// <summary>Memory cost in kibibytes. Default 65536 (64 MB) — recalibrate via benchmark.</summary>
    public int MemoryKb { get; init; }

    /// <summary>Number of passes. Default 3 — recalibrate via benchmark.</summary>
    public int Iterations { get; init; }

    /// <summary>Always 1. See remarks on <see cref="Argon2Parameters"/>.</summary>
    public int DegreeOfParallelism { get; init; }

    /// <summary>Parameter-set version, for future migration of cost settings.</summary>
    public int Version { get; init; }

    public static Argon2Parameters Default => new();
}
