namespace CffVaultManager.Domain;

/// <summary>
/// PostgreSQL (unlike SQL Server's default collation) compares strings case-sensitively, so
/// <see cref="Entities.User.Email"/> and <see cref="Entities.Tenant.Slug"/> uniqueness/lookup
/// would otherwise silently start allowing case-variant duplicates (e.g. "Alice@x.com" and
/// "alice@x.com" as two distinct accounts) after the SQL Server -> PostgreSQL migration — see
/// docs/data-model.md. Normalizing to lowercase at every write and comparison keeps behavior
/// identical regardless of the underlying database provider.
/// </summary>
public static class IdentifierNormalization
{
    // Nullable input, never throws: a malformed/missing field on a public unauthenticated endpoint
    // (e.g. POST /api/auth/prelogin with no Email) must fall through as "no match", not crash with
    // a NullReferenceException from inside an EF Core LINQ predicate (see docs/pentest-report-
    // 2026-08-20.md, finding #3) — null normalizes to "", which matches no real Email/Slug.
    public static string NormalizeEmail(string? email) => email?.Trim().ToLowerInvariant() ?? string.Empty;

    public static string NormalizeSlug(string? slug) => slug?.Trim().ToLowerInvariant() ?? string.Empty;
}
