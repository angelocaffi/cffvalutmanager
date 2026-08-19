// One-shot production data migration: SQL Server -> PostgreSQL (see docs/data-model.md,
// "Motore database: SQL Server -> PostgreSQL"). Deliberately plain ADO.NET, no EF Core on either
// side: the table order below mirrors the FK-safe CreateTable order EF Core itself generated in
// Persistence/Migrations/*_InitialPostgresSchema.cs, so it does not need to be re-derived from the
// FK graph. Column names/order for each table are read live from the *target* Postgres schema
// (information_schema), not hand-transcribed, so this tool can't silently drift from whatever the
// EF model actually produced.
//
// Usage:
//   dotnet run -- "<source SQL Server connection string>" "<target Postgres connection string>"
//
// Safe to re-run against an empty target: everything happens inside one transaction, so a failure
// partway through leaves nothing committed. Not safe to run twice against the same *non-empty*
// target (primary keys/unique indexes will reject the second pass, exactly as intended).

using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;
using Npgsql;
using NpgsqlTypes;

if (args.Length != 2)
{
    Console.Error.WriteLine("Usage: dotnet run -- \"<SQL Server connection string>\" \"<Postgres connection string>\"");
    return 1;
}

string sourceConnectionString = args[0];
string targetConnectionString = args[1];

// FK-safe order, copied from the CreateTable call order in
// src/CffVaultManager.Infrastructure/Persistence/Migrations/*_InitialPostgresSchema.cs (EF Core's
// own topological sort of the model's foreign keys) — every table's dependencies are copied before
// the table itself.
string[] tablesInOrder =
[
    "TenantProvisioningRequests",
    "Tenants",
    "TenantBillingProfiles",
    "Users",
    "BillingPricing",
    "Notifications",
    "OneTimeCodes",
    "PaymentTransactions",
    "RefreshTokens",
    "UserInvitations",
    "Vaults",
    "WebAuthnCeremonies",
    "WebAuthnCredentials",
    "Folders",
    "Tags",
    "VaultMemberships",
    "VaultItems",
    "AuditLogEntries",
    "ExternalShareLinks",
    "ItemMemberships",
    "VaultItemTags",
];

// The only two columns needing the lowercase normalization backfill (see
// CffVaultManager.Domain.IdentifierNormalization / docs/data-model.md "Case-sensitivity").
var columnsToLowercase = new Dictionary<string, string>
{
    ["Users"] = "Email",
    ["Tenants"] = "Slug",
};

await using var source = new SqlConnection(sourceConnectionString);
await source.OpenAsync();

await using var target = new NpgsqlConnection(targetConnectionString);
await target.OpenAsync();

Console.WriteLine("Pre-flight: checking for case-variant duplicate Email/Slug values already present in the source database...");
if (!await PreflightCheckAsync(source))
{
    Console.Error.WriteLine("Aborting: resolve the duplicates above manually, then re-run.");
    return 1;
}

var stopwatch = System.Diagnostics.Stopwatch.StartNew();
await using var transaction = await target.BeginTransactionAsync();

var rowCounts = new Dictionary<string, long>();
try
{
    foreach (string table in tablesInOrder)
    {
        string[] columns = await GetTargetColumnsAsync(target, table);
        columnsToLowercase.TryGetValue(table, out string? lowercaseColumn);

        long copied = await CopyTableAsync(source, target, table, columns, lowercaseColumn);
        rowCounts[table] = copied;
        Console.WriteLine($"  {table}: {copied} righe copiate");
    }

    await transaction.CommitAsync();
}
catch
{
    await transaction.RollbackAsync();
    throw;
}

stopwatch.Stop();
Console.WriteLine($"Copia completata in {stopwatch.Elapsed.TotalSeconds:0.0}s.");

Console.WriteLine("Verifica: confronto conteggio righe e hash degli Id tra sorgente e destinazione...");
bool verified = await VerifyAsync(source, target, tablesInOrder, rowCounts);
if (!verified)
{
    Console.Error.WriteLine("VERIFICA FALLITA — controllare i dettagli sopra prima di considerare la migrazione riuscita.");
    return 1;
}

Console.WriteLine("Verifica riuscita: conteggio righe e hash degli Id coincidono per tutte le tabelle.");
return 0;

// ---- Helpers --------------------------------------------------------------------------------

static async Task<bool> PreflightCheckAsync(SqlConnection source)
{
    bool ok = true;

    await using (var cmd = new SqlCommand(
        "SELECT LOWER(Email) AS NormalizedEmail, COUNT(*) AS Cnt FROM Users GROUP BY LOWER(Email) HAVING COUNT(*) > 1",
        source))
    await using (var reader = await cmd.ExecuteReaderAsync())
    {
        while (await reader.ReadAsync())
        {
            ok = false;
            Console.Error.WriteLine($"  Duplicato case-variant su Users.Email dopo normalizzazione: '{reader.GetString(0)}' ({reader.GetInt32(1)} righe)");
        }
    }

    await using (var cmd = new SqlCommand(
        "SELECT LOWER(Slug) AS NormalizedSlug, COUNT(*) AS Cnt FROM Tenants GROUP BY LOWER(Slug) HAVING COUNT(*) > 1",
        source))
    await using (var reader = await cmd.ExecuteReaderAsync())
    {
        while (await reader.ReadAsync())
        {
            ok = false;
            Console.Error.WriteLine($"  Duplicato case-variant su Tenants.Slug dopo normalizzazione: '{reader.GetString(0)}' ({reader.GetInt32(1)} righe)");
        }
    }

    return ok;
}

static async Task<string[]> GetTargetColumnsAsync(NpgsqlConnection target, string table)
{
    var columns = new List<string>();
    await using var cmd = new NpgsqlCommand(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = @table ORDER BY ordinal_position",
        target);
    cmd.Parameters.AddWithValue("table", table);
    await using var reader = await cmd.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        columns.Add(reader.GetString(0));
    }

    return [.. columns];
}

static async Task<long> CopyTableAsync(SqlConnection source, NpgsqlConnection target, string table, string[] columns, string? lowercaseColumn)
{
    string columnList = string.Join(", ", columns.Select(c => $"[{c}]"));
    await using var selectCmd = new SqlCommand($"SELECT {columnList} FROM [{table}]", source);
    await using var reader = await selectCmd.ExecuteReaderAsync();

    string pgColumnList = string.Join(", ", columns.Select(c => $"\"{c}\""));
    await using var importer = await target.BeginBinaryImportAsync(
        $"COPY \"{table}\" ({pgColumnList}) FROM STDIN (FORMAT BINARY)");

    long rowCount = 0;
    while (await reader.ReadAsync())
    {
        await importer.StartRowAsync();
        for (int i = 0; i < columns.Length; i++)
        {
            object value = reader.GetValue(i);
            if (value is DBNull)
            {
                await importer.WriteNullAsync();
                continue;
            }

            if (columns[i] == lowercaseColumn && value is string s)
            {
                value = s.Trim().ToLowerInvariant();
            }

            await WriteTypedAsync(importer, value);
        }

        rowCount++;
    }

    await importer.CompleteAsync();
    return rowCount;
}

static async Task WriteTypedAsync(NpgsqlBinaryImporter importer, object value)
{
    switch (value)
    {
        case Guid g: await importer.WriteAsync(g, NpgsqlDbType.Uuid); break;
        case string s: await importer.WriteAsync(s, NpgsqlDbType.Text); break;
        case byte[] b: await importer.WriteAsync(b, NpgsqlDbType.Bytea); break;
        case bool bo: await importer.WriteAsync(bo, NpgsqlDbType.Boolean); break;
        case int i32: await importer.WriteAsync(i32, NpgsqlDbType.Integer); break;
        case long i64: await importer.WriteAsync(i64, NpgsqlDbType.Bigint); break;
        case decimal d: await importer.WriteAsync(d, NpgsqlDbType.Numeric); break;
        case DateTimeOffset dto: await importer.WriteAsync(dto, NpgsqlDbType.TimestampTz); break;
        case DateTime dt: await importer.WriteAsync(dt, NpgsqlDbType.TimestampTz); break;
        default:
            throw new NotSupportedException($"Tipo non gestito nella copia: {value.GetType()} (valore: {value})");
    }
}

static async Task<bool> VerifyAsync(SqlConnection source, NpgsqlConnection target, string[] tables, Dictionary<string, long> copiedCounts)
{
    bool allOk = true;
    foreach (string table in tables)
    {
        await using var sourceCountCmd = new SqlCommand($"SELECT COUNT(*) FROM [{table}]", source);
        long sourceCount = Convert.ToInt64(await sourceCountCmd.ExecuteScalarAsync());

        await using var targetCountCmd = new NpgsqlCommand($"SELECT COUNT(*) FROM \"{table}\"", target);
        long targetCount = Convert.ToInt64(await targetCountCmd.ExecuteScalarAsync());

        if (sourceCount != targetCount || sourceCount != copiedCounts[table])
        {
            allOk = false;
            Console.Error.WriteLine($"  {table}: sorgente={sourceCount}, destinazione={targetCount}, copiate={copiedCounts[table]} — MISMATCH");
            continue;
        }

        if (table == "VaultItemTags")
        {
            // No single-column PK on the join table; row-count equality above is the check.
            continue;
        }

        await using var sourceIdsCmd = new SqlCommand($"SELECT [Id] FROM [{table}] ORDER BY [Id]", source);
        await using var sourceIdsReader = await sourceIdsCmd.ExecuteReaderAsync();
        string sourceHash = await IdSetHashAsync(sourceIdsReader);

        await using var targetIdsCmd = new NpgsqlCommand($"SELECT \"Id\" FROM \"{table}\" ORDER BY \"Id\"", target);
        await using var targetIdsReader = await targetIdsCmd.ExecuteReaderAsync();
        string targetHash = await IdSetHashAsync(targetIdsReader);

        if (sourceHash != targetHash)
        {
            allOk = false;
            Console.Error.WriteLine($"  {table}: stesso conteggio righe ma hash degli Id diverso — copia non fedele");
        }
    }

    return allOk;
}

static async Task<string> IdSetHashAsync(DbDataReader reader)
{
    var builder = new StringBuilder();
    while (await reader.ReadAsync())
    {
        builder.Append(reader.GetValue(0)).Append(';');
    }

    return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
}
