namespace CffVaultManager.Web.Client.Models;

/// <summary>
/// Source password manager recognized from a CSV export's header row (docs/features/import-export.md
/// "Import CSV"). <see cref="Unknown"/> falls back to manual column mapping in the UI rather than
/// rejecting the file outright — covers 1Password (whose CSV schema varies per item category and
/// isn't stable enough to hard-code) and any exporter not explicitly supported.
/// </summary>
public enum CsvVendor
{
    Chrome,
    Bitwarden,
    LastPass,
    Unknown,
}

/// <summary>
/// One CSV data row normalized to the fields <see cref="PasswordFormModel"/> understands. v1 scope
/// is Password-type entries only — the three supported vendors' schemas agree on this shape, while
/// their other item types (secure note, card, identity) don't map cleanly to a single set of fields.
/// </summary>
public sealed record CsvImportRow(string Title, string? Username, string? Password, string? Url, string? Notes, string? Folder);

/// <summary>
/// Minimal hand-rolled RFC 4180 CSV reader (no external dependency exists in this project) plus
/// vendor detection/mapping for Chrome, Bitwarden and LastPass exports. Everything here runs
/// entirely client-side: the uploaded file never reaches the server as plaintext, only the
/// already-AES-256-GCM-encrypted payload built from it (see VaultBackup.razor).
/// </summary>
public static class CsvParser
{
    public static List<string[]> Parse(string text)
    {
        var rows = new List<string[]>();
        var field = new System.Text.StringBuilder();
        var row = new List<string>();
        bool inQuotes = false;
        int i = 0;
        int n = text.Length;

        void EndField()
        {
            row.Add(field.ToString());
            field.Clear();
        }

        void EndRow()
        {
            EndField();
            rows.Add([.. row]);
            row.Clear();
        }

        while (i < n)
        {
            char c = text[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < n && text[i + 1] == '"')
                    {
                        field.Append('"');
                        i += 2;
                        continue;
                    }

                    inQuotes = false;
                    i++;
                    continue;
                }

                field.Append(c);
                i++;
                continue;
            }

            switch (c)
            {
                case '"':
                    inQuotes = true;
                    i++;
                    break;
                case ',':
                    EndField();
                    i++;
                    break;
                case '\r':
                    i++;
                    break;
                case '\n':
                    EndRow();
                    i++;
                    break;
                default:
                    field.Append(c);
                    i++;
                    break;
            }
        }

        if (field.Length > 0 || row.Count > 0)
        {
            EndRow();
        }

        return rows.Where(r => r.Length > 0 && r.Any(v => !string.IsNullOrWhiteSpace(v))).ToList();
    }

    public static CsvVendor Detect(IReadOnlyList<string> header)
    {
        var set = header.Select(h => h.Trim().ToLowerInvariant()).ToHashSet();

        if (set.Contains("login_username") && set.Contains("login_password"))
        {
            return CsvVendor.Bitwarden;
        }

        if (set.Contains("grouping") && set.Contains("fav"))
        {
            return CsvVendor.LastPass;
        }

        if (set.Contains("name") && set.Contains("url") && set.Contains("username") && set.Contains("password"))
        {
            return CsvVendor.Chrome;
        }

        return CsvVendor.Unknown;
    }

    /// <summary>Maps one data row using the known schema for <paramref name="vendor"/>. Null means the row is out of v1 scope (e.g. a non-login Bitwarden item) and should be skipped.</summary>
    public static CsvImportRow? MapRow(CsvVendor vendor, IReadOnlyList<string> header, IReadOnlyList<string> row) => vendor switch
    {
        CsvVendor.Chrome => new CsvImportRow(
            Title: Get(header, row, "name") ?? "(senza titolo)",
            Username: Get(header, row, "username"),
            Password: Get(header, row, "password"),
            Url: Get(header, row, "url"),
            Notes: Get(header, row, "note"),
            Folder: null),

        CsvVendor.Bitwarden => MapBitwarden(header, row),

        CsvVendor.LastPass => new CsvImportRow(
            Title: Get(header, row, "name") ?? "(senza titolo)",
            Username: Get(header, row, "username"),
            Password: Get(header, row, "password"),
            Url: Get(header, row, "url"),
            Notes: WithTotp(Get(header, row, "extra"), Get(header, row, "totp")),
            Folder: Get(header, row, "grouping")),

        _ => null,
    };

    private static CsvImportRow? MapBitwarden(IReadOnlyList<string> header, IReadOnlyList<string> row)
    {
        string? type = Get(header, row, "type");
        if (type is not null && !string.Equals(type, "login", StringComparison.OrdinalIgnoreCase))
        {
            // Out of v1 scope: Bitwarden's secure note/card/identity rows don't map to PasswordFormModel.
            return null;
        }

        return new CsvImportRow(
            Title: Get(header, row, "name") ?? "(senza titolo)",
            Username: Get(header, row, "login_username"),
            Password: Get(header, row, "login_password"),
            Url: Get(header, row, "login_uri"),
            Notes: WithTotp(Get(header, row, "notes"), Get(header, row, "login_totp")),
            Folder: Get(header, row, "folder"));
    }

    private static string? WithTotp(string? notes, string? totp) => totp is null
        ? notes
        : notes is null ? $"TOTP: {totp}" : $"{notes}\nTOTP: {totp}";

    private static string? Get(IReadOnlyList<string> header, IReadOnlyList<string> row, string columnName)
    {
        int index = -1;
        for (int i = 0; i < header.Count; i++)
        {
            if (string.Equals(header[i].Trim(), columnName, StringComparison.OrdinalIgnoreCase))
            {
                index = i;
                break;
            }
        }

        if (index < 0 || index >= row.Count)
        {
            return null;
        }

        string value = row[index];
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
