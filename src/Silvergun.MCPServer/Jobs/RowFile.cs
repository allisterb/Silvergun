namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>Why a page could not be read.</summary>
public enum RowProblem
{
    None,

    /// <summary>The cursor's offset is not the start of a row of this list.</summary>
    Cursor,

    /// <summary>The list is not what the job child writes: the entry is corrupt.</summary>
    Corrupt,

    /// <summary>The list could not be opened or read (evicted, say).</summary>
    Unreadable
}

/// <summary>
/// One page of a row file: the rows kept, the offset of the first row not returned (null at the end), and whether the scan
/// stopped at its row limit rather than at the budget.
/// </summary>
public sealed record RowPage(IReadOnlyList<JsonObject> Rows, long? Next, bool ScanLimited, RowProblem Problem, string? Why)
{
    #region Methods
    public static RowPage Failed(RowProblem problem, string why) => new([], null, false, problem, why);
    #endregion
}

/// <summary>
/// Row files (task S2): the job child writes each drill-down list as one compact JSON object per line, already escaped,
/// wrapped and bounded exactly as it is served, and the server pages it from a byte offset without parsing the rest. The
/// default encoder writes every non-ASCII char as <c>\uXXXX</c>, so a line is ASCII and its length is the length it has
/// in a tool result.
/// </summary>
public static class RowFile
{
    #region Methods
    /// <summary>The chars <paramref name="node"/> takes in a tool result (the envelope uses the same default encoder).</summary>
    public static int Chars(JsonNode node) => node.ToJsonString(JobProtocol.JsonOptions).Length;

    /// <summary>
    /// <paramref name="escaped"/> (an escaper's output) cut to at most <paramref name="maxChars"/> chars at an escape
    /// boundary, never inside <c>\U000E0041</c> or a surrogate pair, then the escaper's suffix (its hash is of the escaped text).
    /// </summary>
    public static string Cut(string escaped, int maxChars)
    {
        if (escaped.Length <= maxChars)
            return escaped;
        var i = 0;
        while (i < escaped.Length)
        {
            var n = escaped[i] == '\\' ? EscapeLength(escaped, i)
                : char.IsHighSurrogate(escaped[i]) && i + 1 < escaped.Length && char.IsLowSurrogate(escaped[i + 1]) ? 2
                : 1;
            if (i + n > maxChars)
                break;
            i += n;
        }
        return escaped[..i] + UntrustedText.CutSuffix(escaped, escaped.Length - i);
    }

    /// <summary>
    /// Halves the longest <c>{"untrusted": …}</c> value of <paramref name="row"/> (outside the <paramref name="keep"/> keys)
    /// until the row takes at most <paramref name="maxChars"/>; false when it cannot be made to.
    /// </summary>
    public static bool Fit(JsonObject row, int maxChars, IReadOnlySet<string>? keep = null)
    {
        for (var round = 0; round < MaxFitRounds && Chars(row) > maxChars; round++)
        {
            var longest = Untrusted(row, keep).MaxBy(u => u["untrusted"]!.GetValue<string>().Length);
            var text = longest?["untrusted"]!.GetValue<string>();
            if (longest is null || text!.Length <= MinFitChars)
                return false;
            longest["untrusted"] = Cut(text, text.Length / 2);
        }
        return Chars(row) <= maxChars;
    }

    /// <summary>
    /// The rows of <paramref name="path"/> from <paramref name="offset"/> that <paramref name="keep"/> accepts, until the
    /// next would take the page past <paramref name="budgetChars"/>, <paramref name="maxRows"/> are kept, or
    /// <paramref name="maxScan"/> rows were read. A page never cuts a row, so across pages every row comes exactly once.
    /// </summary>
    public static RowPage Read(string path, long offset, Func<JsonObject, bool>? keep, int budgetChars, int maxRows, int maxScan)
    {
        try
        {
            using var stream = Open(path);
            if (offset < 0 || offset > stream.Length)
                return RowPage.Failed(RowProblem.Cursor, "the cursor's offset is outside the list");
            if (offset > 0)
            {
                stream.Position = offset - 1;
                if (stream.ReadByte() != '\n')
                    return RowPage.Failed(RowProblem.Cursor, "the cursor's offset is not the start of a row");
            }

            var lines = new Lines(stream);
            var rows = new List<JsonObject>();
            var (chars, scanned, position) = (0, 0, offset);
            while (lines.Next() is { } line)
            {
                var start = position;
                position += line.Length + 1;
                if (Parse(line) is not { } row)
                    return RowPage.Failed(RowProblem.Corrupt, "a row is not a JSON object");
                scanned++;
                if (keep is null || keep(row))
                {
                    // Measured as served, not as stored: a corrupt line could hold raw non-ASCII.
                    var size = Chars(row) + 1;
                    if (rows.Count >= maxRows || (rows.Count > 0 && chars + size > budgetChars))
                        return new(rows, start, false, RowProblem.None, null);
                    if (size > budgetChars)
                        return RowPage.Failed(RowProblem.Corrupt, "a row is over the page budget");
                    rows.Add(row);
                    chars += size;
                }
                if (scanned >= maxScan && position < stream.Length)
                    return new(rows, position, true, RowProblem.None, null);
            }
            return new(rows, null, false, RowProblem.None, null);
        }
        catch (InvalidDataException ex)
        {
            return RowPage.Failed(RowProblem.Corrupt, ex.Message);
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException)
        {
            // ArgumentException: a duplicate key, thrown by JsonObject when first read.
            return RowPage.Failed(RowProblem.Corrupt, "a row is not valid JSON for the list");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return RowPage.Failed(RowProblem.Unreadable, $"{Path.GetFileName(path)} could not be read ({ex.GetType().Name})");
        }
    }

    /// <summary>
    /// Every row of <paramref name="path"/> whose line contains <paramref name="needle"/> (a cheap pre-check, so most rows are
    /// never parsed) and that <paramref name="match"/> accepts, at most <paramref name="max"/> of them.
    /// </summary>
    public static (IReadOnlyList<JsonObject> Rows, RowProblem Problem, string? Why) Find(string path, byte[] needle, Func<JsonObject, bool> match, int max)
    {
        try
        {
            using var stream = Open(path);
            var lines = new Lines(stream);
            var found = new List<JsonObject>();
            while (found.Count < max && lines.Next() is { } line)
                if (line.AsSpan().IndexOf(needle) >= 0)
                {
                    if (Parse(line) is not { } row)
                        return ([], RowProblem.Corrupt, "a row is not a JSON object");
                    if (match(row))
                        found.Add(row);
                }
            return (found, RowProblem.None, null);
        }
        catch (InvalidDataException ex)
        {
            return ([], RowProblem.Corrupt, ex.Message);
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException)
        {
            return ([], RowProblem.Corrupt, "a row is not valid JSON for the list");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ([], RowProblem.Unreadable, $"{Path.GetFileName(path)} could not be read ({ex.GetType().Name})");
        }
    }

    /// <summary>The value of <paramref name="row"/>[<paramref name="key"/>] when it is <c>{"untrusted": "…"}</c>, else null.</summary>
    public static string? UntrustedValue(JsonObject row, string key) =>
        row[key] is JsonObject { Count: 1 } wrapped && wrapped["untrusted"] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    /// <summary>Every string value anywhere in <paramref name="node"/> (keys excluded), for a filter.</summary>
    public static IEnumerable<string> Strings(JsonNode? node) => node switch
    {
        JsonObject obj => obj.SelectMany(p => Strings(p.Value)),
        JsonArray array => array.SelectMany(Strings),
        JsonValue value when value.TryGetValue<string>(out var s) => [s],
        _ => [],
    };

    // Opened so an eviction elsewhere can still delete the entry while it is read.
    private static FileStream Open(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);

    // A row is ASCII by construction (the default encoder), and has no duplicate key at any depth; anything else is corrupt.
    private static JsonObject? Parse(byte[] line) =>
        System.Text.Ascii.IsValid(line) ? JsonNode.Parse(line, documentOptions: JobProtocol.DocumentOptions) as JsonObject : null;

    // Every {"untrusted": …} object under `node`, outside the `keep` keys.
    private static IEnumerable<JsonObject> Untrusted(JsonNode? node, IReadOnlySet<string>? keep) => node switch
    {
        JsonObject { Count: 1 } obj when obj["untrusted"] is JsonValue v && v.TryGetValue<string>(out _) => [obj],
        JsonObject obj => obj.Where(p => keep is null || !keep.Contains(p.Key)).SelectMany(p => Untrusted(p.Value, null)),
        JsonArray array => array.SelectMany(n => Untrusted(n, null)),
        _ => [],
    };

    // The length of the escape starting at `at` (a backslash), as UntrustedText writes them; never past the end.
    private static int EscapeLength(string text, int at) => Math.Min(text.Length - at, at + 1 >= text.Length ? 1 : text[at + 1] switch
    {
        'x' => 4,
        'u' => 6,
        'U' => 10,
        _ => 2,
    });
    #endregion

    #region Fields
    /// <summary>The bytes a row may take on disk; a longer line is corruption.</summary>
    public const int MaxRowBytes = 64 * 1024;

    private const int MaxFitRounds = 256;
    private const int MinFitChars = 64;
    #endregion

    #region Types
    // Newline-terminated lines of at most MaxRowBytes. A last line without its newline is corruption: the writer ends every row.
    private sealed class Lines(Stream stream)
    {
        public byte[]? Next()
        {
            var line = new MemoryStream();
            while (true)
            {
                if (start == end)
                {
                    (start, end) = (0, stream.Read(buffer));
                    if (end == 0)
                        return line.Length == 0 ? null : throw new InvalidDataException("the list ends inside a row");
                }
                var newline = buffer.AsSpan(start, end - start).IndexOf((byte)'\n');
                var stop = newline < 0 ? end : start + newline;
                line.Write(buffer, start, stop - start);
                if (line.Length > MaxRowBytes)
                    throw new InvalidDataException($"a row is over {MaxRowBytes} bytes");
                start = stop;
                if (newline >= 0)
                {
                    start++;
                    return line.ToArray();
                }
            }
        }

        private readonly byte[] buffer = new byte[64 * 1024];
        private int start;
        private int end;
    }
    #endregion
}

/// <summary>
/// Writes one row file in the job child: each row fitted to <see cref="MaxRowChars"/> (the page budget always holds one),
/// at most <paramref name="maxRows"/> rows and <paramref name="maxBytes"/> bytes, then <see cref="Truncated"/>. The file
/// appears under its name only on <see cref="Commit"/>.
/// </summary>
public sealed class RowWriter(string dir, string name, int maxRows = RowWriter.DefaultMaxRows, long maxBytes = RowWriter.DefaultMaxBytes) : IDisposable
{
    #region Properties
    public int Rows { get; private set; }

    /// <summary>A row was not written: a cap was reached, or a row could not be fitted (<see cref="Unfitted"/>).</summary>
    public bool Truncated { get; private set; }

    /// <summary>Rows dropped because no cut made them fit (none is expected: rows are bounded field by field).</summary>
    public int Unfitted { get; private set; }

    public long Bytes { get; private set; }
    #endregion

    #region Methods
    /// <summary>
    /// Appends <paramref name="row"/>; false when a cap stops the list (stop adding). <paramref name="keep"/>: keys never cut
    /// (a key a filter matches exactly). <paramref name="degrade"/>: a smaller form to try when no cut makes the row fit.
    /// </summary>
    public bool Add(JsonObject row, IReadOnlySet<string>? keep = null, Func<JsonObject, JsonObject>? degrade = null)
    {
        if (Rows >= maxRows)
            return !(Truncated = true);
        if (!RowFile.Fit(row, MaxRowChars, keep) && !(degrade is not null && RowFile.Fit(row = degrade(row), MaxRowChars, keep)))
        {
            Unfitted++;
            Truncated = true;
            return true;
        }
        var bytes = JsonSerializer.SerializeToUtf8Bytes(row, JobProtocol.JsonOptions);
        if (Bytes + bytes.Length + 1 > maxBytes)
            return !(Truncated = true);
        stream.Write(bytes);
        stream.WriteByte((byte)'\n');
        Bytes += bytes.Length + 1;
        Rows++;
        return true;
    }

    /// <summary>The list's index entry: its row count, whether it is cut, and how many rows could not be fitted (when any).</summary>
    public JsonObject Index()
    {
        var index = new JsonObject { ["rows"] = Rows, ["truncated"] = Truncated };
        if (Unfitted > 0)
            index["unfitted"] = Unfitted;
        return index;
    }

    /// <summary>Flushes and renames the file into place.</summary>
    public void Commit()
    {
        stream.Flush(flushToDisk: true);
        stream.Dispose();
        File.Move(temp, Path.Combine(dir, name), overwrite: true);
    }

    public void Dispose() => stream.Dispose();
    #endregion

    #region Fields
    /// <summary>
    /// The chars one row may take: under the page budget less the most a page's other fields (a finding kind's pass) take,
    /// so a page always holds at least one.
    /// </summary>
    public const int MaxRowChars = McpLimits.PageBudgetChars - 3_000;

    public const int DefaultMaxRows = 200_000;
    public const long DefaultMaxBytes = 64L * 1024 * 1024;

    private readonly string temp = Path.Combine(dir, "." + name + ".tmp");
    private readonly FileStream stream = new(Path.Combine(dir, "." + name + ".tmp"), FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024);
    #endregion
}
