namespace Silvergun.MCPServer.Jobs;

using System.Buffers.Text;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// An opaque paging cursor (task D5): it names the query (job, tool, arguments, hashed), the result it pages (the entry's
/// <c>analyzedAt</c>, so a re-analysed entry is never paged with an old cursor), and the byte offset of the next row. It
/// lives in no server's memory, so any server process continues any cursor. A forged offset can only start a page at a row
/// boundary of the same list, which the agent could reach anyway.
/// </summary>
public static class PageCursor
{
    #region Methods
    /// <summary>The cursor for the rows of <paramref name="query"/> from <paramref name="offset"/>.</summary>
    public static string Encode(string query, DateTimeOffset analyzedAt, long offset) =>
        Prefix + Base64Url.EncodeToString(Encoding.ASCII.GetBytes($"{QueryHash(query)}|{analyzedAt.UtcTicks}|{offset}"));

    /// <summary>
    /// The offset <paramref name="cursor"/> continues <paramref name="query"/> from (0 for no cursor), or why it does not
    /// belong to this query and result.
    /// </summary>
    public static (long Offset, string? Problem) Decode(string? cursor, string query, DateTimeOffset analyzedAt)
    {
        if (string.IsNullOrEmpty(cursor))
            return (0, null);
        string[] parts;
        try
        {
            parts = cursor.StartsWith(Prefix, StringComparison.Ordinal) && cursor.Length <= MaxCursorChars
                ? Encoding.ASCII.GetString(Base64Url.DecodeFromChars(cursor.AsSpan(Prefix.Length))).Split('|')
                : [];
        }
        catch (FormatException)
        {
            parts = [];
        }
        if (parts.Length != 3 || parts[0] != QueryHash(query) || !long.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var offset))
            return (0, "the cursor is not one this query issued: it comes from another job, tool or set of arguments; call again without a cursor to start over");
        if (parts[1] != analyzedAt.UtcTicks.ToString(CultureInfo.InvariantCulture))
            return (0, "the job's result was analysed again since this cursor was issued; call again without a cursor to start over");
        return (offset, null);
    }

    /// <summary>The query key of a tool call: the job, the tool and each argument, in order, length-prefixed (null and "" alike).</summary>
    public static string Query(string jobId, string tool, params string?[] arguments) =>
        string.Concat(new[] { jobId, tool }.Concat(arguments.Select(a => a ?? string.Empty)).Select(a => $"{a.Length}:{a}"));

    private static string QueryHash(string query) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(query)))[..16];
    #endregion

    #region Fields
    private const string Prefix = "c1.";
    private const int MaxCursorChars = 256;
    #endregion
}
