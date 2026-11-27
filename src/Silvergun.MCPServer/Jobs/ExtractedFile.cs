namespace Silvergun.MCPServer.Jobs;

using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>
/// <c>read_file</c>'s server half (task D2.3, S2): an extracted file is opened only when <c>inventory.jsonl</c> names it,
/// only at the path the row records, only inside the entry's <c>files/</c> or <c>files-bundles/</c>, and never through a
/// link. Its bytes are rendered for display, bounded, and fenced by the caller.
/// </summary>
public static class ExtractedFile
{
    #region Methods
    /// <summary>
    /// The inventory row whose path is exactly <paramref name="path"/> and the full path of its file, or the status and
    /// reason <c>read_file</c> refuses it with. The row's <c>note</c>, when it has one, is the second reason.
    /// </summary>
    public static (JsonObject? Row, string? FullPath, ToolStatus Status, string? Problem, RowProblem Corrupt) Resolve(string entryDir, string path)
    {
        var needle = Encoding.ASCII.GetBytes("\"path\":{\"untrusted\":" + JsonSerializer.Serialize(path, JobProtocol.JsonOptions) + "}");
        var (rows, problem, why) = RowFile.Find(Path.Combine(entryDir, JobProtocol.InventoryFile), needle, r => RowFile.UntrustedValue(r, "path") == path, 2);
        if (problem != RowProblem.None)
            return (null, null, ToolStatus.Failed, why, problem);
        if (rows.Count == 0)
            return (null, null, ToolStatus.NotFound, "no file of this job has that path; pass a path exactly as list_files gives it (the untrusted value)", RowProblem.None);
        if (rows.Count > 1)
            return (null, null, ToolStatus.NotPermitted, "that path names more than one entry of the package, so it does not say which to read", RowProblem.None);

        var row = rows[0];
        if (row["kind"] is JsonValue kind && kind.TryGetValue<string>(out var k) && k == "notExtracted")
            return (row, null, ToolStatus.NotFound, "the entry is declared in the package but was never extracted, so there is nothing to read", RowProblem.None);
        if (!(row["readable"] is JsonValue readable && readable.TryGetValue<bool>(out var r) && r)
            || !(row["file"] is JsonValue stored && stored.TryGetValue<string>(out var file) && file.Length > 0))
            return (row, null, ToolStatus.NotPermitted, "the entry is a link, or its name is too long to serve; it is never opened", RowProblem.None);

        string full;
        try
        {
            full = Path.GetFullPath(Path.Join(entryDir, file));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return (row, null, ToolStatus.NotPermitted, "the inventory row names no usable file; it is never opened", RowProblem.Corrupt);
        }
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var roots = new[] { JobProtocol.FilesDir, JobProtocol.FilesDir + "-bundles" }.Select(d => Path.Combine(entryDir, d) + Path.DirectorySeparatorChar);
        if (!roots.Any(r => full.StartsWith(r, comparison)))
            return (row, null, ToolStatus.NotPermitted, "the inventory row names a file outside the job's extracted files; it is never opened", RowProblem.Corrupt);
        try
        {
            if (!File.Exists(full))
                return (row, null, ToolStatus.NotFound, Gone, RowProblem.None);
            if (LinkOnPath(entryDir, full))
                return (row, null, ToolStatus.NotPermitted, "the file, or a directory above it, is a link; it is never followed", RowProblem.None);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (row, null, ToolStatus.NotFound, Gone, RowProblem.None);
        }
        return (row, full, ToolStatus.Succeeded, null, RowProblem.None);
    }

    /// <summary>
    /// Up to <paramref name="length"/> bytes of <paramref name="full"/> from <paramref name="offset"/> (fewer when the file
    /// shrank while it was read), and the file's size; or the status and reason it could not be read.
    /// </summary>
    public static (byte[]? Bytes, long Size, ToolStatus Status, string? Problem) ReadRange(string full, long offset, int length)
    {
        try
        {
            using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 1, FileOptions.None);
            var size = stream.Length;
            if (offset > size)
                return (null, size, ToolStatus.InvalidArgument, $"offset is past the end of the file, which is {size} bytes");
            stream.Position = offset;
            var bytes = new byte[(int)Math.Min(length, size - offset)];
            var read = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            return (read == bytes.Length ? bytes : bytes[..read], size, ToolStatus.Succeeded, null);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return (null, 0, ToolStatus.NotFound, Gone);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (null, 0, ToolStatus.Failed, $"the extracted file could not be read ({ex.GetType().Name})");
        }
    }

    /// <summary>
    /// <paramref name="bytes"/> as UTF-8 text for display, within <paramref name="maxChars"/>: newlines (and CRLF, as one) stay;
    /// every control, bidi, invisible and Tag-block code point is escaped (<see cref="UntrustedText.Escape"/>); a byte that is
    /// not UTF-8 is U+FFFD, counted in <c>Invalid</c>. Stops before a sequence cut by the end of the range, unless
    /// <paramref name="atEnd"/>. <c>Used</c> is the bytes rendered.
    /// </summary>
    public static (string Text, int Used, int Invalid) Text(ReadOnlySpan<byte> bytes, int maxChars, bool atEnd)
    {
        var sb = new StringBuilder();
        var (used, invalid) = (0, 0);
        while (used < bytes.Length)
        {
            var status = System.Text.Rune.DecodeFromUtf8(bytes[used..], out var rune, out var consumed);
            if (status == System.Buffers.OperationStatus.NeedMoreData && !atEnd)
                break;
            string piece;
            if (status != System.Buffers.OperationStatus.Done)
                (piece, invalid) = (replacement, invalid + 1);
            else if (rune.Value == '\r' && used + 1 < bytes.Length && bytes[used + 1] == '\n')
                (piece, consumed) = ("\n", 2);
            else if (rune.Value == '\r' && used + 1 == bytes.Length && !atEnd && used > 0)
                break;   // a CR at the range's end may be half a CRLF: the next page starts with it
            else
                piece = rune.Value is '\n' or '\t' ? rune.ToString()
                    : Invisible(rune.Value) ? (rune.IsBmp ? $"\\u{rune.Value:x4}" : $"\\U{rune.Value:X8}")
                    : UntrustedText.Escape(rune.ToString());
            if (sb.Length + piece.Length > maxChars)
                break;
            sb.Append(piece);
            used += consumed;
        }
        // A range too short for its first character still moves on: that character shows as U+FFFD.
        return used == 0 && bytes.Length > 0 && !atEnd ? Text(bytes, maxChars, atEnd: true) : (sb.ToString(), used, invalid);
    }

    /// <summary>
    /// <paramref name="bytes"/> as a hex dump within <paramref name="maxChars"/>: 16 bytes a line, each line its absolute
    /// offset from <paramref name="start"/>, the bytes, and their printable ASCII (anything else a dot).
    /// </summary>
    public static (string Text, int Used) Hex(ReadOnlySpan<byte> bytes, long start, int maxChars)
    {
        var sb = new StringBuilder();
        var used = 0;
        while (used < bytes.Length)
        {
            var line = bytes.Slice(used, Math.Min(16, bytes.Length - used));
            var hex = string.Join(" ", line.ToArray().Select((b, i) => (i == 8 ? " " : "") + b.ToString("x2")));
            var text = $"{start + used:x8}  {hex,-48}  |{new string(line.ToArray().Select(b => b is >= 0x20 and < 0x7F ? (char)b : '.').ToArray())}|\n";
            if (sb.Length + text.Length > maxChars)
                break;
            sb.Append(text);
            used += line.Length;
        }
        return (sb.ToString().TrimEnd('\n'), used);
    }

    // Default_Ignorable_Code_Point and Bidi_Control code points that UntrustedText.Escape lets through (S2 review W5): the
    // bulk block is not JSON-encoded, so they would reach the agent raw. Escape's own set is left to an ADR (it is shared).
    private static bool Invisible(int cp) =>
        cp is 0x034F or 0x061C or 0x115F or 0x1160 or 0x17B4 or 0x17B5 or 0x3164 or 0xFFA0
            or >= 0x180B and <= 0x180F or >= 0x2060 and <= 0x206F or >= 0xFE00 and <= 0xFE0F or >= 0xFFF0 and <= 0xFFFB
            or >= 0x1BCA0 and <= 0x1BCA3 or >= 0x1D173 and <= 0x1D17A or >= 0xE0000 and <= 0xE0FFF;

    // Whether `full`, or any directory between it and the entry, is a reparse point (a symlink or junction).
    private static bool LinkOnPath(string entryDir, string full)
    {
        var stop = Path.TrimEndingDirectorySeparator(entryDir);
        for (var p = full; p is not null && p.Length > stop.Length; p = Path.GetDirectoryName(p))
            if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0)
                return true;
        return false;
    }
    #endregion

    #region Fields
    // ADR 0034's wording for an extracted file that is gone.
    private const string Gone = "the extracted file no longer exists (an antivirus may have removed it)";

    // U+FFFD, built from its code point so the source holds no raw non-ASCII.
    private static readonly string replacement = char.ConvertFromUtf32(0xFFFD);
    #endregion
}
