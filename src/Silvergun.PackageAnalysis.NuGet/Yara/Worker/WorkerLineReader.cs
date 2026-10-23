namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using System.Text;
using System.Text.Unicode;

/// <summary>What one <see cref="WorkerLineReader.ReadLine"/> call found.</summary>
public enum WorkerLineStatus
{
    /// <summary>A complete <c>\n</c>-terminated line of valid UTF-8.</summary>
    Line,

    /// <summary>The stream ended cleanly, at a line boundary.</summary>
    Eof,

    /// <summary>The stream ended part-way through a line (no terminating <c>\n</c>).</summary>
    Truncated,

    /// <summary>A line exceeded the byte limit. Detected before more than the limit was buffered; the reader stops.</summary>
    TooLong,

    /// <summary>A complete line that is not valid UTF-8.</summary>
    InvalidUtf8,

    /// <summary>Reading failed (the pipe broke, or the stream was closed under the reader).</summary>
    IoError,
}

/// <summary>
/// Reads <c>\n</c>-terminated UTF-8 lines from a hostile stream, bounded <b>while reading</b>: a line's bytes are
/// accumulated only up to <see cref="MaxLineBytes"/>, and the first byte past it ends reading with
/// <see cref="WorkerLineStatus.TooLong"/>, so an endless line costs at most the limit plus one read buffer of bytes
/// read. Memory is bounded the same way (review N6): the line buffer grows by doubling but is capped at exactly
/// <see cref="MaxLineBytes"/>, so the reader holds at most the limit plus its 64 KiB read buffer (plus the copy a
/// returned line is). Every status except <see cref="WorkerLineStatus.Line"/> is terminal: once returned, every later
/// call returns it again without touching the stream. Not thread-safe.
/// </summary>
public sealed class WorkerLineReader
{
    #region Constructors
    public WorkerLineReader(Stream stream, int maxLineBytes = WorkerProtocol.MaxLineBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxLineBytes);
        this.stream = stream;
        MaxLineBytes = maxLineBytes;
    }
    #endregion

    #region Properties
    /// <summary>The per-line byte limit, excluding the terminating <c>\n</c>.</summary>
    public int MaxLineBytes { get; }
    #endregion

    #region Methods
    /// <summary>
    /// The next line's bytes (without its <c>\n</c>) and <see cref="WorkerLineStatus.Line"/>, or an empty buffer and the
    /// terminal status. The returned bytes are a copy the caller owns.
    /// </summary>
    public (WorkerLineStatus Status, byte[] Bytes) ReadLine()
    {
        if (terminal is { } done)
            return (done, []);

        lineLength = 0;
        while (true)
        {
            if (start == end && Fill() is { } stop)
                return (Terminate(stop), []);

            var chunk = buffer.AsSpan(start, end - start);
            var newline = chunk.IndexOf((byte)'\n');
            var content = newline < 0 ? chunk : chunk[..newline];
            if (lineLength + content.Length > MaxLineBytes)
                return (Terminate(WorkerLineStatus.TooLong), []);

            Append(content);
            start += newline < 0 ? content.Length : newline + 1;
            if (newline >= 0)
                return Utf8.IsValid(line.AsSpan(0, lineLength))
                    ? (WorkerLineStatus.Line, line.AsSpan(0, lineLength).ToArray())
                    : (Terminate(WorkerLineStatus.InvalidUtf8), []);
        }
    }

    /// <summary>A short, escaped, lossily decoded excerpt of <paramref name="bytes"/>, safe to put in a log line.</summary>
    internal static string Excerpt(ReadOnlySpan<byte> bytes) =>
        WorkerProtocol.Safe(Encoding.UTF8.GetString(bytes[..Math.Min(bytes.Length, ExcerptBytes)]), ExcerptChars);

    // Refills the read buffer; null when bytes arrived, else the terminal status (Eof, Truncated or IoError).
    private WorkerLineStatus? Fill()
    {
        try
        {
            start = 0;
            end = stream.Read(buffer, 0, buffer.Length);
            return end > 0 ? null : lineLength == 0 ? WorkerLineStatus.Eof : WorkerLineStatus.Truncated;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            end = 0;
            return WorkerLineStatus.IoError;
        }
    }

    // Appends to the line buffer, growing it by doubling but never past MaxLineBytes (the caller has already checked that
    // the line still fits), so the buffer's capacity is bounded by the limit itself.
    private void Append(ReadOnlySpan<byte> content)
    {
        var needed = lineLength + content.Length;
        if (needed > line.Length)
            Array.Resize(ref line, (int)Math.Min(MaxLineBytes, Math.Max(needed, Math.Max(InitialLineBytes, 2L * line.Length))));

        content.CopyTo(line.AsSpan(lineLength));
        lineLength = needed;
    }

    private WorkerLineStatus Terminate(WorkerLineStatus status)
    {
        terminal = status;
        lineLength = 0;
        return status;
    }
    #endregion

    #region Fields
    private const int ReadBufferBytes = 64 * 1024;
    private const int InitialLineBytes = 256;
    private const int ExcerptBytes = 120;
    private const int ExcerptChars = 80;

    private readonly Stream stream;
    private readonly byte[] buffer = new byte[ReadBufferBytes];
    private byte[] line = [];
    private int lineLength;
    private int start;
    private int end;
    private WorkerLineStatus? terminal;
    #endregion
}
