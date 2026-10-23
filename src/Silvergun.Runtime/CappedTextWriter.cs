namespace Silvergun;

using System;
using System.IO;
using System.Text;

/// <summary>
/// A <see cref="TextWriter"/> that forwards at most <see cref="MaxBytes"/> UTF-8 bytes to an inner writer, in total,
/// over its whole lifetime. The first write that would cross the cap is cut at a character boundary and followed by
/// a one-line truncation marker; everything after that is dropped. The marker is budgeted inside the cap, so the
/// inner writer never receives more than <see cref="MaxBytes"/> bytes. Used for worker-mode stderr (ADR 0033): a
/// worker's diagnostics channel must stay bounded even if something in it loops. Thread-safe.
/// </summary>
public sealed class CappedTextWriter : TextWriter
{
    #region Constructors
    public CappedTextWriter(TextWriter inner, long maxBytes)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, (long)Encoding.UTF8.GetByteCount(TruncationMarker));
        this.inner = inner;
        MaxBytes = maxBytes;
    }
    #endregion

    #region Properties
    public override Encoding Encoding => inner.Encoding;

    /// <summary>The total UTF-8 byte budget, truncation marker included.</summary>
    public long MaxBytes { get; }

    /// <summary>UTF-8 bytes forwarded so far (≤ <see cref="MaxBytes"/>).</summary>
    public long BytesWritten { get { lock (sync) return bytesWritten; } }

    /// <summary><c>true</c> once output has been cut and the truncation marker written.</summary>
    public bool Truncated { get { lock (sync) return truncated; } }
    #endregion

    #region Methods
    public override void Write(char value) => Write(new ReadOnlySpan<char>(in value));

    public override void Write(string? value) => Write(value.AsSpan());

    public override void Write(char[] buffer, int index, int count) => Write(buffer.AsSpan(index, count));

    public override void Write(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty)
            return;

        lock (sync)
        {
            if (truncated)
                return;

            var bytes = Encoding.UTF8.GetByteCount(value);
            if (bytesWritten + bytes <= MaxBytes - markerBytes)
            {
                inner.Write(value);
                bytesWritten += bytes;
                return;
            }

            var prefix = value[..PrefixLength(value, MaxBytes - markerBytes - bytesWritten)];
            inner.Write(prefix);
            inner.Write(TruncationMarker);
            inner.Flush();
            bytesWritten += Encoding.UTF8.GetByteCount(prefix) + markerBytes;
            truncated = true;
        }
    }

    public override void Flush()
    {
        lock (sync)
            inner.Flush();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            lock (sync)
                inner.Dispose();
        base.Dispose(disposing);
    }

    // The longest prefix of text whose UTF-8 encoding fits in budget bytes, never splitting a surrogate pair.
    private static int PrefixLength(ReadOnlySpan<char> text, long budget)
    {
        var used = 0L;
        var i = 0;
        while (i < text.Length)
        {
            var pair = char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]);
            var size = pair ? 4 : text[i] < 0x80 ? 1 : text[i] < 0x800 ? 2 : 3;
            if (used + size > budget)
                break;
            used += size;
            i += pair ? 2 : 1;
        }
        return i;
    }
    #endregion

    #region Fields
    /// <summary>Appended once, when the cap is reached.</summary>
    public const string TruncationMarker = "\n[stderr truncated: worker diagnostics cap reached]\n";

    private static readonly int markerBytes = Encoding.UTF8.GetByteCount(TruncationMarker);

    private readonly TextWriter inner;
    private readonly object sync = new();
    private long bytesWritten;
    private bool truncated;
    #endregion
}
