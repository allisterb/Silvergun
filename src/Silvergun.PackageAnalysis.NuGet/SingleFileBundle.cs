namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

/// <summary>A .NET single-file bundle entry written to disk. <see cref="Name"/> is the raw, attacker-authored manifest name.</summary>
internal sealed record ExtractedBundleEntry(string Name, string FullPath, int Index = -1);

/// <summary>A bundle entry that was not extracted, or the whole bundle when <see cref="Name"/> is empty (Index -1). Name is raw.</summary>
internal sealed record UnextractedBundleEntry(string Name, string Reason, int Index = -1);

/// <summary>A single-file bundle found in a package: the host file, its escaped path and role, and its header offset.</summary>
internal sealed record BundleHost(string FullPath, string Reported, PackageItemRole Role, long HeaderOffset);

/// <summary>A package-level coverage gap from unpacking: the escaped <c>host!/entry</c> path, the host's role and file,
/// and the reason (already worded for a SkipReason).</summary>
internal sealed record UnextractedBundleRow(string Reported, PackageItemRole Role, string HostFullPath, string Reason);

/// <summary>
/// Unpacks a .NET single-file bundle (the manifest the host's bundle header points at: major, minor, file count, bundle
/// id, v2+ deps/runtimeconfig locations and flags, then per entry offset, size, v6+ compressed size, type, path; v6+
/// entries are raw deflate). Measured on Clowd.Squirrel 2.11.1's Squirrel.exe and Update.exe (v6.0, 118 and 83 entries).
/// Every manifest value is attacker-authored: entries are bounds-checked against the bundle data, capped in size and
/// expansion ratio, charged to a byte budget, inflated to exactly their declared size, and written under a name that is
/// the entry's own only when that is a plain file name. Nothing is classified here: callers decide by content.
/// </summary>
internal static class SingleFileBundle
{
    #region Methods
    /// <summary>
    /// Extracts the bundle in <paramref name="hostPath"/>, whose header is at <paramref name="headerOffset"/>, into
    /// <paramref name="outDir"/>. Every entry ATTEMPTED is charged its declared size against <paramref name="budget"/>,
    /// whether it then succeeds or fails, so failing entries cannot inflate unbounded work; at most
    /// <paramref name="maxEntries"/> entries are attempted and the rest are one summary failure. Entries that fail are
    /// returned with a reason; a manifest that cannot be read is one failure with an empty name. Throws only on I/O
    /// failure opening the host or creating <paramref name="outDir"/>.
    /// </summary>
    internal static (IReadOnlyList<ExtractedBundleEntry> Extracted, IReadOnlyList<UnextractedBundleEntry> Failed, long Charged, int Attempted) Extract(
        string hostPath, long headerOffset, string outDir, long budget, int maxEntries = int.MaxValue)
    {
        using var host = File.OpenRead(hostPath);
        IReadOnlyList<Entry> entries;
        try
        {
            entries = ReadManifest(host, headerOffset);
        }
        catch (InvalidDataException ex)
        {
            return ([], [new(string.Empty, $"the bundle manifest could not be read: {ex.Message}")], 0, 0);
        }

        Directory.CreateDirectory(outDir);
        var (extracted, failed, used, charged) = (new List<ExtractedBundleEntry>(), new List<UnextractedBundleEntry>(),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase), 0L);
        var attempted = Math.Min(entries.Count, Math.Max(maxEntries, 0));
        for (var i = 0; i < attempted; i++)
        {
            var e = entries[i];
            if (Invalid(e, headerOffset, budget - charged) is { } why)
            {
                failed.Add(new(e.Name, why, i));
                continue;
            }

            charged += e.Size;
            var path = Path.Combine(outDir, DiskName(e.Name, i, used));
            var preexisting = Path.Exists(path);   // never delete what this call did not create
            try
            {
                WriteEntry(host, e, path);
                extracted.Add(new(e.Name, path, i));
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
            {
                if (!preexisting)
                    TryDelete(path);
                failed.Add(new(e.Name, ex is InvalidDataException
                    ? $"the entry could not be inflated: {ex.Message}"
                    : $"{ex.GetType().Name} while extracting the entry", i));
            }
        }
        if (attempted < entries.Count)
            failed.Add(new(string.Empty, $"{entries.Count - attempted} entr(ies) past the package-wide limit on bundle entries were not extracted"));
        return (extracted, failed, charged, attempted);
    }

    private static IReadOnlyList<Entry> ReadManifest(Stream host, long headerOffset)
    {
        var length = host.Length - headerOffset;
        if (headerOffset < 0 || length <= 0 || length > MaxManifestBytes)
            throw new InvalidDataException($"the manifest region is {length} bytes (limit {MaxManifestBytes})");

        var c = new Cursor(NativeBinaryDetector.ReadAt(host, headerOffset, (int)length));
        var major = c.U32();
        c.U32();
        var count = c.I32();
        if (major is < 1 or > MaxMajor)
            throw new InvalidDataException($"unsupported bundle version {major}");
        if (count is < 0 or > MaxEntries)
            throw new InvalidDataException($"{count} entries (limit {MaxEntries})");
        c.Str();                                   // bundle id
        if (major >= 2)
            c.Skip(40);                            // deps.json and runtimeconfig.json offset/size, flags

        return Enumerable.Range(0, count)
            .Select(_ => new Entry(Offset: c.I64(), Size: c.I64(), CompressedSize: major >= 6 ? c.I64() : 0, Type: c.U8(), Name: c.Str()))
            .ToArray();
    }

    // Why an entry may not be extracted, or null. Entry data lies before the manifest, so it must end by headerOffset.
    private static string? Invalid(Entry e, long headerOffset, long budgetLeft)
    {
        var stored = e.CompressedSize > 0 ? e.CompressedSize : e.Size;
        return e.Offset < 0 || e.Size < 0 || e.CompressedSize < 0 ? "negative offset or size in the manifest"
            : e.Offset > headerOffset - stored ? $"its data ({e.Offset}+{stored}) lies outside the bundle"
            : e.Size > MaxEntryBytes ? $"{e.Size} bytes exceeds the per-entry limit of {MaxEntryBytes}"
            : e.Size > budgetLeft ? $"{e.Size} bytes exceeds the remaining bundle extraction budget ({Math.Max(budgetLeft, 0)})"
            : e.CompressedSize > 0 && e.Size > e.CompressedSize * MaxRatio ? $"expands {e.CompressedSize} to {e.Size} bytes (ratio limit {MaxRatio})"
            : null;
    }

    // Writes exactly e.Size bytes, or throws InvalidDataException. Deflate output is cut at Size + 1, so a lying size can
    // never write more than the budget it was charged.
    private static void WriteEntry(Stream host, Entry e, string path)
    {
        host.Position = e.Offset;
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write);
        // Deflate reads only the entry's declared compressed bytes, as the runtime does; it never runs on into later data.
        using var inflate = e.CompressedSize == 0 ? null : new DeflateStream(new Bounded(host, e.CompressedSize), CompressionMode.Decompress);
        var written = inflate is null ? Copy(host, output, e.Size) : Copy(inflate, output, e.Size + 1);
        if (written != e.Size)
            throw new InvalidDataException($"{written} bytes produced, the manifest says {e.Size}");
    }

    private static long Copy(Stream from, Stream to, long max)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while (total < max && (read = from.Read(buffer, 0, (int)Math.Min(buffer.Length, max - total))) > 0)
        {
            to.Write(buffer, 0, read);
            total += read;
        }
        return total;
    }

    // The entry's own name when it is a plain, unused file name (so reference resolution beside it can work), else an
    // index. Never a path: manifest names can carry separators, traversal, device names or control characters.
    private static string DiskName(string name, int index, HashSet<string> used)
    {
        var plain = name.Length is > 0 and <= 128
            && char.IsAsciiLetterOrDigit(name[0])
            && name.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-' or '_')
            && !name.EndsWith('.')
            && !reservedStems.Contains(name.Split('.')[0])
            && used.Add(name);
        return plain ? name : $"_{index:D5}.bin";   // a leading '_' is never a plain name, so the two cannot collide
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
    #endregion

    #region Child types
    private readonly record struct Entry(long Offset, long Size, long CompressedSize, byte Type, string Name);

    // A read-only window of `length` bytes from the inner stream's current position; the inner stream is not disposed.
    private sealed class Bounded(Stream inner, long length) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = remaining <= 0 ? 0 : inner.Read(buffer, offset, (int)Math.Min(count, remaining));
            remaining -= read;
            return read;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private long remaining = length;
    }

    // Bounds-checked little-endian reader over the manifest bytes; any overrun is InvalidDataException.
    private sealed class Cursor(byte[] bytes)
    {
        public uint U32() => BitConverter.ToUInt32(Take(4));
        public int I32() => BitConverter.ToInt32(Take(4));
        public long I64() => BitConverter.ToInt64(Take(8));
        public byte U8() => Take(1)[0];
        public void Skip(int n) => Take(n);

        // A BinaryWriter string: 7-bit encoded byte length, then UTF-8.
        public string Str()
        {
            var (length, shift) = (0, 0);
            byte b;
            do
            {
                if (shift > 28)
                    throw new InvalidDataException("malformed string length");
                b = U8();
                if (shift == 28 && b > 0x0F)               // as BinaryReader: a fifth byte past 4 bits overflows
                    throw new InvalidDataException("malformed string length");
                length |= (b & 0x7F) << shift;
                shift += 7;
            }
            while ((b & 0x80) != 0);
            if (length is < 0 or > MaxNameBytes)
                throw new InvalidDataException($"a {length}-byte string (limit {MaxNameBytes})");
            return Encoding.UTF8.GetString(Take(length));
        }

        private ReadOnlySpan<byte> Take(int n)
        {
            if (n < 0 || position > bytes.Length - n)
                throw new InvalidDataException("the manifest ends early");
            position += n;
            return bytes.AsSpan(position - n, n);
        }

        private int position;
    }
    #endregion

    #region Fields
    private const uint MaxMajor = 64;
    private const int MaxEntries = 4096, MaxNameBytes = 4096, MaxManifestBytes = 16 << 20;
    private const long MaxEntryBytes = 256L << 20, MaxRatio = 200;

    private static readonly HashSet<string> reservedStems = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };
    #endregion
}
