namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

/// <summary>
/// Synthetic .NET single-file bundles (native-binaries-3), built in code: entry data, then the manifest the bundle header
/// starts (u32 major, u32 minor, i32 count, string bundle id; major >= 2: a 40-byte deps/runtimeconfig/flags block; per
/// entry i64 offset, i64 size, major >= 6: i64 compressed size, u8 type, string path; strings are BinaryWriter's 7-bit
/// length + UTF-8). Compressed entries are raw deflate (<see cref="DeflateStream"/>). Every manifest value can be
/// overridden to stage a hostile bundle. Linked into Silvergun.CLI.Tests as well, so it uses no NuGet internals.
/// </summary>
internal static class SingleFileBundleBuilder
{
    #region Methods
    /// <summary>
    /// <paramref name="prefix"/>, each entry's data in order, then the manifest; returns the bytes and the manifest's
    /// offset (the header offset). <paramref name="count"/> overrides the entry count written.
    /// </summary>
    internal static (byte[] Bytes, long HeaderOffset) Build(
        byte[] prefix, IReadOnlyList<Entry> entries, uint major = 6, uint minor = 0, int? count = null, string bundleId = "bundle-id",
        byte[]? rawBundleId = null)
    {
        using var data = new MemoryStream();
        data.Write(prefix);
        var rows = new List<(long Offset, long Size, long Compressed, Entry E)>();
        foreach (var e in entries)
        {
            if (e.Compress && major < 6)
                throw new ArgumentException("compressed entries need major >= 6", nameof(entries));
            var stored = e.Stored ?? (e.Compress ? Deflate(e.Bytes) : e.Bytes);
            var offset = data.Length;
            data.Write(stored);
            rows.Add((e.Offset ?? offset, e.Size ?? e.Bytes.Length, e.CompressedSize ?? (e.Compress ? stored.Length : 0), e));
        }

        var headerOffset = data.Length;
        using (var w = new BinaryWriter(data, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(major);
            w.Write(minor);
            w.Write(count ?? entries.Count);
            if (rawBundleId is null) w.Write(bundleId); else w.Write(rawBundleId);
            if (major >= 2)
                w.Write(new byte[40]);
            foreach (var (offset, size, compressed, e) in rows)
            {
                w.Write(offset);
                w.Write(size);
                if (major >= 6)
                    w.Write(compressed);
                w.Write(e.Type);
                if (e.RawName is null) w.Write(e.Name); else w.Write(e.RawName);
            }
        }
        return (data.ToArray(), headerOffset);
    }

    /// <summary>
    /// A host as the bundler lays it out: <paramref name="image"/>, the 8-byte header offset, the host signature, the
    /// entry data, then the manifest the offset points at (after the signature, as <c>DotNetHostScanner</c> requires).
    /// <paramref name="truncateManifestAt"/> cuts the file that many bytes into the manifest.
    /// </summary>
    internal static byte[] Hosted(byte[] image, IReadOnlyList<Entry> entries, uint major = 6, int? truncateManifestAt = null)
    {
        var prefix = image.Concat(new byte[8]).Concat(Signature).ToArray();
        var (bytes, headerOffset) = Build(prefix, entries, major);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(image.Length), headerOffset);
        return truncateManifestAt is { } cut ? bytes[..(int)(headerOffset + cut)] : bytes;
    }

    /// <summary>Raw deflate (no zlib/gzip framing), as the bundler writes compressed entries.</summary>
    internal static byte[] Deflate(byte[] bytes)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
            deflate.Write(bytes);
        return output.ToArray();
    }

    /// <summary>A BinaryWriter string's encoding: 7-bit length prefix, then the UTF-8 bytes.</summary>
    internal static byte[] Str(byte[] utf8)
    {
        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            w.Write7BitEncodedInt(utf8.Length);
            w.Write(utf8);
        }
        return ms.ToArray();
    }
    #endregion

    #region Nested types
    /// <summary>
    /// One bundle entry. The nullable members, when set, are written to the manifest instead of the honest value:
    /// <see cref="Stored"/> replaces the bytes placed in the bundle (e.g. invalid deflate), <see cref="RawName"/> the
    /// encoded path string (prefix included).
    /// </summary>
    internal sealed record Entry(string Name, byte[] Bytes, bool Compress = false, byte Type = 1)
    {
        public long? Offset { get; init; }
        public long? Size { get; init; }
        public long? CompressedSize { get; init; }
        public byte[]? Stored { get; init; }
        public byte[]? RawName { get; init; }
    }
    #endregion

    #region Fields
    /// <summary>The host bundle signature (SDK AppHostTemplate 3.1-10.0); same bytes as DotNetHostScannerTests.Signature.</summary>
    internal static readonly byte[] Signature = Convert.FromHexString("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae");
    #endregion
}
