namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Xunit;

/// <summary>
/// native-binaries-2: <see cref="DotNetHostScanner.HashAndScan"/> over synthetic byte arrays. The classification table
/// (no signature / zero offset / non-zero offset, with and without the app-path placeholder), the bundle-header
/// plausibility bounds, markers straddling the 1 MiB read boundary and its 63-byte carry, a signature too close to the
/// start to have an offset before it, the SHA-256 against <see cref="SHA256.HashData(byte[])"/> at the buffer-size edges,
/// short reads, and the stream's starting position. Plus the real SDK AppHostTemplate when installed.
/// </summary>
public sealed class DotNetHostScannerTests
{
    #region Methods: classification
    [Fact]
    public void HashAndScan_SignatureWithZeroOffset_IsAppHost()
    {
        var bytes = Image(4096, signatureAt: 1000, headerOffset: 0);

        var (_, host, bundled) = Scan(bytes);

        Assert.Equal(DotNetHost.AppHost, host);
        Assert.Null(bundled);
    }

    [Fact]
    public void HashAndScan_SignatureWithZeroOffsetAndThePlaceholder_IsHostTemplate()
    {
        var bytes = Image(4096, signatureAt: 1000, headerOffset: 0);
        Placeholder.CopyTo(bytes, 2000);

        var (_, host, bundled) = Scan(bytes);

        Assert.Equal(DotNetHost.HostTemplate, host);
        Assert.Null(bundled);
    }

    // The placeholder before the signature counts as much as after it.
    [Fact]
    public void HashAndScan_PlaceholderBeforeTheSignature_IsHostTemplate()
    {
        var bytes = Image(4096, signatureAt: 3000, headerOffset: 0);
        Placeholder.CopyTo(bytes, 100);

        Assert.Equal(DotNetHost.HostTemplate, Scan(bytes).Host);
    }

    [Fact]
    public void HashAndScan_PlaceholderOnly_IsHostTemplate()
    {
        var bytes = new byte[4096];
        Placeholder.CopyTo(bytes, 500);

        var (_, host, bundled) = Scan(bytes);

        Assert.Equal(DotNetHost.HostTemplate, host);
        Assert.Null(bundled);
    }

    [Fact]
    public void HashAndScan_NeitherMarker_IsNone()
    {
        var (_, host, bundled) = Scan(Noise(64 * 1024, seed: 1));

        Assert.Equal(DotNetHost.None, host);
        Assert.Null(bundled);
    }

    [Fact]
    public void HashAndScan_EmptyStream_IsNoneWithTheEmptyHash()
    {
        var (sha, host, bundled) = Scan([]);

        Assert.Equal(DotNetHost.None, host);
        Assert.Null(bundled);
        Assert.Equal(Sha256([]), sha);
    }

    // One byte short of either marker is not the marker.
    [Fact]
    public void HashAndScan_TruncatedMarkers_AreNone()
    {
        var bytes = new byte[4096];
        Signature.AsSpan(0, Signature.Length - 1).CopyTo(bytes.AsSpan(1000));
        Placeholder.AsSpan(1, Placeholder.Length - 1).CopyTo(bytes.AsSpan(2000));

        Assert.Equal(DotNetHost.None, Scan(bytes).Host);
    }

    // The bundle header after the signature, as the bundler lays it out (header appended after the host).
    [Fact]
    public void HashAndScan_NonZeroOffsetToAValidHeader_IsSingleFileBundleWithItsCount()
    {
        var bytes = Image(8192, signatureAt: 1000, headerOffset: 5000);
        Header(bytes, 5000, major: 6, minor: 0, count: 118);

        var (_, host, bundled) = Scan(bytes);

        Assert.Equal(DotNetHost.SingleFileBundle, host);
        Assert.Equal(118, bundled);
    }

    // The bundler appends the header after the host, so a plausible header before the signature is not believed (review S1):
    // still a bundle, but no count.
    [Fact]
    public void HashAndScan_NonZeroOffsetToAHeaderBeforeTheSignature_IsSingleFileBundleWithNoCount()
    {
        var bytes = Image(8192, signatureAt: 6000, headerOffset: 100);
        Header(bytes, 100, major: 2, minor: 0, count: 83);

        var (_, host, bundled) = Scan(bytes);

        Assert.Equal(DotNetHost.SingleFileBundle, host);
        Assert.Null(bundled);
    }

    // The offset's own 8 bytes sit just before the signature: a header there is before it too.
    [Fact]
    public void HashAndScan_HeaderAtTheOffsetFieldBeforeTheSignature_HasNoCount()
    {
        const int at = 1000;
        var bytes = Image(8192, signatureAt: at, headerOffset: at - 8);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)null), HostAndCount(Scan(bytes)));
    }

    // headerOffset == signatureAt: the "<=" edge of the check. The signature's own bytes would read as major
    // 0xb902128b, so this also could not pass the plausibility bound; HeaderRightAfterTheSignature pins the accepting side.
    [Fact]
    public void HashAndScan_HeaderExactlyAtTheSignature_HasNoCount()
    {
        const int at = 1000;
        var bytes = Image(8192, signatureAt: at, headerOffset: at);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)null), HostAndCount(Scan(bytes)));
    }

    // signatureAt + 1 cannot carry a plausible header: its 12 bytes are the signature's own (major 0x6ab90212 > 64).
    [Fact]
    public void HashAndScan_HeaderOneByteAfterTheSignatureStart_HasNoCount()
    {
        const int at = 1000;
        var bytes = Image(8192, signatureAt: at, headerOffset: at + 1);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)null), HostAndCount(Scan(bytes)));
    }

    // The first position after the signature that does not overlap it: the earliest header that is read.
    [Fact]
    public void HashAndScan_HeaderRightAfterTheSignature_IsRead()
    {
        const int at = 1000;
        var bytes = Image(8192, signatureAt: at, headerOffset: at + 32);
        Header(bytes, at + 32, major: 6, minor: 0, count: 21);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)21), HostAndCount(Scan(bytes)));
    }

    // A non-zero offset makes it a bundle whatever else is there: the placeholder does not turn it into a template.
    [Fact]
    public void HashAndScan_NonZeroOffsetAndThePlaceholder_IsStillSingleFileBundle()
    {
        var bytes = Image(8192, signatureAt: 1000, headerOffset: 5000);
        Header(bytes, 5000, major: 6, minor: 0, count: 3);
        Placeholder.CopyTo(bytes, 2000);

        var (_, host, bundled) = Scan(bytes);

        Assert.Equal(DotNetHost.SingleFileBundle, host);
        Assert.Equal(3, bundled);
    }

    // The header ends exactly at EOF: the last offset that still fits 12 bytes.
    [Fact]
    public void HashAndScan_HeaderEndingExactlyAtEndOfFile_IsRead()
    {
        const int length = 4096;
        var bytes = Image(length, signatureAt: 1000, headerOffset: length - 12);
        Header(bytes, length - 12, major: 6, minor: 0, count: 7);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)7), HostAndCount(Scan(bytes)));
    }

    // Offsets that cannot hold a 12-byte header: negative, one byte too far, at EOF, far past EOF, long.MinValue/MaxValue.
    [Theory]
    [InlineData(-1L)]
    [InlineData(-12L)]
    [InlineData(long.MinValue)]
    [InlineData(4096L - 11)]
    [InlineData(4096L)]
    [InlineData(1L << 40)]
    [InlineData(long.MaxValue)]
    public void HashAndScan_OffsetOutsideTheFile_IsSingleFileBundleWithNoCount(long headerOffset)
    {
        var bytes = Image(4096, signatureAt: 1000, headerOffset: headerOffset);
        // Plausible header bytes right up to EOF, so only the offset check can reject it.
        Header(bytes, 4096 - 12, major: 6, minor: 0, count: 5);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)null), HostAndCount(Scan(bytes)));
    }

    [Theory]
    [InlineData(0u, 5)]                 // major below 1
    [InlineData(65u, 5)]                // major above 64
    [InlineData(uint.MaxValue, 5)]      // major as a negative i32 would be -1
    [InlineData(6u, -1)]                // negative count
    [InlineData(6u, int.MinValue)]
    [InlineData(6u, 1_000_001)]         // count above 1e6
    [InlineData(6u, int.MaxValue)]
    public void HashAndScan_ImplausibleHeader_IsSingleFileBundleWithNoCount(uint major, int count)
    {
        var bytes = Image(8192, signatureAt: 1000, headerOffset: 5000);
        Header(bytes, 5000, major, minor: 0, count);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)null), HostAndCount(Scan(bytes)));
    }

    [Theory]
    [InlineData(1u, 0)]
    [InlineData(64u, 0)]
    [InlineData(1u, 1_000_000)]
    [InlineData(64u, 1)]
    public void HashAndScan_HeaderAtThePlausibilityBounds_KeepsItsCount(uint major, int count)
    {
        var bytes = Image(8192, signatureAt: 1000, headerOffset: 5000);
        Header(bytes, 5000, major, minor: 99, count);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)count), HostAndCount(Scan(bytes)));
    }

    // The FIRST signature decides: a later one with a non-zero offset does not turn an apphost into a bundle.
    [Fact]
    public void HashAndScan_TwoSignatures_TheFirstDecides()
    {
        var bytes = Image(8192, signatureAt: 1000, headerOffset: 0);
        Put(bytes, 4000, headerOffset: 6000);
        Header(bytes, 6000, major: 6, minor: 0, count: 9);

        Assert.Equal(DotNetHost.AppHost, Scan(bytes).Host);
    }

    [Fact]
    public void HashAndScan_SignatureAsTheLastBytesOfTheFile_IsFound()
    {
        const int length = 4096;
        var bytes = Image(length, signatureAt: length - 32, headerOffset: 0);

        Assert.Equal(DotNetHost.AppHost, Scan(bytes).Host);
    }
    #endregion

    #region Methods: a signature too close to the start for an offset
    // Fewer than 8 bytes before the signature: no offset to read, so it is treated as zero (never an out-of-range read).
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    public void HashAndScan_SignatureBeforePosition8_IsAppHost(int at)
    {
        var bytes = new byte[4096];
        bytes.AsSpan(0, at).Fill(0xFF);                 // non-zero bytes there must not be read as an offset
        Signature.CopyTo(bytes, at);

        Assert.Equal((DotNetHost.AppHost, (int?)null), HostAndCount(Scan(bytes)));
    }

    [Fact]
    public void HashAndScan_SignatureBeforePosition8WithThePlaceholder_IsHostTemplate()
    {
        var bytes = new byte[4096];
        Signature.CopyTo(bytes, 3);
        Placeholder.CopyTo(bytes, 1000);

        Assert.Equal(DotNetHost.HostTemplate, Scan(bytes).Host);
    }

    // At exactly 8 the offset is the file's first 8 bytes.
    [Fact]
    public void HashAndScan_SignatureAtPosition8_ReadsTheOffsetFromTheFirst8Bytes()
    {
        var bytes = Image(4096, signatureAt: 8, headerOffset: 2000);
        Header(bytes, 2000, major: 6, minor: 0, count: 4);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)4), HostAndCount(Scan(bytes)));
    }
    #endregion

    #region Methods: the 1 MiB read boundary and its carry
    // Every split of the 32-byte signature across the first read boundary, plus fully before / fully after it.
    [Theory]
    [MemberData(nameof(SignatureSplits))]
    public void HashAndScan_SignatureAcrossTheFirstReadBoundary_IsFound(int bytesBeforeBoundary)
    {
        var at = Mib - bytesBeforeBoundary;
        var bytes = Image(Mib + 4096, signatureAt: at, headerOffset: 0);

        Assert.Equal(DotNetHost.AppHost, Scan(bytes).Host);
    }

    public static TheoryData<int> SignatureSplits() => [0, 1, 2, 8, 16, 31, 32, 33, 40, 63];

    // The 64-byte placeholder is longer than the 63-byte carry: every split of it must still be found.
    [Theory]
    [MemberData(nameof(PlaceholderSplits))]
    public void HashAndScan_PlaceholderAcrossTheFirstReadBoundary_IsFound(int bytesBeforeBoundary)
    {
        var bytes = new byte[Mib + 4096];
        Placeholder.CopyTo(bytes, Mib - bytesBeforeBoundary);

        Assert.Equal(DotNetHost.HostTemplate, Scan(bytes).Host);
    }

    public static TheoryData<int> PlaceholderSplits() => [0, 1, 2, 31, 32, 62, 63, 64, 65];

    // The offset before the signature straddles the boundary and is non-zero: the bundle is still classified and read.
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(7)]
    public void HashAndScan_OffsetAcrossTheFirstReadBoundary_IsReadWhole(int offsetBytesBeforeBoundary)
    {
        var at = Mib - offsetBytesBeforeBoundary + 8;
        var bytes = Image(Mib + 8192, signatureAt: at, headerOffset: Mib + 4096);
        Header(bytes, Mib + 4096, major: 6, minor: 0, count: 118);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)118), HostAndCount(Scan(bytes)));
    }

    // The second boundary (2 MiB), reached through a window that began with the first read's carry.
    [Fact]
    public void HashAndScan_MarkersAcrossTheSecondReadBoundary_AreFound()
    {
        var signature = Image(2 * Mib + 4096, signatureAt: 2 * Mib - 20, headerOffset: 0);
        Assert.Equal(DotNetHost.AppHost, Scan(signature).Host);

        var placeholder = new byte[2 * Mib + 4096];
        Placeholder.CopyTo(placeholder, 2 * Mib - 40);
        Assert.Equal(DotNetHost.HostTemplate, Scan(placeholder).Host);
    }

    // Megabytes in, as in a singlefilehost-based bundle (~7 MB): the whole file is searched, and the position is exact.
    [Fact]
    public void HashAndScan_SignatureSeveralMiBIn_IsFoundAndItsOffsetRead()
    {
        var length = 7 * Mib + 333;
        var at = 6 * Mib + 12345;
        var bytes = Image(length, signatureAt: at, headerOffset: 7 * Mib);
        Header(bytes, 7 * Mib, major: 6, minor: 0, count: 83);

        Assert.Equal((DotNetHost.SingleFileBundle, (int?)83), HostAndCount(Scan(bytes)));
    }

    // A stream that returns short reads: windows smaller than the carry, many boundaries; the result must not change.
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(64)]
    [InlineData(4093)]
    public void HashAndScan_ShortReads_FindTheSameMarkersAndHash(int chunk)
    {
        var bytes = Image(64 * 1024, signatureAt: 9001, headerOffset: 40000);
        Header(bytes, 40000, major: 6, minor: 0, count: 12);
        Placeholder.CopyTo(bytes, 30001);

        using var trickle = new TrickleStream(bytes, chunk);
        var result = DotNetHostScanner.HashAndScan(trickle);

        Assert.Equal((Sha256(bytes), DotNetHost.SingleFileBundle, (int?)12), result);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(33)]
    public void HashAndScan_ShortReads_FindAZeroOffsetSignatureAndThePlaceholder(int chunk)
    {
        var bytes = Image(16 * 1024, signatureAt: 777, headerOffset: 0);
        using (var trickle = new TrickleStream(bytes, chunk))
            Assert.Equal(DotNetHost.AppHost, DotNetHostScanner.HashAndScan(trickle).Host);

        Placeholder.CopyTo(bytes, 5555);
        using (var trickle = new TrickleStream(bytes, chunk))
            Assert.Equal(DotNetHost.HostTemplate, DotNetHostScanner.HashAndScan(trickle).Host);
    }
    #endregion

    #region Methods: the hash
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(Mib - 1)]
    [InlineData(Mib)]
    [InlineData(Mib + 1)]
    [InlineData(Mib + 63)]
    [InlineData(2 * Mib)]
    [InlineData(3 * Mib + 17)]
    public void HashAndScan_Hash_EqualsSha256OfTheSameBytes(int size)
    {
        var bytes = Noise(size, seed: size);

        var (sha, _, _) = Scan(bytes);

        Assert.Equal(Sha256(bytes), sha);
        Assert.Matches("^[0-9a-f]{64}$", sha);
    }

    // The hash covers every byte once, with markers in the file too (the carry is never hashed twice).
    [Fact]
    public void HashAndScan_Hash_WithMarkersAcrossBoundaries_EqualsSha256()
    {
        var bytes = Image(3 * Mib + 5, signatureAt: Mib - 10, headerOffset: 3 * Mib - 100);
        Header(bytes, 3 * Mib - 100, major: 6, minor: 0, count: 2);
        Placeholder.CopyTo(bytes, 2 * Mib - 30);

        var (sha, host, bundled) = Scan(bytes);

        Assert.Equal(Sha256(bytes), sha);
        Assert.Equal((DotNetHost.SingleFileBundle, (int?)2), (host, bundled));
    }
    #endregion

    #region Methods: the stream's starting position
    // The scanner starts from 0 whatever the caller left the position at (a header probe usually leaves it mid-file).
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5000)]
    [InlineData(-1)]   // at EOF
    public void HashAndScan_TheStreamsStartingPosition_IsIrrelevant(int position)
    {
        var bytes = Image(8192, signatureAt: 1000, headerOffset: 5000);
        Header(bytes, 5000, major: 6, minor: 0, count: 118);
        using var stream = new MemoryStream(bytes, writable: false);
        stream.Position = position < 0 ? stream.Length : position;

        var result = DotNetHostScanner.HashAndScan(stream);

        Assert.Equal((Sha256(bytes), DotNetHost.SingleFileBundle, (int?)118), result);
    }

    // Scanning the same stream twice gives the same answer (no state survives a call).
    [Fact]
    public void HashAndScan_Twice_GivesTheSameAnswer()
    {
        var bytes = Image(8192, signatureAt: 1000, headerOffset: 0);
        using var stream = new MemoryStream(bytes, writable: false);

        Assert.Equal(DotNetHostScanner.HashAndScan(stream), DotNetHostScanner.HashAndScan(stream));
    }
    #endregion

    #region Methods: the markers themselves
    // The placeholder is SHA-256("foobar") in lowercase hex, which is what the SDK writes into the unpatched slot.
    [Fact]
    public void ThePlaceholder_IsTheHexSha256OfFoobar()
    {
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData("foobar"u8)), Encoding.ASCII.GetString(Placeholder));
    }
    #endregion

    #region Methods: the real SDK AppHostTemplate
    // Every installed SDK's AppHostTemplate/apphost.exe is the unpatched host: signature with offset 0 AND the placeholder.
    [SdkAppHostTemplateFact]
    public void HashAndScan_RealSdkAppHostTemplates_AreHostTemplate()
    {
        foreach (var path in SdkAppHostTemplateFactAttribute.Templates())
        {
            var bytes = File.ReadAllBytes(path);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);

            var (sha, host, bundled) = DotNetHostScanner.HashAndScan(stream);

            Assert.True(host == DotNetHost.HostTemplate, $"{path}: {host}");
            Assert.Null(bundled);
            Assert.Equal(Sha256(bytes), sha);
        }
    }

    // The same template with its placeholder overwritten (as the SDK patches it with the app's dll name) is an AppHost.
    [SdkAppHostTemplateFact]
    public void HashAndScan_RealSdkAppHostTemplate_WithThePlaceholderPatched_IsAppHost()
    {
        foreach (var path in SdkAppHostTemplateFactAttribute.Templates())
        {
            var bytes = File.ReadAllBytes(path);
            var slot = bytes.AsSpan().IndexOf(Placeholder);
            Assert.True(slot >= 0, $"{path}: no placeholder");
            var name = new byte[Placeholder.Length];
            "MyTool.dll"u8.CopyTo(name);
            name.CopyTo(bytes, slot);

            Assert.True(Scan(bytes).Host == DotNetHost.AppHost, $"{path}: {Scan(bytes).Host}");
        }
    }
    #endregion

    #region Methods: helpers
    private static (string Sha256, DotNetHost Host, int? BundledFiles) Scan(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        return DotNetHostScanner.HashAndScan(stream);
    }

    private static (DotNetHost, int?) HostAndCount((string Sha256, DotNetHost Host, int? BundledFiles) r) => (r.Host, r.BundledFiles);

    // A zeroed image of `length` bytes with the signature at `signatureAt` and the 8-byte LE offset just before it.
    internal static byte[] Image(int length, int signatureAt, long headerOffset)
    {
        var bytes = new byte[length];
        Put(bytes, signatureAt, headerOffset);
        return bytes;
    }

    internal static void Put(byte[] bytes, int signatureAt, long headerOffset)
    {
        Signature.CopyTo(bytes, signatureAt);
        if (signatureAt >= 8)
            BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(signatureAt - 8), headerOffset);
    }

    // The bundle header's first three fields: major u32, minor u32, file count i32.
    internal static void Header(byte[] bytes, int at, uint major, uint minor, int count)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), major);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at + 4), minor);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(at + 8), count);
    }

    private static byte[] Noise(int size, int seed)
    {
        var bytes = new byte[size];
        new Random(seed).NextBytes(bytes);
        Assert.True(bytes.AsSpan().IndexOf(Signature) < 0 && bytes.AsSpan().IndexOf(Placeholder) < 0);
        return bytes;
    }

    private static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    #endregion

    #region Fields
    private const int Mib = 1 << 20;

    // The host bundle signature as measured in SDK AppHostTemplate/apphost.exe 3.1-10.0 (see the spec).
    internal static readonly byte[] Signature = Convert.FromHexString("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae");

    // The unpatched app-path slot.
    internal static readonly byte[] Placeholder = Encoding.ASCII.GetBytes("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2");
    #endregion

    #region Nested types
    /// <summary>A seekable read-only stream whose Read returns at most <c>chunk</c> bytes.</summary>
    private sealed class TrickleStream(byte[] bytes, int chunk) : MemoryStream(bytes, writable: false)
    {
        public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, chunk));

        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(buffer.Length, chunk)]);
    }
    #endregion
}

/// <summary>Skips unless at least one SDK <c>AppHostTemplate\apphost.exe</c> is installed (read-only use).</summary>
internal sealed class SdkAppHostTemplateFactAttribute : FactAttribute
{
    public SdkAppHostTemplateFactAttribute()
    {
        if (!Templates().Any())
            Skip = "No .NET SDK AppHostTemplate/apphost.exe found under the dotnet root.";
    }

    internal static string[] Templates()
    {
        var root = Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } r && Directory.Exists(Path.Combine(r, "sdk"))
            ? r
            : OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet")
            : "/usr/share/dotnet";
        var sdk = Path.Combine(root, "sdk");
        return !Directory.Exists(sdk) ? []
            : [.. Directory.EnumerateDirectories(sdk)
                .Select(d => Path.Combine(d, "AppHostTemplate", "apphost.exe"))
                .Where(File.Exists)
                .Order(StringComparer.Ordinal)];
    }
}
