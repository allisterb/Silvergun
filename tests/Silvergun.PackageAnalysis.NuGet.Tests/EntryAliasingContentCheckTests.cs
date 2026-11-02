namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

using Silvergun;

using Xunit;

using static EntryAliasingSupport;

/// <summary>
/// <c>docs/agent/tasks/entry-aliasing-coverage.md</c> <b>Review 7</b>, closed by <b>S8</b> (ADR 0036): the bytes we
/// scan must be the bytes NuGet installs. RecursiveExtractor reads each record through SharpCompress, which takes the
/// name, compression method and sizes from the record's LOCAL header and honours the Info-ZIP Unicode Path extra field
/// (0x7075). NuGet and <see cref="ZipArchive"/> read the CENTRAL directory. A crafted archive can make the two disagree,
/// and no name-based rule can see that. Measured by the reviewer on both platforms (scratchpad <c>s13a-probe</c> /
/// <c>s13w-pkgs</c>, built by <c>s13-rawzip.py</c> and <c>s13-upath.py</c>), each with <c>lost=[]</c> and
/// <c>--strict</c> exit 0 before S8:
/// <list type="bullet">
/// <item><b>C1</b>, <c>g-lhname-dupalias</c>: <c>W</c> (the hook), then <c>X</c> (a decoy) twice, byte-identical to
/// ZipArchive, but the second <c>X</c> record's local name is <c>W</c>. The extractor writes the decoy over <c>W</c>,
/// and NuGet installs <c>W</c> = the hook. <c>h-upath-dupalias</c> does the same through a 0x7075 field naming
/// <c>W</c>, with the local name left as <c>X</c>.</item>
/// <item><b>C2</b>, <c>g-method-sole</c>: one entry whose central directory says deflate and whose local header says
/// stored, so the extractor writes the raw deflate bytes; also with four bytes appended to that stream forcing its CRC32
/// to the hook's, so only a content hash (never a CRC32) can tell the two apart. <c>g-size-sole</c>: one stored entry
/// whose local header gives a shorter size, so the extractor writes a truncated file. Either way NuGet installs the
/// hook.</item>
/// </list>
/// Each must now be LOST, so the package is incomplete (<c>--strict</c> exits 3). <b>Controls</b>, not lost:
/// <c>g-samelh</c> (two central-directory records pointing at ONE local header, so both readers agree) and
/// byte-identical duplicates, including one stored copy and one deflated copy.
///
/// <para>The zips are built byte by byte by <see cref="RawZip"/> (no tool can write these shapes). Every on-disk
/// statement is asserted before the verdict, so a test cannot pass vacuously against an extractor that stopped
/// diverging. Every shape runs on both platforms; only the real-CLI child process is Windows-only (the
/// <c>net10.0-windows</c> build carries the CLI). Content is benign: the hook is <see cref="PackageFixture.MaliciousTargets"/>
/// (a certutil token against <c>malicious.example</c>) where the reviewer's probe had a webhook URL, and the decoy an
/// empty project.</para>
/// </summary>
public sealed class EntryAliasingContentCheckTests : IClassFixture<ContentCheckPackageFixture>
{
    #region Constructors
    public EntryAliasingContentCheckTests(ContentCheckPackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: C1, a duplicate whose second record writes another entry's file (every platform)
    // NuGet's view first (ZipArchive: W is the hook, both X copies the decoy), then the extractor's (the decoy over W).
    // X's first occurrence holds X's bytes, so X passes; W's file holds the decoy, so W is the one entry lost.
    [Fact]
    public void OpenAndScan_ForADuplicateWhoseLocalHeaderNamesAnotherEntry_ReportTheOverwrittenEntryLost()
    {
        AssertDuplicateAliasLosesW(fixture.LocalNameDuplicateAliasPath);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OpenAndScan_ForADuplicateWhoseUnicodePathFieldNamesAnotherEntry_ReportTheOverwrittenEntryLost(bool utf8Flag)
    {
        AssertDuplicateAliasLosesW(utf8Flag ? fixture.UnicodePathDuplicateAliasUtf8Path : fixture.UnicodePathDuplicateAliasPath);
    }

    // The same local-name divergence without a duplicate: Z's record writes W. W fails its check, Z claims nothing.
    [Fact]
    public void Open_ForALoneRecordWhoseLocalHeaderNamesAnotherEntry_ReportsBothNamesLost()
    {
        using var pkg = Open(fixture.LocalNameOverAnotherEntryPath);

        Assert.Equal([ContentCheckPackageFixture.WEntry], BuildFiles(pkg));
        Assert.Equal(EntryAliasPackageFixture.DecoyTargets, File.ReadAllText(Path.Combine(pkg.ContentRoot, "build", "W.targets")));
        Assert.Equal([ContentCheckPackageFixture.WEntry, ContentCheckPackageFixture.ZEntry], pkg.UninventoriedEntryNames);
    }
    #endregion

    #region Methods: C2, a sole entry the extractor writes with other bytes (every platform)
    // The local header says stored, so the extractor writes the raw deflate stream; ZipArchive inflates it to the hook.
    [Fact]
    public void OpenAndScan_ForAnEntryWhoseLocalHeaderSaysStoredWhereTheCentralDirectorySaysDeflate_ReportItLost()
    {
        AssertNuGetSees(fixture.MethodMismatchPath, EntryAliasPackageFixture.TargetsEntry, Hook);

        using (var pkg = Open(fixture.MethodMismatchPath))
        {
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], BuildFiles(pkg));
            Assert.Equal(fixture.DeflatedHook, File.ReadAllBytes(Path.Combine(pkg.ContentRoot, "build", "Some.Package.targets")));
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.MethodMismatchPath);
        AssertNotInventoriedRows(scan, (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build));
        Assert.Empty(scan.ScriptFindings);
    }

    // The same, with a second copy: ZipArchive sees two identical hooks, the extractor writes the raw stream last.
    [Fact]
    public void Open_ForAnIdenticalDuplicateWhoseSecondLocalHeaderSaysStored_ReportsTheNameLost()
    {
        using var pkg = Open(fixture.MethodMismatchDuplicatePath);

        Assert.Equal(fixture.DeflatedHook, File.ReadAllBytes(Path.Combine(pkg.ContentRoot, "build", "Some.Package.targets")));
        Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.UninventoriedEntryNames);
    }

    // The method divergence with the CRC forged: the file on disk is not the hook, yet its CRC32 is the hook's, which is
    // also the central directory's CRC32 of what NuGet installs. Any CRC32 identity reads the two as one; SHA-256 does not
    // (ADR 0036: "never use the central-directory CRC32 or sizes as identity").
    [Fact]
    public void OpenAndScan_ForAStoredLocalHeaderWhoseBytesAreForgedToTheHooksCrc32_ReportItLost()
    {
        AssertNuGetSees(fixture.MethodMismatchCrcForgedPath, EntryAliasPackageFixture.TargetsEntry, Hook);
        using (var zip = ZipFile.OpenRead(fixture.MethodMismatchCrcForgedPath))
            Assert.Equal(Crc32Forge.Compute(Hook), zip.Entries.Single(e => e.FullName == EntryAliasPackageFixture.TargetsEntry).Crc32);

        using (var pkg = Open(fixture.MethodMismatchCrcForgedPath))
        {
            var onDisk = File.ReadAllBytes(Path.Combine(pkg.ContentRoot, "build", "Some.Package.targets"));
            Assert.Equal(fixture.ForgedDeflatedHook, onDisk);
            Assert.NotEqual(Hook, onDisk);
            Assert.Equal(Crc32Forge.Compute(Hook), Crc32Forge.Compute(onDisk));
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.MethodMismatchCrcForgedPath);
        AssertNotInventoriedRows(scan, (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build));
        Assert.Empty(scan.ScriptFindings);
    }

    // A stored entry whose local header gives 11 bytes: the extractor writes the hook's first 11 bytes.
    [Fact]
    public void OpenAndScan_ForAnEntryWhoseLocalHeaderGivesAShorterSize_ReportItLost()
    {
        AssertNuGetSees(fixture.SizeMismatchPath, EntryAliasPackageFixture.TargetsEntry, Hook);

        using (var pkg = Open(fixture.SizeMismatchPath))
        {
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], BuildFiles(pkg));
            Assert.Equal(Hook[..ContentCheckPackageFixture.ShortSize], File.ReadAllBytes(Path.Combine(pkg.ContentRoot, "build", "Some.Package.targets")));
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.SizeMismatchPath);
        AssertNotInventoriedRows(scan, (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build));
        Assert.Empty(scan.ScriptFindings);
    }
    #endregion

    #region Methods: controls, where the two readers agree (every platform)
    // Two central-directory records, one local header: ZipArchive sees the hook twice, the extractor writes it once.
    [Fact]
    public void OpenAndScan_ForTwoCentralRecordsSharingOneLocalHeader_LoseNothingAndReportTheHooksFindings()
    {
        using (var zip = ZipFile.OpenRead(fixture.SharedLocalHeaderPath))
            Assert.Equal(2, zip.Entries.Count(e => e.FullName == EntryAliasPackageFixture.TargetsEntry));

        AssertHookScannedAndNothingLost(fixture.SharedLocalHeaderPath);
    }

    [Fact]
    public void OpenAndScan_ForAByteIdenticalDuplicate_LoseNothingAndReportTheHooksFindings()
    {
        AssertHookScannedAndNothingLost(fixture.IdenticalDuplicatePath);
    }

    // The comparison is on DECOMPRESSED bytes: a stored copy and a deflated copy of the same hook are identical.
    [Fact]
    public void OpenAndScan_ForAByteIdenticalDuplicateStoredOnceAndDeflatedOnce_LoseNothingAndReportTheHooksFindings()
    {
        AssertHookScannedAndNothingLost(fixture.IdenticalMixedMethodPath);
    }
    #endregion

#if WINDOWS
    #region Methods: the real CLI, end to end (net10.0-windows carries the CLI)
    [Fact]
    public void ScanPackageCli_ForADuplicateWhoseLocalHeaderNamesAnotherEntry_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.LocalNameDuplicateAliasPath, ContentCheckPackageFixture.WEntry);
    }

    [Fact]
    public void ScanPackageCli_ForADuplicateWhoseUnicodePathFieldNamesAnotherEntry_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.UnicodePathDuplicateAliasPath, ContentCheckPackageFixture.WEntry);
    }

    [Fact]
    public void ScanPackageCli_ForAnEntryWhoseLocalHeaderSaysStored_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.MethodMismatchPath, EntryAliasPackageFixture.TargetsEntry);
    }

    [Fact]
    public void ScanPackageCli_ForAnEntryWhoseLocalHeaderGivesAShorterSize_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.SizeMismatchPath, EntryAliasPackageFixture.TargetsEntry);
    }
    #endregion
#endif

    #region Methods: helpers
    private static byte[] Hook => Encoding.UTF8.GetBytes(PackageFixture.MaliciousTargets);

    private static void AssertDuplicateAliasLosesW(string nupkgPath)
    {
        AssertNuGetSees(nupkgPath, ContentCheckPackageFixture.WEntry, Hook);
        using (var zip = ZipFile.OpenRead(nupkgPath))
            Assert.Equal(2, zip.Entries.Count(e => e.FullName == ContentCheckPackageFixture.XEntry));

        using (var pkg = Open(nupkgPath))
        {
            Assert.Equal([ContentCheckPackageFixture.WEntry, ContentCheckPackageFixture.XEntry], BuildFiles(pkg));
            Assert.Equal(EntryAliasPackageFixture.DecoyTargets, File.ReadAllText(Path.Combine(pkg.ContentRoot, "build", "W.targets")));
            Assert.Equal(EntryAliasPackageFixture.DecoyTargets, File.ReadAllText(Path.Combine(pkg.ContentRoot, "build", "X.targets")));
            Assert.Equal([ContentCheckPackageFixture.WEntry], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(nupkgPath);
        AssertNotInventoriedRows(scan, (ContentCheckPackageFixture.WEntry, PackageItemRole.Build));
        Assert.Empty(scan.ScriptFindings);
    }

    // NuGet's view, through ZipArchive: the FIRST central-directory entry of `name` decompresses to `bytes`.
    private static void AssertNuGetSees(string nupkgPath, string name, byte[] bytes)
    {
        using var zip = ZipFile.OpenRead(nupkgPath);
        using var stream = zip.Entries.First(e => e.FullName == name).Open();
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        Assert.Equal(bytes, buffer.ToArray());
    }

    private static void AssertHookScannedAndNothingLost(string nupkgPath)
    {
        AssertNuGetSees(nupkgPath, EntryAliasPackageFixture.TargetsEntry, Hook);

        using (var pkg = Open(nupkgPath))
        {
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], BuildFiles(pkg));
            Assert.Equal(Hook, File.ReadAllBytes(Path.Combine(pkg.ContentRoot, "build", "Some.Package.targets")));
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(nupkgPath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.TargetsEntry);
        Assert.DoesNotContain(scan.Assemblies, a => a.SkipReason is not null);
        Assert.Equal(ScriptScanStatus.Completed, scan.ScriptScanStatus);
    }
    #endregion

    #region Fields
    private readonly ContentCheckPackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages review 7's probe shapes (<c>s13-rawzip.py</c>, <c>s13-upath.py</c>) for <see cref="EntryAliasingContentCheckTests"/>
/// with <see cref="RawZip"/>, the probe's webhook hook replaced by <see cref="PackageFixture.MaliciousTargets"/>.
/// </summary>
public sealed class ContentCheckPackageFixture : IDisposable
{
    #region Constructors
    public ContentCheckPackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-entry-alias", "content-check-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        const string t = EntryAliasPackageFixture.TargetsEntry;
        var hook = Encoding.UTF8.GetBytes(PackageFixture.MaliciousTargets);
        var decoy = Encoding.UTF8.GetBytes(EntryAliasPackageFixture.DecoyTargets);
        var nuspec = new RawZip.Entry("PkgRaw.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
            "PkgRaw", "1.0.0", "Silvergun Tests", "Reader-disagreement test package.", "net8.0", [])));
        DeflatedHook = RawZip.Deflate(hook);
        var crcOfDeflated = Crc32Forge.Compute(DeflatedHook);
        var size = (uint)DeflatedHook.Length;

        // g-lhname-dupalias, g-lhname-nondup.
        LocalNameDuplicateAliasPath = Write("LocalNameDuplicateAlias",
            [nuspec, new(WEntry, hook), new(XEntry, decoy), new(XEntry, decoy) { LocalName = WEntry }]);
        LocalNameOverAnotherEntryPath = Write("LocalNameOverAnotherEntry",
            [nuspec, new(WEntry, hook), new(ZEntry, decoy) { LocalName = WEntry }]);

        // h-upath-dupalias(-utf8): every record stored; the second X carries a 0x7075 field naming W in both headers.
        RawZip.Entry Stored(string name, byte[] data, ushort flags, string? unicodePath = null) =>
            new(name, data) { Method = 0, Flags = flags, Extra = unicodePath is null ? [] : RawZip.UnicodePathField(name, unicodePath) };
        UnicodePathDuplicateAliasPath = Write("UnicodePathDuplicateAlias",
            [Stored("PkgRaw.nuspec", nuspec.Data, 0), Stored(WEntry, hook, 0), Stored(XEntry, decoy, 0), Stored(XEntry, decoy, 0, WEntry)]);
        UnicodePathDuplicateAliasUtf8Path = Write("UnicodePathDuplicateAliasUtf8",
            [Stored("PkgRaw.nuspec", nuspec.Data, RawZip.Utf8Flag), Stored(WEntry, hook, RawZip.Utf8Flag),
             Stored(XEntry, decoy, RawZip.Utf8Flag), Stored(XEntry, decoy, RawZip.Utf8Flag, WEntry)]);

        // g-method-sole, g-method-dup: the central directory says deflate, the local header says stored (with the deflate
        // stream's own size and CRC, so the stored read is self-consistent).
        RawZip.Entry StoredLocally(byte[] data) =>
            new(t, data) { LocalMethod = 0, LocalCrc = crcOfDeflated, LocalCompressedSize = size, LocalUncompressedSize = size };
        MethodMismatchPath = Write("MethodMismatch", [nuspec, StoredLocally(hook)]);
        MethodMismatchDuplicatePath = Write("MethodMismatchDuplicate", [nuspec, new(t, hook), StoredLocally(hook)]);

        // g-method-sole with the CRC forged: four bytes after the deflate stream's final block (which the inflater never
        // reads) make the stored bytes' CRC32 the hook's, so a CRC32 of the disk file equals NuGet's (central) CRC32.
        ForgedDeflatedHook = Crc32Forge.Force(DeflatedHook, Crc32Forge.Compute(hook));
        var forgedSize = (uint)ForgedDeflatedHook.Length;
        MethodMismatchCrcForgedPath = Write("MethodMismatchCrcForged",
            [nuspec, new(t, hook)
            {
                Payload = ForgedDeflatedHook, LocalMethod = 0, LocalCrc = Crc32Forge.Compute(ForgedDeflatedHook),
                LocalCompressedSize = forgedSize, LocalUncompressedSize = forgedSize,
            }]);

        // g-size-sole: stored, and the local header gives a shorter size.
        SizeMismatchPath = Write("SizeMismatch",
            [nuspec, new(t, hook) { Method = 0, LocalCompressedSize = ShortSize, LocalUncompressedSize = ShortSize }]);

        // Controls: g-samelh, g-dup-ident, g-dup-ident-mixedmethod.
        SharedLocalHeaderPath = Write("SharedLocalHeader", [nuspec, new(t, hook)], centralDirectory: [0, 1, 1]);
        IdenticalDuplicatePath = Write("IdenticalDuplicate", [nuspec, new(t, hook), new(t, hook)]);
        IdenticalMixedMethodPath = Write("IdenticalMixedMethod", [nuspec, new(t, hook) { Method = 0 }, new(t, hook)]);
    }
    #endregion

    #region Properties
    /// <summary>The entry the aliasing record writes over: it holds the hook in NuGet's view.</summary>
    public const string WEntry = "build/W.targets";

    /// <summary>The duplicated decoy entry.</summary>
    public const string XEntry = "build/X.targets";

    /// <summary>A lone decoy entry whose local header names <see cref="WEntry"/>.</summary>
    public const string ZEntry = "build/Z.targets";

    /// <summary>The size the short local header gives.</summary>
    public const int ShortSize = 11;

    public string LocalNameDuplicateAliasPath { get; }
    public string LocalNameOverAnotherEntryPath { get; }
    public string UnicodePathDuplicateAliasPath { get; }
    public string UnicodePathDuplicateAliasUtf8Path { get; }
    public string MethodMismatchPath { get; }
    public string MethodMismatchDuplicatePath { get; }
    public string MethodMismatchCrcForgedPath { get; }
    public string SizeMismatchPath { get; }
    public string SharedLocalHeaderPath { get; }
    public string IdenticalDuplicatePath { get; }
    public string IdenticalMixedMethodPath { get; }

    /// <summary>The hook's raw deflate stream: what a stored-in-the-local-header read writes to disk.</summary>
    public byte[] DeflatedHook { get; }

    /// <summary><see cref="DeflatedHook"/> plus four bytes forcing its CRC32 to the hook's.</summary>
    public byte[] ForgedDeflatedHook { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        try
        {
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    private string Write(string name, RawZip.Entry[] entries, int[]? centralDirectory = null)
    {
        var path = Path.Combine(rootDir, $"{name}.1.0.0.nupkg");
        RawZip.Write(path, entries, centralDirectory);
        return path;
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}

/// <summary>
/// Writes a zip byte by byte, so the local header of a record can disagree with its central-directory record (the name,
/// the compression method, the CRC32 or the sizes), several central records can point at one local header, and an
/// extra field can be added to both. Mirrors the reviewer's <c>s13-rawzip.py</c> / <c>s13-upath.py</c>; every field not
/// overridden is what a well-formed zip would hold.
/// </summary>
internal static class RawZip
{
    #region Methods
    /// <summary>
    /// Writes the local records in order, then the central directory: one record per local record by default, or one per
    /// index in <paramref name="centralDirectory"/> (an index may repeat).
    /// </summary>
    public static void Write(string path, IReadOnlyList<Entry> entries, IReadOnlyList<int>? centralDirectory = null)
    {
        using var buffer = new MemoryStream();
        using var w = new BinaryWriter(buffer);
        var offsets = new List<uint>();
        var payloads = entries.Select(e => e.Payload ?? (e.Method == 0 ? e.Data : Deflate(e.Data))).ToArray();

        foreach (var (e, payload) in entries.Zip(payloads))
        {
            offsets.Add((uint)buffer.Position);
            var name = Encoding.UTF8.GetBytes(e.LocalName ?? e.Name);
            w.Write(0x04034B50u);
            w.Write((ushort)20);
            w.Write(e.Flags);
            w.Write(e.LocalMethod ?? e.Method);
            w.Write((ushort)0);
            w.Write(DosDate);
            w.Write(e.LocalCrc ?? Crc32Forge.Compute(e.Data));
            w.Write(e.LocalCompressedSize ?? (uint)payload.Length);
            w.Write(e.LocalUncompressedSize ?? (uint)e.Data.Length);
            w.Write((ushort)name.Length);
            w.Write((ushort)e.Extra.Length);
            w.Write(name);
            w.Write(e.Extra);
            w.Write(payload);
        }

        var central = centralDirectory ?? Enumerable.Range(0, entries.Count).ToArray();
        var centralStart = (uint)buffer.Position;
        foreach (var i in central)
        {
            var e = entries[i];
            var name = Encoding.UTF8.GetBytes(e.Name);
            w.Write(0x02014B50u);
            w.Write((ushort)20);
            w.Write((ushort)20);
            w.Write(e.Flags);
            w.Write(e.Method);
            w.Write((ushort)0);
            w.Write(DosDate);
            w.Write(Crc32Forge.Compute(e.Data));
            w.Write((uint)payloads[i].Length);
            w.Write((uint)e.Data.Length);
            w.Write((ushort)name.Length);
            w.Write((ushort)e.Extra.Length);
            w.Write((ushort)0);   // comment length
            w.Write((ushort)0);   // disk number start
            w.Write((ushort)0);   // internal attributes
            w.Write(0u);          // external attributes
            w.Write(offsets[i]);
            w.Write(name);
            w.Write(e.Extra);
        }

        var centralSize = (uint)buffer.Position - centralStart;
        w.Write(0x06054B50u);
        w.Write((ushort)0);
        w.Write((ushort)0);
        w.Write((ushort)central.Count);
        w.Write((ushort)central.Count);
        w.Write(centralSize);
        w.Write(centralStart);
        w.Write((ushort)0);
        w.Flush();
        File.WriteAllBytes(path, buffer.ToArray());
    }

    /// <summary>A raw (headerless) deflate stream of <paramref name="data"/>, as a zip stores it.</summary>
    public static byte[] Deflate(byte[] data)
    {
        using var buffer = new MemoryStream();
        using (var deflate = new DeflateStream(buffer, CompressionLevel.Optimal, leaveOpen: true))
            deflate.Write(data);
        return buffer.ToArray();
    }

    /// <summary>
    /// An Info-ZIP Unicode Path extra field (0x7075): version 1, the CRC32 of the header's own name bytes (which a reader
    /// checks before honouring it), then the UTF-8 name it substitutes.
    /// </summary>
    public static byte[] UnicodePathField(string headerName, string unicodeName)
    {
        var name = Encoding.UTF8.GetBytes(unicodeName);
        using var buffer = new MemoryStream();
        using var w = new BinaryWriter(buffer);
        w.Write((ushort)0x7075);
        w.Write((ushort)(1 + 4 + name.Length));
        w.Write((byte)1);
        w.Write(Crc32Forge.Compute(Encoding.UTF8.GetBytes(headerName)));
        w.Write(name);
        w.Flush();
        return buffer.ToArray();
    }
    #endregion

    #region Fields
    /// <summary>General-purpose flag bit 11: the name is UTF-8.</summary>
    public const ushort Utf8Flag = 0x800;

    private const ushort DosDate = 0x5821;   // 2024-01-01
    #endregion

    #region Nested types
    /// <summary>
    /// One local record. <see cref="Data"/> is the PLAIN content, stored raw when <see cref="Method"/> is 0 and deflated
    /// when it is 8, unless <see cref="Payload"/> gives the record's bytes outright. <see cref="Method"/>,
    /// <see cref="Name"/>, the plain CRC32 and size, and the payload's length go to the central directory; the
    /// <c>Local*</c> properties override the local header only.
    /// </summary>
    public sealed record Entry(string Name, byte[] Data)
    {
        public byte[]? Payload { get; init; }
        public ushort Method { get; init; } = 8;
        public ushort Flags { get; init; } = Utf8Flag;
        public byte[] Extra { get; init; } = [];
        public string? LocalName { get; init; }
        public ushort? LocalMethod { get; init; }
        public uint? LocalCrc { get; init; }
        public uint? LocalCompressedSize { get; init; }
        public uint? LocalUncompressedSize { get; init; }
    }
    #endregion
}
