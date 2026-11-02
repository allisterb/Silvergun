namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using Silvergun;

using Xunit;

using static EntryAliasingSupport;

/// <summary>
/// <c>docs/agent/tasks/entry-aliasing-coverage.md</c>, <b>S8</b> (ADR 0036) as it applies to DUPLICATE names. A name
/// declared more than once is weighed once, at its first occurrence: that occurrence's extracted file must hold the
/// SHA-256 of the decompressed bytes of ZipArchive's FIRST entry of that name (what NuGet installs). The extractor
/// keeps the LAST copy, so copies that differ fail the check and the name is lost. Byte-identical copies pass:
/// 39 Microsoft 3.1.0-era packages in the local NuGet cache ship <c>packageIcon.png</c> twice, byte for byte. This
/// replaces S7's identical-duplicate exemption (<c>IdenticalDuplicateNames</c>, removed) and C3's "a duplicate is lost".
///
/// <para><b>What must still be lost</b> (fail-closed): copies of the same length with different bytes; copies whose
/// central-directory CRC32 and size agree but whose bytes differ (both fields are author-written, and a CRC32 collision
/// costs four appended bytes, forged here by <see cref="Crc32Forge"/>); and a first copy that cannot be read (a corrupt
/// deflate stream). The duplicates with different bytes in <see cref="EntryAliasingBackslashAndDuplicateTests"/> stay as
/// they were.</para>
///
/// <para><b>Measured, corrupt deflate streams (2026-11-01, Windows, this tree):</b> RecursiveExtractor does NOT fail the
/// package. It returns <c>Ok</c> and writes nothing for the corrupt copy: with the LAST copy corrupt the first copy's
/// bytes stay on disk, with the FIRST copy corrupt the last copy's bytes are on disk, with every copy (or a sole entry)
/// corrupt no file is written. So <see cref="NuGetPackage.Open"/> succeeds, and the verdict comes from the rule: a
/// corrupt first copy fails the content check (ZipArchive cannot read NuGet's bytes), and an entry with no file claims
/// nothing. A corrupt LAST copy is not lost, correctly: NuGet installs the first copy, which is what was scanned.</para>
///
/// <para>The read-error, missing-entry and missing-file clauses of <c>NuGetPackage.ContentMatchesNuGet</c> are also
/// asserted against the method directly (private, by reflection), since the last two cannot be staged through
/// <see cref="NuGetPackage.Open"/>. The shared byte budget (<c>MaxExtractedBytes</c>, 2 GiB per side) is NOT covered: it
/// is initialised from a <c>const</c>, so no test can shrink it, and an overrun cannot be staged end to end without a
/// fixture over 2 GiB, which the extractor's own 2 GiB cap and ratio cap refuse first.</para>
///
/// <para>Content is benign: the hook is <see cref="PackageFixture.MaliciousTargets"/> (a certutil token against
/// <c>malicious.example</c>), the decoy an empty project, everything else short plain text. Every shape runs on both
/// platforms, except that the real-package regression needs the package in the local NuGet cache.</para>
/// </summary>
public sealed class EntryAliasingIdenticalDuplicateTests : IClassFixture<IdenticalDuplicatePackageFixture>
{
    #region Constructors
    public EntryAliasingIdenticalDuplicateTests(IdenticalDuplicatePackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: byte-identical duplicates are not lost (every platform)
    [Fact]
    public void OpenAndScan_ForTwoByteIdenticalCopiesOfAContentFile_LoseNothingAndAreComplete()
    {
        using (var pkg = Open(fixture.IdenticalContentPath))
        {
            Assert.Equal(2, pkg.DeclaredEntryNames.Count(n => n == IdenticalDuplicatePackageFixture.TextEntry));
            Assert.Equal([IdenticalDuplicatePackageFixture.TextEntry], ContentFiles(pkg));
            Assert.Equal(IdenticalDuplicatePackageFixture.Text1, File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "x.txt")));
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        AssertComplete(Scan(fixture.IdenticalContentPath));
    }

    // The hook twice, byte for byte: NuGet installs the hook and the hook is what was scanned, so its findings are
    // reported and nothing is lost.
    [Fact]
    public void OpenAndScan_ForTwoByteIdenticalCopiesOfATargetsFile_LoseNothingAndReportTheHooksFindings()
    {
        AssertIdenticalHookScanned(fixture.IdenticalTargetsPath, copies: 2);
    }

    [Fact]
    public void OpenAndScan_ForThreeByteIdenticalCopiesOfATargetsFile_LoseNothingAndReportTheHooksFindings()
    {
        AssertIdenticalHookScanned(fixture.TriplicateIdenticalTargetsPath, copies: 3);
    }

    // The check is per name: an identical pair beside a differing pair loses only the differing one.
    [Fact]
    public void OpenAndScan_ForAnIdenticalPairBesideADifferingPair_ReportOnlyTheDifferingNameLost()
    {
        using (var pkg = Open(fixture.MixedDuplicatesPath))
            Assert.Equal([IdenticalDuplicatePackageFixture.OtherTextEntry], pkg.UninventoriedEntryNames);

        AssertNotInventoriedRows(Scan(fixture.MixedDuplicatesPath), (IdenticalDuplicatePackageFixture.OtherTextEntry, PackageItemRole.Content));
    }

    // Nor does it excuse anything else: the identical hook pair is followed by a drive-segment decoy, which the extractor
    // writes over the hook's file on both platforms. The decoy is what was scanned, so the targets name fails its
    // content check and the decoy claimed nothing: both are lost, in archive order.
    [Fact]
    public void OpenAndScan_ForAnIdenticalPairFollowedByADriveSegmentDecoy_ReportTheOverwrittenNameAndTheDecoyLost()
    {
        using (var pkg = Open(fixture.IdenticalPairThenDriveDecoyPath))
        {
            AssertTheTargetsFileHolds(pkg, EntryAliasPackageFixture.DecoyTargets);
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry, IdenticalDuplicatePackageFixture.DriveTargets], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.IdenticalPairThenDriveDecoyPath);
        AssertNotInventoriedRows(scan,
            (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build), (IdenticalDuplicatePackageFixture.DriveTargets, PackageItemRole.Other));
        Assert.Empty(scan.ScriptFindings);
    }

    // An escaping name is lost whatever its copies hold (Review 5): identical copies do not exempt it.
    [Fact]
    public void Open_ForTwoByteIdenticalCopiesOfAnEscapingName_StillReportsItLost()
    {
        using var pkg = Open(fixture.IdenticalRootedPath);

        Assert.Equal([IdenticalDuplicatePackageFixture.RootedTextEntry], pkg.UninventoriedEntryNames);
    }
    #endregion

    #region Methods: copies that differ are lost (every platform)
    [Fact]
    public void OpenAndScan_ForTwoSameLengthCopiesWithDifferentBytes_ReportTheNameLostOnce()
    {
        Assert.Equal(IdenticalDuplicatePackageFixture.Text1.Length, IdenticalDuplicatePackageFixture.Text2.Length);
        Assert.NotEqual(IdenticalDuplicatePackageFixture.Text1, IdenticalDuplicatePackageFixture.Text2);

        using (var pkg = Open(fixture.SameLengthDifferentPath))
        {
            Assert.Equal(IdenticalDuplicatePackageFixture.Text2, File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "x.txt")));
            Assert.Equal([IdenticalDuplicatePackageFixture.TextEntry], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.SameLengthDifferentPath), (IdenticalDuplicatePackageFixture.TextEntry, PackageItemRole.Content));
    }

    // The central directory is never trusted. The hook first (what NuGet installs), then a decoy forged to the hook's
    // exact length and CRC32: every field a CRC-and-size comparison would read agrees, the bytes do not. The decoy is
    // what the extractor left on disk and what was scanned (no findings), so the name must be lost.
    [Fact]
    public void OpenAndScan_ForCopiesWithTheSameCrc32AndSizeButDifferentBytes_ReportTheNameLost()
    {
        AssertCentralDirectoryAgreesButBytesDiffer(fixture.CrcCollisionTargetsPath, EntryAliasPackageFixture.TargetsEntry);

        using (var pkg = Open(fixture.CrcCollisionTargetsPath))
        {
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], BuildFiles(pkg));
            Assert.Equal(
                fixture.ForgedDecoy,
                File.ReadAllBytes(Path.Combine(pkg.ContentRoot, "build", "Some.Package.targets")));
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.CrcCollisionTargetsPath);
        AssertNotInventoriedRows(scan, (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build));
        Assert.Empty(scan.ScriptFindings);
    }
    #endregion

    #region Methods: corrupt deflate streams (every platform; measured, see the class remarks)
    // The first copy is NuGet's and unreadable: the extractor wrote the second copy's bytes, which may not be compared
    // with anything NuGet would install, so the name is lost (a read error is a mismatch).
    [Fact]
    public void OpenAndScan_ForADuplicateWhoseFirstCopyIsACorruptDeflateStream_ReportTheNameLost()
    {
        AssertOneCopyUnreadable(fixture.CorruptFirstCopyPath, unreadableIndex: 0);

        using (var pkg = Open(fixture.CorruptFirstCopyPath))
        {
            Assert.Equal([IdenticalDuplicatePackageFixture.TextEntry], ContentFiles(pkg));
            Assert.Equal(IdenticalDuplicatePackageFixture.Text1, File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "x.txt")));
            Assert.Equal([IdenticalDuplicatePackageFixture.TextEntry], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.CorruptFirstCopyPath), (IdenticalDuplicatePackageFixture.TextEntry, PackageItemRole.Content));
    }

    // The last copy is corrupt and the extractor writes nothing for it, so the first copy's bytes, which are NuGet's, stay
    // on disk and pass the check. Not lost, and correctly so: what was scanned is what NuGet installs.
    [Fact]
    public void Open_ForADuplicateWhoseLastCopyIsACorruptDeflateStream_KeepsTheFirstCopyAndLosesNothing()
    {
        AssertOneCopyUnreadable(fixture.CorruptLastCopyPath, unreadableIndex: 1);

        using var pkg = Open(fixture.CorruptLastCopyPath);

        Assert.Equal([IdenticalDuplicatePackageFixture.TextEntry], ContentFiles(pkg));
        Assert.Equal(IdenticalDuplicatePackageFixture.Text1, File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "x.txt")));
        Assert.Empty(pkg.UninventoriedEntryNames);
    }

    // Every copy corrupt: no file is written, so the name claims nothing.
    [Fact]
    public void Open_ForADuplicateWhoseEveryCopyIsACorruptDeflateStream_ReportsTheNameLost()
    {
        using var pkg = Open(fixture.CorruptBothCopiesPath);

        Assert.Empty(ContentFiles(pkg));
        Assert.Equal([IdenticalDuplicatePackageFixture.TextEntry], pkg.UninventoriedEntryNames);
    }

    // A sole corrupt entry: the extractor drops it silently (Ok), so it claims nothing and is lost, never clean.
    [Fact]
    public void OpenAndScan_ForASoleCorruptDeflateStream_ReportTheEntryLost()
    {
        using (var pkg = Open(fixture.CorruptSolePath))
        {
            Assert.Empty(ContentFiles(pkg));
            Assert.Equal([IdenticalDuplicatePackageFixture.TextEntry], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.CorruptSolePath), (IdenticalDuplicatePackageFixture.TextEntry, PackageItemRole.Content));
    }
    #endregion

    #region Methods: ContentMatchesNuGet directly (every platform)
    // NuGet is first-wins: the check reads the FIRST central-directory entry of a name, never a later one.
    [Fact]
    public void ContentMatchesNuGet_ForADifferingPair_MatchesTheFirstCopysBytesOnly()
    {
        var first = fixture.WriteLooseFile(Encoding.UTF8.GetBytes(IdenticalDuplicatePackageFixture.Text1));
        var last = fixture.WriteLooseFile(Encoding.UTF8.GetBytes(IdenticalDuplicatePackageFixture.Text2));
        using var zip = ZipFile.OpenRead(fixture.SameLengthDifferentPath);

        var matches = ContentMatchesNuGet(zip, new Dictionary<string, string> { ["first"] = first, ["last"] = last });

        Assert.True(matches(IdenticalDuplicatePackageFixture.TextEntry, "first"));
        Assert.False(matches(IdenticalDuplicatePackageFixture.TextEntry, "last"));
    }

    // Decompressed bytes, not the stored ones: a byte-identical copy of the plain text matches a deflated entry.
    [Fact]
    public void ContentMatchesNuGet_ForAFileHoldingTheEntrysDecompressedBytes_IsTrue()
    {
        var file = fixture.WriteLooseFile(Encoding.UTF8.GetBytes(IdenticalDuplicatePackageFixture.Text1));
        using var zip = ZipFile.OpenRead(fixture.IdenticalContentPath);
        Assert.Equal(CompressionMethodDeflate, CentralDirectoryMethods(fixture.IdenticalContentPath)[1]);

        Assert.True(ContentMatchesNuGet(zip, new Dictionary<string, string> { ["k"] = file })(IdenticalDuplicatePackageFixture.TextEntry, "k"));
    }

    [Fact]
    public void ContentMatchesNuGet_ForANameTheArchiveDoesNotDeclare_IsFalse()
    {
        var file = fixture.WriteLooseFile(Encoding.UTF8.GetBytes(IdenticalDuplicatePackageFixture.Text1));
        using var zip = ZipFile.OpenRead(fixture.IdenticalContentPath);

        Assert.False(ContentMatchesNuGet(zip, new Dictionary<string, string> { ["k"] = file })("content/absent.txt", "k"));
    }

    [Fact]
    public void ContentMatchesNuGet_ForAKeyWithNoExtractedFile_IsFalse()
    {
        using var zip = ZipFile.OpenRead(fixture.IdenticalContentPath);

        Assert.False(ContentMatchesNuGet(zip, new Dictionary<string, string>())(IdenticalDuplicatePackageFixture.TextEntry, "k"));
    }

    // The file was listed, then vanished before the check read it: an IO error, a mismatch, never a throw.
    [Fact]
    public void ContentMatchesNuGet_WhenTheExtractedFileIsGone_IsFalse()
    {
        var file = fixture.WriteLooseFile(Encoding.UTF8.GetBytes(IdenticalDuplicatePackageFixture.Text1));
        File.Delete(file);
        using var zip = ZipFile.OpenRead(fixture.IdenticalContentPath);

        Assert.False(ContentMatchesNuGet(zip, new Dictionary<string, string> { ["k"] = file })(IdenticalDuplicatePackageFixture.TextEntry, "k"));
    }

    // NuGet's copy cannot be read: a mismatch, never a throw, even though the file holds what the entry was meant to be.
    [Fact]
    public void ContentMatchesNuGet_WhenTheFirstCopyIsACorruptDeflateStream_IsFalse()
    {
        var file = fixture.WriteLooseFile(Encoding.UTF8.GetBytes(IdenticalDuplicatePackageFixture.Text1));
        using var zip = ZipFile.OpenRead(fixture.CorruptSolePath);

        Assert.False(ContentMatchesNuGet(zip, new Dictionary<string, string> { ["k"] = file })(IdenticalDuplicatePackageFixture.TextEntry, "k"));
    }
    #endregion

    #region Methods: a real package (the local NuGet cache)
    // The W1 regression on the package it was found on: two byte-identical packageIcon.png entries. Read in place from
    // the cache (never copied into the repo); Open only, so no CIL analysis runs in this process.
    [LocalNuGetCachePackageFact(IdenticalDuplicatePackageFixture.LoggingPackage)]
    public void Open_ForMicrosoftExtensionsLogging310_DoesNotLoseItsByteIdenticalPackageIcon()
    {
        var path = LocalNuGetCachePackageFactAttribute.PathOf(IdenticalDuplicatePackageFixture.LoggingPackage);
        using (var zip = ZipFile.OpenRead(path))
        {
            var icons = zip.Entries.Where(e => e.FullName == "packageIcon.png").Select(e => Convert.ToHexString(Sha256Of(e))).ToArray();
            Assert.Equal(2, icons.Length);
            Assert.Equal(icons[0], icons[1]);
        }

        using var pkg = Open(path);
        Assert.Equal(2, pkg.DeclaredEntryNames.Count(n => n == "packageIcon.png"));
        Assert.True(File.Exists(Path.Combine(pkg.ContentRoot, "packageIcon.png")));
        Assert.Empty(pkg.UninventoriedEntryNames);
    }
    #endregion

    #region Methods: helpers
    private static void AssertComplete(PackageCapabilityReport scan)
    {
        Assert.DoesNotContain(scan.Assemblies, a => a.SkipReason is not null);
        Assert.Equal(ScriptScanStatus.Completed, scan.ScriptScanStatus);
    }

    private static void AssertIdenticalHookScanned(string nupkgPath, int copies)
    {
        using (var pkg = Open(nupkgPath))
        {
            Assert.Equal(copies, pkg.DeclaredEntryNames.Count(n => n == EntryAliasPackageFixture.TargetsEntry));
            AssertTheTargetsFileHolds(pkg, PackageFixture.MaliciousTargets);
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.Scripts.Select(s => s.RelativePath));
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(nupkgPath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.TargetsEntry);
        AssertComplete(scan);
    }

    // The build directory holds exactly the one real-named file, with these bytes.
    private static void AssertTheTargetsFileHolds(NuGetPackage pkg, string content)
    {
        Assert.Equal([EntryAliasPackageFixture.TargetsEntry], BuildFiles(pkg));
        Assert.Equal(content, File.ReadAllText(Path.Combine(pkg.ContentRoot, "build", "Some.Package.targets")));
    }

    // The precondition of the CRC32 tests, read back from the archive itself (not from Crc32Forge): two copies of the
    // name whose central-directory CRC32 and uncompressed size agree, and whose decompressed bytes hash differently.
    private static void AssertCentralDirectoryAgreesButBytesDiffer(string nupkgPath, string name)
    {
        using var zip = ZipFile.OpenRead(nupkgPath);
        var copies = zip.Entries.Where(e => e.FullName == name).ToArray();
        Assert.Equal(2, copies.Length);
        Assert.Equal(copies[0].Crc32, copies[1].Crc32);
        Assert.Equal(copies[0].Length, copies[1].Length);
        Assert.NotEqual(Convert.ToHexString(Sha256Of(copies[0])), Convert.ToHexString(Sha256Of(copies[1])));
    }

    // The corrupt package's precondition: the same CRC32 and size on both copies, one readable, the other not.
    private static void AssertOneCopyUnreadable(string nupkgPath, int unreadableIndex)
    {
        using var zip = ZipFile.OpenRead(nupkgPath);
        var copies = zip.Entries.Where(e => e.FullName == IdenticalDuplicatePackageFixture.TextEntry).ToArray();
        Assert.Equal(2, copies.Length);
        Assert.Equal(copies[0].Crc32, copies[1].Crc32);
        Assert.Equal(copies[0].Length, copies[1].Length);
        Assert.Equal(IdenticalDuplicatePackageFixture.Text1, Encoding.UTF8.GetString(Decompressed(copies[1 - unreadableIndex])));
        Assert.ThrowsAny<InvalidDataException>(() => Sha256Of(copies[unreadableIndex]));
    }

    private static byte[] Decompressed(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static byte[] Sha256Of(ZipArchiveEntry entry) => SHA256.HashData(Decompressed(entry));

    // Each central-directory record's compression method, in archive order, read from the raw bytes.
    private static ushort[] CentralDirectoryMethods(string zipPath)
    {
        var span = File.ReadAllBytes(zipPath).AsSpan();
        ReadOnlySpan<byte> endOfCentralDirectory = [0x50, 0x4B, 0x05, 0x06];
        var eocd = span.LastIndexOf(endOfCentralDirectory);
        var count = BinaryPrimitives.ReadUInt16LittleEndian(span[(eocd + 10)..]);
        var record = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[(eocd + 16)..]);
        var methods = new ushort[count];
        for (var i = 0; i < count; i++)
        {
            methods[i] = BinaryPrimitives.ReadUInt16LittleEndian(span[(record + 10)..]);
            record += 46 + BinaryPrimitives.ReadUInt16LittleEndian(span[(record + 28)..])
                + BinaryPrimitives.ReadUInt16LittleEndian(span[(record + 30)..]) + BinaryPrimitives.ReadUInt16LittleEndian(span[(record + 32)..]);
        }
        return methods;
    }

    // NuGetPackage.ContentMatchesNuGet (private static): the check Open builds over the archive and the extracted files.
    private static Func<string, string, bool> ContentMatchesNuGet(ZipArchive zip, IReadOnlyDictionary<string, string> filesByRel)
    {
        var method = typeof(NuGetPackage).GetMethod("ContentMatchesNuGet", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return (Func<string, string, bool>)method.Invoke(null, [zip, filesByRel])!;
    }
    #endregion

    #region Fields
    private const ushort CompressionMethodDeflate = 8;

    private readonly IdenticalDuplicatePackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the duplicate-name packages for <see cref="EntryAliasingIdenticalDuplicateTests"/> with pure BCL zip (names
/// stored verbatim by <see cref="NupkgBuilder"/>, in the archive order given). The CRC32-collision decoy is forged by
/// <see cref="Crc32Forge"/>; the corrupt packages are written normally and then have a copy's deflate stream patched
/// in place by <see cref="CorruptDeflateStream"/>, leaving its CRC32 and sizes as they were.
/// </summary>
public sealed class IdenticalDuplicatePackageFixture : IDisposable
{
    #region Constructors
    public IdenticalDuplicatePackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-entry-alias", "identical-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        const string targets = EntryAliasPackageFixture.TargetsEntry;
        var hook = Bytes(PackageFixture.MaliciousTargets);
        var decoy = Bytes(EntryAliasPackageFixture.DecoyTargets);
        var nuspec = (Name: "PkgIdentical.nuspec", Bytes: Bytes(NupkgBuilder.NuspecXml(
            "PkgIdentical", "1.0.0", "Silvergun Tests", "Identical-duplicate test package.", "net8.0", [])));

        IdenticalContentPath = Write("IdenticalContent", [nuspec, (TextEntry, Bytes(Text1)), (TextEntry, Bytes(Text1))]);
        IdenticalTargetsPath = Write("IdenticalTargets", [nuspec, (targets, hook), (targets, hook)]);
        TriplicateIdenticalTargetsPath = Write("TriplicateIdenticalTargets", [nuspec, (targets, hook), (targets, hook), (targets, hook)]);
        MixedDuplicatesPath = Write("MixedDuplicates",
            [nuspec, (TextEntry, Bytes(Text1)), (OtherTextEntry, Bytes(Text1)), (TextEntry, Bytes(Text1)), (OtherTextEntry, Bytes(Text2))]);
        IdenticalPairThenDriveDecoyPath = Write("IdenticalPairThenDriveDecoy", [nuspec, (targets, hook), (targets, hook), (DriveTargets, decoy)]);
        IdenticalRootedPath = Write("IdenticalRooted", [nuspec, (RootedTextEntry, Bytes(Text1)), (RootedTextEntry, Bytes(Text1))]);
        SameLengthDifferentPath = Write("SameLengthDifferent", [nuspec, (TextEntry, Bytes(Text1)), (TextEntry, Bytes(Text2))]);

        // The decoy: an empty project padded to the hook's length less four, then four bytes forcing the hook's CRC32.
        ForgedDecoy = Crc32Forge.Force(
            Bytes(EntryAliasPackageFixture.DecoyTargets.PadRight(hook.Length - 4)), Crc32Forge.Compute(hook));
        CrcCollisionTargetsPath = Write("CrcCollisionTargets", [nuspec, (targets, hook), (targets, ForgedDecoy)]);

        CorruptLastCopyPath = Write("CorruptLastCopy", [nuspec, (TextEntry, Bytes(Text1)), (TextEntry, Bytes(Text1))]);
        CorruptDeflateStream.Patch(CorruptLastCopyPath, entryIndex: 2);
        CorruptFirstCopyPath = Write("CorruptFirstCopy", [nuspec, (TextEntry, Bytes(Text1)), (TextEntry, Bytes(Text1))]);
        CorruptDeflateStream.Patch(CorruptFirstCopyPath, entryIndex: 1);
        CorruptBothCopiesPath = Write("CorruptBothCopies", [nuspec, (TextEntry, Bytes(Text1)), (TextEntry, Bytes(Text1))]);
        CorruptDeflateStream.Patch(CorruptBothCopiesPath, entryIndex: 1);
        CorruptDeflateStream.Patch(CorruptBothCopiesPath, entryIndex: 2);
        CorruptSolePath = Write("CorruptSole", [nuspec, (TextEntry, Bytes(Text1))]);
        CorruptDeflateStream.Patch(CorruptSolePath, entryIndex: 1);
    }
    #endregion

    #region Properties
    /// <summary>The text entry the content shapes duplicate.</summary>
    public const string TextEntry = "content/x.txt";

    /// <summary>A second, independently duplicated text entry.</summary>
    public const string OtherTextEntry = "content/y.txt";

    /// <summary><see cref="TextEntry"/> rooted with '/': escapes the content root.</summary>
    public const string RootedTextEntry = "/content/x.txt";

    /// <summary>The targets name behind a leading drive segment, which the extractor drops on both platforms.</summary>
    public const string DriveTargets = "./C:/build/Some.Package.targets";

    /// <summary>One copy's text, long enough to deflate to a real block.</summary>
    public const string Text1 = "hello from the first copy of this entry, hello again\n";

    /// <summary>Another copy's text: the same length as <see cref="Text1"/>, different bytes.</summary>
    public const string Text2 = "hello from the other copy of this entry, hello again\n";

    /// <summary>The cache-relative path of the real package the W1 regression was found on.</summary>
    public const string LoggingPackage = "microsoft.extensions.logging/3.1.0/microsoft.extensions.logging.3.1.0.nupkg";

    public string IdenticalContentPath { get; }
    public string IdenticalTargetsPath { get; }
    public string TriplicateIdenticalTargetsPath { get; }
    public string MixedDuplicatesPath { get; }
    public string IdenticalPairThenDriveDecoyPath { get; }
    public string IdenticalRootedPath { get; }
    public string SameLengthDifferentPath { get; }
    public string CrcCollisionTargetsPath { get; }
    public string CorruptLastCopyPath { get; }
    public string CorruptFirstCopyPath { get; }
    public string CorruptBothCopiesPath { get; }
    public string CorruptSolePath { get; }

    /// <summary>The forged decoy's bytes: the hook's length and CRC32, different content.</summary>
    public byte[] ForgedDecoy { get; }
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

    /// <summary>Writes a loose file (standing in for an extracted one) under the fixture's directory; returns its path.</summary>
    public string WriteLooseFile(byte[] bytes)
    {
        var dir = Path.Combine(rootDir, "loose");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    private string Write(string name, (string Name, byte[] Bytes)[] entries)
    {
        var path = Path.Combine(rootDir, $"{name}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path, [], entries);
        return path;
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}

/// <summary>
/// A small CRC-32 (IEEE 802.3, the zip CRC) and the textbook four-byte forcing routine: given a prefix and a target CRC,
/// it appends the four bytes that make the whole message hash to the target. Linear-algebra trivia, used only to build a
/// benign same-CRC decoy; the test reads the resulting CRC back from the zip's own central directory rather than trusting
/// this class. <see cref="RawZip"/> uses <see cref="Compute"/> for the CRC fields it writes.
/// </summary>
internal static class Crc32Forge
{
    #region Methods
    public static uint Compute(byte[] data) => ~Update(0xFFFFFFFFu, data);

    // Walk back from the wanted final register: each step's table index is fixed by the register's top byte (the table's
    // top bytes are a permutation). Then walk forward from the prefix's register, choosing each byte to hit that index.
    public static byte[] Force(byte[] prefix, uint target)
    {
        var index = new byte[4];
        var wanted = ~target;
        for (var i = 3; i >= 0; i--)
        {
            var top = wanted >> 24;
            index[i] = (byte)Array.FindIndex(table, t => t >> 24 == top);
            wanted = (wanted ^ table[index[i]]) << 8;
        }

        var register = Update(0xFFFFFFFFu, prefix);
        var tail = new byte[4];
        for (var i = 0; i < 4; i++)
        {
            tail[i] = (byte)(index[i] ^ (register & 0xFF));
            register = (register >> 8) ^ table[index[i]];
        }

        var forced = prefix.Concat(tail).ToArray();
        if (Compute(forced) != target)
            throw new InvalidOperationException("CRC-32 forcing failed.");
        return forced;
    }

    private static uint Update(uint register, byte[] data)
    {
        foreach (var b in data)
            register = (register >> 8) ^ table[(register ^ b) & 0xFF];
        return register;
    }

    private static uint[] MakeTable() =>
        Enumerable.Range(0, 256)
            .Select(n => Enumerable.Range(0, 8).Aggregate((uint)n, (c, _) => (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1))
            .ToArray();
    #endregion

    #region Fields
    private static readonly uint[] table = MakeTable();
    #endregion
}

/// <summary>
/// Corrupts ONE entry's deflate stream in a written zip, in place: the first byte of its compressed data becomes
/// <c>0x07</c> (BFINAL=1, BTYPE=11, the block type RFC 1951 reserves as an error). The entry's name, CRC32 and sizes are
/// untouched, so every central-directory field still matches its twin; only reading the stream fails.
/// </summary>
internal static class CorruptDeflateStream
{
    #region Methods
    /// <param name="entryIndex">The entry's position in the central directory (archive order, zero-based).</param>
    public static void Patch(string zipPath, int entryIndex)
    {
        var bytes = File.ReadAllBytes(zipPath);
        var span = bytes.AsSpan();

        var eocd = span.LastIndexOf(EndOfCentralDirectory);
        Assert.True(eocd >= 0, "no end-of-central-directory record.");
        var record = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[(eocd + 16)..]);

        for (var i = 0; i < entryIndex; i++)
            record += 46 + Length(span, record + 28) + Length(span, record + 30) + Length(span, record + 32);

        Assert.True(span[record..].StartsWith(CentralDirectoryHeader), $"entry {entryIndex} is not a central-directory record.");
        Assert.Equal(8, Length(span, record + 10));   // deflate
        var local = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[(record + 42)..]);
        Assert.True(span[local..].StartsWith(LocalFileHeader), $"entry {entryIndex} has no local header at {local}.");

        bytes[local + 30 + Length(span, local + 26) + Length(span, local + 28)] = 0x07;
        File.WriteAllBytes(zipPath, bytes);
    }

    private static int Length(ReadOnlySpan<byte> span, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(span[offset..]);
    #endregion

    #region Fields
    private static ReadOnlySpan<byte> EndOfCentralDirectory => [0x50, 0x4B, 0x05, 0x06];
    private static ReadOnlySpan<byte> CentralDirectoryHeader => [0x50, 0x4B, 0x01, 0x02];
    private static ReadOnlySpan<byte> LocalFileHeader => [0x50, 0x4B, 0x03, 0x04];
    #endregion
}

/// <summary>
/// Gates a test on a package being present in the local NuGet global-packages folder (<c>NUGET_PACKAGES</c>, else
/// <c>~/.nuget/packages</c>), read in place. Skip, never an early return (see <see cref="WindowsExtractionFactAttribute"/>).
/// </summary>
public sealed class LocalNuGetCachePackageFactAttribute : FactAttribute
{
    #region Constructors
    public LocalNuGetCachePackageFactAttribute(string cacheRelativePath)
    {
        if (!File.Exists(PathOf(cacheRelativePath)))
            Skip = $"Needs {cacheRelativePath} in the local NuGet cache ({PathOf(cacheRelativePath)}), and it is not there.";
    }
    #endregion

    #region Methods
    public static string PathOf(string cacheRelativePath) =>
        Path.Combine(
            Environment.GetEnvironmentVariable("NUGET_PACKAGES") is { Length: > 0 } root
                ? root
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages"),
            cacheRelativePath);
    #endregion
}
