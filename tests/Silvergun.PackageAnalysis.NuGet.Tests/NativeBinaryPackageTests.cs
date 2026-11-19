namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

using static NativeHeaderBuilder;

/// <summary>
/// native-binaries-1 at the package and report level: <see cref="NuGetPackage.NativeBinaries"/> found by header over
/// EVERY contained file (an extensionless ELF under <c>tools/</c> included), with role, escaped path, size and SHA-256;
/// <see cref="PackageCapabilityReport.NativeBinaryScanStatus"/> set by <see cref="PackageScanner.Scan"/>; the
/// per-file IO-failure path; and the JSON contract (round trip, legacy JSON, reason escaped and cut).
/// </summary>
public sealed class NativeBinaryPackageTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public NativeBinaryPackageTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: NuGetPackage.Open
    // The acceptance package: an extensionless ELF under tools/ (its name carrying a bidi override), a native PE .dll,
    // an IL-only managed .dll and a text file => exactly the two native ones.
    [Fact]
    public void Open_MixedPackage_InventoriesExactlyTheTwoNativeBinaries()
    {
        using var tree = new TempTree();
        var nupkg = MixedPackage(tree);

        using var package = Open(nupkg);

        Assert.Equal(2, package.NativeBinaries.Count);
        Assert.Empty(package.NativeBinaryUnreadFiles);

        var elf = Assert.Single(package.NativeBinaries, b => b.Format == NativeBinaryFormat.Elf);
        Assert.Equal(EscapedElfEntry, elf.RelativePath);
        Assert.Equal(PackageItemRole.Tools, elf.Role);
        Assert.Equal(NativeBinaryKind.Executable, elf.Kind);
        Assert.Equal("x64", elf.Architecture);
        Assert.Equal(NativeBinaryCode.Native, elf.Code);
        Assert.Equal(ElfBytes.Length, elf.Size);
        Assert.Equal(Sha256(ElfBytes), elf.Sha256);

        var pe = Assert.Single(package.NativeBinaries, b => b.Format == NativeBinaryFormat.PE);
        Assert.Equal(NativePeEntry, pe.RelativePath);
        Assert.Equal(PackageItemRole.Lib, pe.Role);
        Assert.Equal(NativeBinaryKind.SharedLibrary, pe.Kind);
        Assert.Equal("x64", pe.Architecture);
        Assert.Equal(NativeBinaryCode.Native, pe.Code);
        Assert.Equal(PeBytes.Length, pe.Size);
        Assert.Equal(Sha256(PeBytes), pe.Sha256);
    }

    // The escaped path carries no raw bidi override; the hash is lowercase hex.
    [Fact]
    public void Open_MixedPackage_PathsAreEscapedAndHashesAreLowercaseHex()
    {
        using var tree = new TempTree();
        using var package = Open(MixedPackage(tree));

        Assert.All(package.NativeBinaries, b =>
        {
            Assert.DoesNotContain(Rlo, b.RelativePath);
            Assert.Matches("^[0-9a-f]{64}$", b.Sha256);
        });
        Assert.Contains(package.NativeBinaries, b => b.RelativePath.Contains(EscapedRlo, StringComparison.Ordinal));
    }

    // A native .dll keeps its place in the assembly inventory (the CIL coverage gap is unchanged) AND is a native binary;
    // the extensionless ELF is not an assembly at all.
    [Fact]
    public void Open_MixedPackage_TheNativeDllIsAlsoAnAssembly_TheElfIsNot()
    {
        using var tree = new TempTree();
        using var package = Open(MixedPackage(tree));

        Assert.Contains(package.Assemblies, a => a.RelativePath == NativePeEntry);
        Assert.Contains(package.Assemblies, a => a.RelativePath == ManagedEntry);
        Assert.DoesNotContain(package.Assemblies, a => a.RelativePath == EscapedElfEntry);
    }

    // Under runtimes/ (the usual place for native libs) the role is Runtimes, and Mach-O/universal formats come through.
    [Fact]
    public void Open_RuntimesNativeLibraries_CarryTheRuntimesRoleAndTheirFormats()
    {
        using var tree = new TempTree();
        var nupkg = Path.Combine(tree.Root, "PkgNativeRuntimes.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg,
        [
            Nuspec("PkgNativeRuntimes"),
            ("runtimes/osx/native/libfoo.dylib", Universal(false, [(CpuX64, MachO(true, true, CpuX64, MhDylib)), (CpuArm64, MachO(true, true, CpuArm64, MhDylib))])),
            ("runtimes/osx-arm64/native/libbar.dylib", MachO(true, true, CpuArm64, MhDylib)),
            ("runtimes/linux-x64/native/libbaz.so", Elf(true, true, EtDyn, EmX64, [PtLoad, PtDynamic])),
        ]);

        using var package = Open(nupkg);

        Assert.Equal(3, package.NativeBinaries.Count);
        Assert.All(package.NativeBinaries, b => Assert.Equal(PackageItemRole.Runtimes, b.Role));
        Assert.All(package.NativeBinaries, b => Assert.Equal(NativeBinaryKind.SharedLibrary, b.Kind));
        Assert.Equal(
            new[] { NativeBinaryFormat.Elf, NativeBinaryFormat.MachO, NativeBinaryFormat.MachOUniversal },
            package.NativeBinaries.Select(b => b.Format).Order().ToArray());
        Assert.Equal("x64+arm64", Assert.Single(package.NativeBinaries, b => b.Format == NativeBinaryFormat.MachOUniversal).Architecture);
    }

    // Review round 1: an IL-only PE outside the CIL inventory (not named .dll/.exe) is listed — nothing else would see it
    // — and the very same bytes named .dll are not (the CIL analysis owns them).
    [Fact]
    public void Open_IlOnlyPeUnderANonAssemblyName_IsListedAsILOnly_TheSameBytesAsADllAreNot()
    {
        using var tree = new TempTree();
        const string id = "PkgIlOnlyHidden";
        var managed = File.ReadAllBytes(fixture.FixtureDllPath);
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg,
        [
            Nuspec(id),
            ("tools/payload", managed),
            ("content/x.bin", managed),
            ("lib/net8.0/X.dll", managed),
            ("tools/Y.exe", managed),
        ]);

        using var package = Open(nupkg);

        Assert.Equal(
            new[] { "content/x.bin", "tools/payload" },
            package.NativeBinaries.Select(b => b.RelativePath).Order(StringComparer.Ordinal).ToArray());
        Assert.All(package.NativeBinaries, b =>
        {
            Assert.Equal(NativeBinaryCode.ILOnly, b.Code);
            Assert.Equal(NativeBinaryFormat.PE, b.Format);
            Assert.Equal(managed.Length, b.Size);
            Assert.Equal(Sha256(managed), b.Sha256);
        });
        Assert.Equal(PackageItemRole.Tools, package.NativeBinaries.Single(b => b.RelativePath == "tools/payload").Role);
        Assert.Contains(package.Assemblies, a => a.RelativePath == "lib/net8.0/X.dll");   // the CIL inventory has the .dll
    }

    [Fact]
    public void Scan_IlOnlyPeUnderANonAssemblyName_ReachesTheReportAsILOnly()
    {
        using var tree = new TempTree();
        const string id = "PkgIlOnlyHiddenScan";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg, [Nuspec(id), ("tools/payload", File.ReadAllBytes(fixture.FixtureDllPath))]);

        var report = Scan(nupkg);

        var binary = Assert.Single(report.NativeBinaries);
        Assert.Equal("tools/payload", binary.RelativePath);
        Assert.Equal(NativeBinaryCode.ILOnly, binary.Code);
        Assert.Equal(NativeBinaryScanStatus.Completed, report.NativeBinaryScanStatus);
    }

    // A package with no native code (the benign fixture: managed dll, a script, a non-PE "notmanaged.dll"): empty.
    [Fact]
    public void Open_PackageWithoutNativeCode_HasNoNativeBinaries()
    {
        using var package = Open(fixture.PkgAPath);

        Assert.Empty(package.NativeBinaries);
        Assert.Empty(package.NativeBinaryUnreadFiles);
    }

    // The nuspec is a contained file too, and must never be mistaken for one.
    [Fact]
    public void Open_TheNuspecIsNeverANativeBinary()
    {
        using var tree = new TempTree();
        using var package = Open(MixedPackage(tree));

        Assert.DoesNotContain(package.NativeBinaries, b => b.RelativePath.EndsWith(".nuspec", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: InventoryNativeBinaries, a file that cannot be read
    // A file that vanished (or is locked) between extraction and the probe is recorded, escaped, with its exception
    // type, and does not stop the files after it from being probed.
    [Fact]
    public void InventoryNativeBinaries_WhenAFileCannotBeRead_RecordsItAndKeepsGoing()
    {
        using var tree = new TempTree();
        var missing = Path.Combine(tree.Root, "tools", "gone");
        var elf = tree.Write("tools/node", ElfBytes);

        var (found, unread) = Inventory([(missing, "tools/go" + Rlo + "ne"), (elf, "tools/node")]);

        var binary = Assert.Single(found);
        Assert.Equal("tools/node", binary.RelativePath);
        Assert.Equal(@"tools/go" + EscapedRlo + "ne (FileNotFoundException)", Assert.Single(unread));
    }

    // Open warns once when files could not be read, escaped, naming at most the first five.
    [Fact]
    public void InventoryNativeBinaries_WhenFilesCannotBeRead_WarnsOnceNamingAtMostFive()
    {
        using var tree = new TempTree();
        using var warnings = new WarningCapture();
        var missing = Enumerable.Range(0, 7)
            .Select(i => (Path.Combine(tree.Root, $"gone{i}"), i == 0 ? "tools/go" + Rlo + "ne0" : $"tools/gone{i}"))
            .ToArray();

        var (_, unread) = Inventory(missing);

        Assert.Equal(7, unread.Count);
        var warning = Assert.Single(warnings.Warnings, w => w.StartsWith("Native binary scan INCOMPLETE", StringComparison.Ordinal));
        Assert.StartsWith("Native binary scan INCOMPLETE: 7 file(s) could not be read: tools/go" + EscapedRlo + "ne0 (FileNotFoundException), ", warning, StringComparison.Ordinal);
        Assert.Contains("tools/gone4 (FileNotFoundException)", warning, StringComparison.Ordinal);
        Assert.DoesNotContain("tools/gone5", warning, StringComparison.Ordinal);
        AssertNoRawControl(warning);
    }

    [Fact]
    public void InventoryNativeBinaries_WhenEveryFileReads_DoesNotWarn()
    {
        using var tree = new TempTree();
        using var warnings = new WarningCapture();
        var elf = tree.Write("tools/node", ElfBytes);

        Inventory([(elf, "tools/node")]);

        Assert.DoesNotContain(warnings.Warnings, w => w.StartsWith("Native binary scan INCOMPLETE", StringComparison.Ordinal));
    }

    [Fact]
    public void InventoryNativeBinaries_WhenEveryFileReads_HasNoUnreadFiles()
    {
        using var tree = new TempTree();
        var text = tree.Write("content/readme.txt", "hello\n");
        var empty = tree.Write("content/empty.bin", Array.Empty<byte>());

        var (found, unread) = Inventory([(text, "content/readme.txt"), (empty, "content/empty.bin")]);

        Assert.Empty(found);
        Assert.Empty(unread);
    }
    #endregion

    #region Methods: PackageScanner.NativeBinaryScanOutcome (the status/reason mapping Scan uses)
    [Fact]
    public void NativeBinaryScanOutcome_WithNoUnreadFiles_IsCompletedWithNoReason()
    {
        Assert.Equal((NativeBinaryScanStatus.Completed, (string?)null), PackageScanner.NativeBinaryScanOutcome([]));
    }

    [Fact]
    public void NativeBinaryScanOutcome_WithOneUnreadFile_IsUnavailableNamingIt()
    {
        var (status, reason) = PackageScanner.NativeBinaryScanOutcome(["tools/node (IOException)"]);

        Assert.Equal(NativeBinaryScanStatus.Unavailable, status);
        Assert.Equal("1 file(s) could not be read for a native header: tools/node (IOException)", reason);
    }

    [Fact]
    public void NativeBinaryScanOutcome_WithSeveralUnreadFiles_CountsAndListsThemInOrder()
    {
        var (status, reason) = PackageScanner.NativeBinaryScanOutcome(
            ["tools/a (IOException)", "content/b.bin (UnauthorizedAccessException)", "c (FileNotFoundException)"]);

        Assert.Equal(NativeBinaryScanStatus.Unavailable, status);
        Assert.Equal(
            "3 file(s) could not be read for a native header: tools/a (IOException), content/b.bin (UnauthorizedAccessException), c (FileNotFoundException)",
            reason);
    }

    // End to end through the report: the outcome's reason, however long, is cut to the report's bound on assignment.
    [Fact]
    public void NativeBinaryScanOutcome_ALongReason_IsCutByTheReport()
    {
        var unread = Enumerable.Range(0, 200).Select(i => $"tools/file{i} (IOException)").ToArray();
        var (status, reason) = PackageScanner.NativeBinaryScanOutcome(unread);

        var report = Report(status, []) with { NativeBinaryScanUnavailableReason = reason };

        Assert.StartsWith("200 file(s) could not be read for a native header: tools/file0 (IOException), ", report.NativeBinaryScanUnavailableReason, StringComparison.Ordinal);
        Assert.Equal(PackageCapabilityReport.MaxNativeBinaryScanUnavailableReasonChars, report.NativeBinaryScanUnavailableReason!.Length);
        Assert.EndsWith("...", report.NativeBinaryScanUnavailableReason, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: PackageScanner.Scan
    [Fact]
    public void Scan_MixedPackage_CarriesTheNativeBinaries_AndIsCompletedWithNoReason()
    {
        using var tree = new TempTree();
        var nupkg = MixedPackage(tree);

        var report = Scan(nupkg);

        Assert.Equal(NativeBinaryScanStatus.Completed, report.NativeBinaryScanStatus);
        Assert.Null(report.NativeBinaryScanUnavailableReason);
        Assert.Equal(2, report.NativeBinaries.Count);
        Assert.Contains(report.NativeBinaries, b => b.RelativePath == EscapedElfEntry && b.Kind == NativeBinaryKind.Executable);
        Assert.Contains(report.NativeBinaries, b => b.RelativePath == NativePeEntry && b.Kind == NativeBinaryKind.SharedLibrary);
    }

    // The native .dll stays a skipped assembly in the CIL results: coverage is unchanged by native-binaries-1.
    [Fact]
    public void Scan_MixedPackage_TheNativeDllIsStillASkippedAssembly()
    {
        using var tree = new TempTree();

        var report = Scan(MixedPackage(tree));

        var native = Assert.Single(report.Assemblies, a => a.Assembly.RelativePath == NativePeEntry);
        Assert.Null(native.Report);
        Assert.NotNull(native.SkipReason);
    }

    [Fact]
    public void Scan_PackageWithoutNativeCode_IsCompletedAndEmpty()
    {
        var report = Scan(fixture.PkgAPath);

        Assert.Equal(NativeBinaryScanStatus.Completed, report.NativeBinaryScanStatus);
        Assert.Empty(report.NativeBinaries);
        Assert.Null(report.NativeBinaryScanUnavailableReason);
    }
    #endregion

    #region Methods: JSON
    [Fact]
    public void ToJson_WritesTheBinariesAndTheStatus_ButNoNullReason()
    {
        var json = Report(NativeBinaryScanStatus.Completed, SampleBinaries()).ToJson();

        Assert.Contains("\"NativeBinaryScanStatus\": \"Completed\"", json, StringComparison.Ordinal);
        Assert.Contains("\"NativeBinaries\": [", json, StringComparison.Ordinal);
        Assert.Contains("\"Format\": \"Elf\"", json, StringComparison.Ordinal);
        Assert.Contains("\"Kind\": \"Executable\"", json, StringComparison.Ordinal);
        Assert.Contains("\"Role\": \"Tools\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("NativeBinaryScanUnavailableReason", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ARoundTrip_PreservesTheBinariesTheStatusAndTheReason()
    {
        var report = Report(NativeBinaryScanStatus.Unavailable, SampleBinaries()) with { NativeBinaryScanUnavailableReason = "1 file(s) could not be read" };

        var json = report.ToJson();
        var restored = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(report.NativeBinaries, restored.NativeBinaries);
        Assert.Equal(NativeBinaryScanStatus.Unavailable, restored.NativeBinaryScanStatus);
        Assert.Equal("1 file(s) could not be read", restored.NativeBinaryScanUnavailableReason);
        Assert.Equal(json, restored.ToJson());
    }

    // A Completed report with an empty list round-trips as Completed + empty: "ships no native code", verified.
    [Fact]
    public void ARoundTrip_OfAnEmptyCompletedScan_StaysCompleted()
    {
        var restored = PackageCapabilityReport.FromJson(Report(NativeBinaryScanStatus.Completed, []).ToJson())!;

        Assert.Equal(NativeBinaryScanStatus.Completed, restored.NativeBinaryScanStatus);
        Assert.Empty(restored.NativeBinaries);
    }

    // JSON written before the fields: empty (never null) and Unavailable, so it never reads as "no native code".
    [Fact]
    public void LegacyJson_WithoutTheFields_IsAnEmptyListAndUnavailable()
    {
        const string legacyJson = """
            {
              "Package": { "Id": "Legacy.Package", "Version": "1.0.0", "Authors": "Old Author", "Description": "Old.", "Dependencies": [] },
              "AnalyzedAt": "2020-01-01T00:00:00+00:00",
              "Assemblies": [],
              "Scripts": [],
              "ScriptFindings": []
            }
            """;

        var restored = PackageCapabilityReport.FromJson(legacyJson)!;

        Assert.NotNull(restored.NativeBinaries);
        Assert.Empty(restored.NativeBinaries);
        Assert.Equal(NativeBinaryScanStatus.Unavailable, restored.NativeBinaryScanStatus);
        Assert.Null(restored.NativeBinaryScanUnavailableReason);
    }

    [Fact]
    public void JsonWithAnExplicitNullList_IsNormalizedToEmpty()
    {
        var json = Report(NativeBinaryScanStatus.Completed, SampleBinaries()).ToJson();
        var start = json.IndexOf("\"NativeBinaries\": [", StringComparison.Ordinal);
        var end = json.IndexOf(']', start);
        var nulled = json[..start] + "\"NativeBinaries\": null" + json[(end + 1)..];

        var restored = PackageCapabilityReport.FromJson(nulled)!;

        Assert.NotNull(restored.NativeBinaries);
        Assert.Empty(restored.NativeBinaries);
    }

    [Fact]
    public void TheRecordDefault_IsEmptyAndUnavailable()
    {
        var report = new PackageCapabilityReport(
            new PackageIdentityInfo("Default.Package", "1.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch, Array.Empty<AssemblyScanResult>(), Array.Empty<PackageScript>(), Array.Empty<ScriptFinding>());

        Assert.Empty(report.NativeBinaries);
        Assert.Equal(NativeBinaryScanStatus.Unavailable, report.NativeBinaryScanStatus);
        Assert.Null(report.NativeBinaryScanUnavailableReason);
    }

    [Fact]
    public void TheReason_IsEscapedAndBoundedOnAssignment()
    {
        var report = Report(NativeBinaryScanStatus.Unavailable, []) with { NativeBinaryScanUnavailableReason = Hostile };

        var reason = report.NativeBinaryScanUnavailableReason!;
        Assert.Equal(512, PackageCapabilityReport.MaxNativeBinaryScanUnavailableReasonChars);
        Assert.Equal(PackageCapabilityReport.MaxNativeBinaryScanUnavailableReasonChars, reason.Length);
        Assert.StartsWith(EscapedHostile, reason, StringComparison.Ordinal);
        Assert.EndsWith("...", reason, StringComparison.Ordinal);
        AssertNoRawControl(reason);
    }

    // FromJson goes through the same accessor: a raw LF / ESC / bidi override (JSON-escaped in the text) comes out escaped.
    [Fact]
    public void FromJson_EscapesAndBoundsTheReason()
    {
        var json = Report(NativeBinaryScanStatus.Unavailable, []).ToJson().TrimEnd().TrimEnd('}')
            + $",\n  \"NativeBinaryScanUnavailableReason\": {JsonSerializer.Serialize(Hostile)}\n}}";

        var restored = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(512, restored.NativeBinaryScanUnavailableReason!.Length);
        Assert.StartsWith(EscapedHostile, restored.NativeBinaryScanUnavailableReason, StringComparison.Ordinal);
        AssertNoRawControl(restored.NativeBinaryScanUnavailableReason);
    }

    [Fact]
    public void AnOrdinaryReason_IsKeptVerbatim()
    {
        const string ordinary = "1 file(s) could not be read for a native header: tools/node (IOException)";

        var report = Report(NativeBinaryScanStatus.Unavailable, []) with { NativeBinaryScanUnavailableReason = ordinary };

        Assert.Equal(ordinary, report.NativeBinaryScanUnavailableReason);
    }
    #endregion

    #region Methods: helpers
    private static NuGetPackage Open(string nupkg)
    {
        var open = NuGetPackage.Open(nupkg);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    private static PackageCapabilityReport Scan(string nupkg)
    {
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    // The first two of InventoryNativeBinaries' results (native-binaries-3 added the bundle hosts, covered in
    // BundleUnpackPackageTests).
    private static (IReadOnlyList<NativeBinary> Found, IReadOnlyList<string> Unread) Inventory((string full, string rel)[] files)
    {
        var method = typeof(NuGetPackage).GetMethod("InventoryNativeBinaries", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var (found, unread, _) = ((IReadOnlyList<NativeBinary>, IReadOnlyList<string>, IReadOnlyList<BundleHost>))method.Invoke(null, [files])!;
        return (found, unread);
    }

    private string MixedPackage(TempTree tree)
    {
        const string id = "PkgNativeMixed";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg,
        [
            Nuspec(id),
            (ElfEntry, ElfBytes),
            (NativePeEntry, PeBytes),
            (ManagedEntry, File.ReadAllBytes(fixture.FixtureDllPath)),
            ("content/readme.txt", Encoding.UTF8.GetBytes("Just a readme.\n")),
        ]);
        return nupkg;
    }

    private static (string, byte[]) Nuspec(string id) =>
        ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
            id, "1.0.0", "Silvergun Tests", "native-binaries-1 test package.", "net8.0", [])));

    private static NativeBinary[] SampleBinaries() =>
    [
        new(EscapedElfEntry, NativeBinaryFormat.Elf, NativeBinaryKind.Executable, "x64", NativeBinaryCode.Native, PackageItemRole.Tools, 120, new string('a', 64)),
        new("lib/net8.0/mixed.dll", NativeBinaryFormat.PE, NativeBinaryKind.SharedLibrary, "x86", NativeBinaryCode.MixedMode, PackageItemRole.Lib, 1024, new string('b', 64)),
        new("runtimes/osx/native/libfoo.dylib", NativeBinaryFormat.MachOUniversal, NativeBinaryKind.Malformed, null, NativeBinaryCode.Native, PackageItemRole.Runtimes, 8, new string('c', 64)),
        new("lib/net8.0/r2r.dll", NativeBinaryFormat.PE, NativeBinaryKind.SharedLibrary, "x64", NativeBinaryCode.ReadyToRun, PackageItemRole.Lib, 2048, new string('d', 64)),
        new("tools/payload", NativeBinaryFormat.PE, NativeBinaryKind.SharedLibrary, "x86", NativeBinaryCode.ILOnly, PackageItemRole.Tools, 4096, new string('e', 64)),
    ];

    private static PackageCapabilityReport Report(NativeBinaryScanStatus status, NativeBinary[] binaries) =>
        new(new PackageIdentityInfo("Native.Package", "1.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch, Array.Empty<AssemblyScanResult>(), Array.Empty<PackageScript>(), Array.Empty<ScriptFinding>(),
            YaraScanStatus: YaraScanStatus.Completed, ScriptScanStatus: ScriptScanStatus.Completed,
            NativeBinaries: binaries, NativeBinaryScanStatus: status);

    private static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void AssertNoRawControl(string text) =>
        Assert.DoesNotContain(text, c => c < ' ' || c is >= (char)0x7F and <= (char)0x9F || c == Rlo);
    #endregion

    #region Fields
    private readonly PackageFixture fixture;

    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so this source never carries it raw.
    private const char Rlo = (char)0x202E;

    // The backslash-u form YaraPathSafety.Escape renders U+202E as, built so this source never carries that sequence.
    private const string EscapedRlo = @"\" + "u202e";

    // Extensionless, as Playwright's node: found by header, never by name.
    private static readonly string ElfEntry = "tools/no" + Rlo + "de";
    private static readonly string EscapedElfEntry = "tools/no" + EscapedRlo + "de";
    private const string NativePeEntry = "lib/net8.0/native.dll";
    private const string ManagedEntry = "lib/net8.0/Managed.dll";

    private static readonly byte[] ElfBytes = Elf(true, true, EtDyn, EmX64, [PtLoad, PtInterp, PtDynamic]);
    private static readonly byte[] PeBytes = Pe(MachineAmd64, CharDll | CharExecutable, pe32Plus: true);

    private static readonly string Hostile = "1 file(s) could not be read for a native header: tools/a\n[ERR] forged" + Rlo + (char)0x1B + "[31m" + new string('z', 2000);
    private const string EscapedHostile = @"1 file(s) could not be read for a native header: tools/a\n[ERR] forged" + EscapedRlo + @"\x1b[31m";
    #endregion
}
