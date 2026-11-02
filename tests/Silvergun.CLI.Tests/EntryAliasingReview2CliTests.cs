namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;

using Spectre.Console;

using Silvergun.CLI;
using Silvergun.CLI.Reports;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The report side of <c>docs/agent/tasks/entry-aliasing-coverage.md</c>: <b>Review 2's W2</b> — a declared entry that
/// was never written as a file of its own (<see cref="AssemblyScanResult.NotInventoried"/>) is an ENTRY, not a file, so
///   * <see cref="CompletenessAssessment.ForPackage"/> names it under its own caveat, "N declared package entr(y was|ies
///     were) never extracted as its/their own file: …", while "N of M file(s) could not be analysed" counts files only;
///   * <see cref="PackageReportRenderer"/> lists it in its own "Package entries never extracted" section, not as a
///     "skipped:" node of the Assemblies tree;
///   * <c>--snapshot</c>'s <c>AssemblyLoadFailures</c> counts files only (the package is still incomplete via IsComplete);
/// and, in-process on whatever platform this suite runs, the exit code for <b>Review 5's</b> escaping decoys (C1-r5) and
/// <b>Review 2's</b> exact duplicate (C3): incomplete, <c>--strict</c> exit 3, where the same package without the decoy is
/// complete and exits 0.
///
/// <para>Real scans of real <c>.nupkg</c> files, offline (<c>resolveReferences</c>/<c>runYara</c> off). The OSV and
/// YARA statuses a full CLI run would set are normalized by <see cref="Verified"/> to isolate the variable under test;
/// no assertion reads either. Every lost shape used here is lost on BOTH platforms (a leading drive segment, an exact
/// duplicate, an escaping name), so nothing is gated. Payloads are the findings-free BenignFixture assembly and short
/// plain text.</para>
/// </summary>
public sealed class EntryAliasingReview2CliTests : IClassFixture<EntryAliasingCliPackageFixture>
{
    #region Constructors
    public EntryAliasingReview2CliTests(EntryAliasingCliPackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: W2, the caveats
    // The reviewer's drv-nuspec-after: "./C:/Real.nuspec" is written over Real.nuspec (the extractor drops the drive
    // segment on both platforms) and claims nothing. The package has no binaries at all, so before W2 this read
    // "1 of 1 file(s) could not be analysed" — one file, of a package that has none.
    [Fact]
    public void ForPackage_ForADriveSegmentManifestDecoy_NamesItInTheSingularNeverExtractedCaveatAndCountsNoFile()
    {
        var assessment = CompletenessAssessment.ForPackage(Scan(fixture.DriveManifestAfterPath));

        Assert.False(assessment.IsComplete);
        Assert.Contains("1 declared package entry was never extracted as its own file: ./C:/Real.nuspec", assessment.Caveats);
        Assert.DoesNotContain(assessment.Caveats, c => c.Contains("file(s) could not be analysed", StringComparison.Ordinal));
    }

    [Fact]
    public void ForPackage_ForTwoLostEntries_NamesBothInThePluralNeverExtractedCaveat()
    {
        var assessment = CompletenessAssessment.ForPackage(Scan(fixture.TwoLostPath));

        Assert.False(assessment.IsComplete);
        Assert.Contains(
            "2 declared package entries were never extracted as their own file: ./C:/Real.nuspec, tools/install.ps1",
            assessment.Caveats);
        Assert.DoesNotContain(assessment.Caveats, c => c.Contains("file(s) could not be analysed", StringComparison.Ordinal));
    }

    // A binary that failed to load AND a lost entry: two caveats, each about its own kind. "N of M" counts FILES — the
    // analysed dll and the native one — so it is "1 of 2", not "2 of 3" as when the lost entry was counted as a file.
    [Fact]
    public void ForPackage_ForAFileThatFailedToLoadPlusALostEntry_GivesBothCaveatsAndCountsFilesOnly()
    {
        var assessment = CompletenessAssessment.ForPackage(Scan(fixture.NativePlusLostPath));

        Assert.False(assessment.IsComplete);
        Assert.Contains($"1 of 2 file(s) could not be analysed: {EntryAliasingCliPackageFixture.NativeEntry}", assessment.Caveats);
        Assert.Contains(
            $"1 declared package entry was never extracted as its own file: {EntryAliasingCliPackageFixture.DuplicatedText}",
            assessment.Caveats);
    }
    #endregion

    #region Methods: W2, the rendered report
    // Its own section, after the Assemblies tree, with the singular note and the entry's verbatim skip reason — and the
    // Assemblies tree (which has no file to list here) does not carry it as a "skipped:" node.
    [Fact]
    public void Render_ForADriveSegmentManifestDecoy_ListsItUnderPackageEntriesNeverExtractedWithTheSingularNote()
    {
        var output = Render(Scan(fixture.DriveManifestAfterPath));

        var assemblies = output.IndexOf("Assemblies", StringComparison.Ordinal);
        var section = output.IndexOf("Package entries never extracted", StringComparison.Ordinal);
        Assert.True(assemblies >= 0 && section > assemblies, "the never-extracted section must follow the Assemblies section.");
        Assert.Contains(
            "[!] 1 declared entry was never written as a file of its own - its content, or the content it replaced, was NOT analysed",
            output, StringComparison.Ordinal);
        Assert.Contains(
            output.Split('\n'),
            l => l.Contains("./C:/Real.nuspec", StringComparison.Ordinal) && l.Contains("NOT inventoried", StringComparison.Ordinal));
        Assert.DoesNotContain("skipped:", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_ForTwoLostEntries_UsesThePluralNote()
    {
        var output = Render(Scan(fixture.TwoLostPath));

        Assert.Contains(
            "[!] 2 declared entries were never written as a file of their own - their content, or the content they replaced, was NOT analysed",
            output, StringComparison.Ordinal);
        Assert.DoesNotContain("1 declared entry was never written", output, StringComparison.Ordinal);
    }

    // The file that failed to load stays a "skipped:" node of the Assemblies tree; only the lost entry moves out of it.
    [Fact]
    public void Render_ForAFileThatFailedToLoadPlusALostEntry_KeepsTheFileUnderAssembliesAndTheEntryInItsOwnSection()
    {
        var output = Render(Scan(fixture.NativePlusLostPath));
        var section = output.IndexOf("Package entries never extracted", StringComparison.Ordinal);
        Assert.True(section >= 0, "the never-extracted section is missing.");

        var skipped = output.IndexOf("skipped:", StringComparison.Ordinal);
        Assert.True(skipped >= 0 && skipped < section, "the native dll's skip node must stay in the Assemblies tree.");
        Assert.Equal(1, Count(output, "skipped:"));
        Assert.True(output.IndexOf(EntryAliasingCliPackageFixture.DuplicatedText, section, StringComparison.Ordinal) > section);
    }
    #endregion

    #region Methods: W2, --snapshot counts files only (the real CLI, a child process)
    // One snapshot element (the one assembly that produced a CapabilityReport); AssemblyLoadFailures counts the native
    // dll and NOT the lost entry, while IsComplete still reads false because of the lost entry and the native dll.
    [Fact]
    public void ScanPackageCli_WithSnapshot_CountsOnlyTheFileThatFailedToLoadAsAnAssemblyLoadFailure()
    {
        var snapshotPath = Path.Combine(Path.GetTempPath(), $"silvergun-ea-snapshot-{Guid.NewGuid():N}.json");
        try
        {
            var (exit, stderr, exited) = RunCli(
                "scan-package", fixture.NativePlusLostPath, "--no-vulns", "--no-yara", "--allow-incomplete", "--snapshot", snapshotPath);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.True(exit == 0, $"expected exit 0 (--allow-incomplete, not --strict), got {exit}. stderr:{Environment.NewLine}{stderr}");
            using var doc = JsonDocument.Parse(File.ReadAllText(snapshotPath));
            var element = Assert.Single(doc.RootElement.EnumerateArray());
            var completeness = element.GetProperty("Completeness");
            Assert.False(completeness.GetProperty("IsComplete").GetBoolean());
            Assert.Equal(1, completeness.GetProperty("AssemblyLoadFailures").GetInt32());
        }
        finally
        {
            try { if (File.Exists(snapshotPath)) File.Delete(snapshotPath); } catch (IOException) { /* best-effort temp cleanup */ }
        }
    }
    #endregion

    #region Methods: Review 5 (C1-r5) and C3, the exit code (in-process, every platform)
    // An escaping decoy over the real entry of the same path: never inventoried, so the package is incomplete and
    // --strict exits 3, naming the DECOY in either archive order (before it, the decoy must not steal the real entry's
    // claim). The control is the same package without the decoy: complete, 0. And C3's duplicate, the same way. Where a
    // decoy with DIFFERENT bytes comes after the real entry, the real entry is named too: its file holds the decoy, so it
    // fails the content check (ADR 0036). The rooted manifest decoy's bytes equal the real manifest's, so only it is named.
    [Theory]
    [InlineData("RootedTargets", "2 declared package entries were never extracted as their own file: build/Some.Package.targets, /build/Some.Package.targets")]
    [InlineData("RootedTargetsBefore", "1 declared package entry was never extracted as its own file: /build/Some.Package.targets")]
    [InlineData("RootedManifest", "1 declared package entry was never extracted as its own file: /Real.nuspec")]
    [InlineData("RootedContent", "2 declared package entries were never extracted as their own file: content/payload.bin, /content/payload.bin")]
    [InlineData("DuplicateTargets", "1 declared package entry was never extracted as its own file: build/Some.Package.targets")]
    public void ScanPackageExitCode_ForADecoyOverARealEntry_IsIncompleteAndThreeWhereTheControlIsZero(string shape, string caveat)
    {
        var (withDecoy, control) = fixture.DecoyPair(shape);
        var report = Scan(withDecoy);
        var clean = Scan(control);

        var assessment = CompletenessAssessment.ForPackage(report);
        Assert.False(assessment.IsComplete);
        Assert.Contains(caveat, assessment.Caveats);
        Assert.Equal(3, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));

        Assert.True(CompletenessAssessment.ForPackage(clean).IsComplete, $"the {shape} control must be complete.");
        Assert.Equal(0, Program.ScanPackageExitCode(clean, strict: true, allowIncomplete: false));
    }
    #endregion

    #region Methods: helpers
    private static PackageCapabilityReport Scan(string nupkgPath)
    {
        var scan = PackageScanner.Scan(nupkgPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return Verified(scan.Value);
    }

    // The OSV and YARA statuses a full CLI run would have set, so their own caveats do not hide the one under test.
    private static PackageCapabilityReport Verified(PackageCapabilityReport report) =>
        report with
        {
            VulnerabilitiesStatus = VulnerabilityScanStatus.Completed,
            YaraScanStatus = YaraScanStatus.Completed,
        };

    // The ASCII report (no Unicode glyphs: "[!]" and "-"), wide enough that a skip reason does not wrap mid-name.
    private static string Render(PackageCapabilityReport report)
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = false;
        console.Profile.Width = 400;
        PackageReportRenderer.Render(console, report, "Probe.nupkg");
        return writer.ToString();
    }

    private static int Count(string text, string value)
    {
        var count = 0;
        for (var i = text.IndexOf(value, StringComparison.Ordinal); i >= 0; i = text.IndexOf(value, i + value.Length, StringComparison.Ordinal))
            count++;
        return count;
    }

    // Same shape as the suite's other RunCli helpers: both streams drained asynchronously, stdin closed, NO_COLOR set.
    private static (int Exit, string Error, bool Exited) RunCli(params string[] args)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";

        using var process = Process.Start(psi)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeoutMs))
        {
            try { process.Kill(entireProcessTree: true); } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            return (-1, string.Empty, false);
        }

        _ = stdout.GetAwaiter().GetResult();
        return (process.ExitCode, stderr.GetAwaiter().GetResult(), true);
    }
    #endregion

    #region Fields
    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");
    private const int TimeoutMs = 120_000;

    private readonly EntryAliasingCliPackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the <c>.nupkg</c> files for <see cref="EntryAliasingReview2CliTests"/> with pure BCL zip (names stored
/// verbatim, in the archive order given). Payloads: the findings-free BenignFixture assembly, a non-PE <c>.dll</c>, and
/// short plain text; the <c>.targets</c> are empty projects (content is irrelevant to every assertion here).
/// </summary>
public sealed class EntryAliasingCliPackageFixture : IDisposable
{
    #region Constructors
    public EntryAliasingCliPackageFixture()
    {
        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-ea-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var benign = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.BenignFixture.dll"));

        var real = (Name: "Real.nuspec", Bytes: Nuspec("Real"));
        var script = (Name: "tools/install.ps1", Bytes: Text("Write-Host 'installing'\n"));
        var targets = (Name: "build/Some.Package.targets", Bytes: Text("<Project>\n  <Target Name=\"Noop\" />\n</Project>\n"));
        var decoyTargets = Text("<Project />\n");
        var content = (Name: "content/payload.bin", Bytes: Text("real content\n"));
        var decoyContent = Text("decoy content\n");
        var probe = (Name: "PkgEaCli.nuspec", Bytes: Nuspec("PkgEaCli"));

        // The drive decoy's bytes equal Real.nuspec's, so Real.nuspec passes its content check (ADR 0036) and the decoy is
        // the one entry lost. The script's second copy DIFFERS from its first: byte-identical copies are not lost.
        DriveManifestAfterPath = Write("DriveManifestAfter", real, ("./C:/Real.nuspec", Nuspec("Real")), script);
        TwoLostPath = Write("TwoLost", real, ("./C:/Real.nuspec", Nuspec("Real")), script, (script.Name, Text("Write-Host 'other'\n")));
        NativePlusLostPath = Write("NativePlusLost",
            probe, (OrdinaryEntry, benign), (NativeEntry, NotManagedBytes),
            (DuplicatedText, Text("one\n")), (DuplicatedText, Text("two\n")));

        pairs = new Dictionary<string, (string, string)>(StringComparer.Ordinal)
        {
            ["RootedTargets"] = (Write("RootedTargets", probe, targets, ("/build/Some.Package.targets", decoyTargets)), Write("RootedTargetsControl", probe, targets)),
            ["RootedTargetsBefore"] = (Write("RootedTargetsBefore", probe, ("/build/Some.Package.targets", decoyTargets), targets), Write("RootedTargetsBeforeControl", probe, targets)),
            ["RootedManifest"] = (Write("RootedManifest", real, ("/Real.nuspec", Nuspec("Real")), script), Write("RootedManifestControl", real, script)),
            ["RootedContent"] = (Write("RootedContent", probe, content, ("/content/payload.bin", decoyContent)), Write("RootedContentControl", probe, content)),
            ["DuplicateTargets"] = (Write("DuplicateTargets", probe, targets, (targets.Name, decoyTargets)), Write("DuplicateTargetsControl", probe, targets)),
        };
    }
    #endregion

    #region Properties
    /// <summary>An ordinary, analysable lib assembly.</summary>
    public const string OrdinaryEntry = "lib/net8.0/Ordinary.dll";

    /// <summary>A non-PE <c>.dll</c>: inventoried as a file, fails to load.</summary>
    public const string NativeEntry = "lib/net8.0/notmanaged.dll";

    /// <summary>A text entry declared twice with DIFFERENT bytes: lost once, on every platform (C3, then ADR 0036).</summary>
    public const string DuplicatedText = "content/readme.txt";

    public string DriveManifestAfterPath { get; }
    public string TwoLostPath { get; }
    public string NativePlusLostPath { get; }
    #endregion

    #region Methods
    /// <summary>The package with the decoy, and the same package without it.</summary>
    public (string WithDecoy, string Control) DecoyPair(string shape) => pairs[shape];

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Nuspec(string id) => Text($"""
        <?xml version="1.0" encoding="utf-8"?>
        <package xmlns="{NuspecNamespace}">
          <metadata>
            <id>{id}</id>
            <version>1.0.0</version>
            <authors>Silvergun Tests</authors>
            <description>Entry-aliasing report-side test package.</description>
            <dependencies>
              <group targetFramework="net8.0" />
            </dependencies>
          </metadata>
        </package>
        """);

    // ZipArchive.CreateEntry stores each name VERBATIM, which is what lets a rooted, drive or duplicate name be staged.
    private string Write(string name, params (string Entry, byte[] Bytes)[] entries)
    {
        var path = Path.Combine(rootDir, $"{name}.1.0.0.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            foreach (var (entry, bytes) in entries)
            {
                using var s = zip.CreateEntry(entry).Open();
                s.Write(bytes, 0, bytes.Length);
            }
        }
        return path;
    }
    #endregion

    #region Fields
    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";

    // Arbitrary non-PE bytes standing in for a native dll (as CompletenessCliTests uses).
    private static readonly byte[] NotManagedBytes = [0x00, 0x01, 0x02, 0x03, 0x2A, 0x7F, 0x55, 0xAA, 0x13, 0x37];

    private readonly string rootDir;
    private readonly Dictionary<string, (string, string)> pairs;
    #endregion
}
