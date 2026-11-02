namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

using Silvergun.CLI;
using Silvergun.CLI.Reports;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The exit-code half of Round 3's W1: <b>a payload whose declared name ends in a space or a dot must not read as
/// clean on Windows — and must not read as lost on Linux.</b>
///
/// <para>Windows silently drops a trailing space or dot when it creates a file (measured 2026-08-22), so a declared
/// <c>lib/net8.0/evil.dll </c> is extracted as <c>lib/net8.0/evil.dll</c> — a path no entry declares, dropped by the
/// inventory gate — while the entry itself claims nothing and used to fall through the lost-kind test, because
/// <c>"…/evil.dll ".EndsWith(".dll")</c> is <b>false</b>. Net: extracted, never analysed, package
/// <b>complete, exit 0, even under <c>--strict</c></b>, with only the non-gating <c>TrailingSpaceOrDot</c> anomaly
/// disclosing it. The kind test now runs on the trimmed key, so the entry becomes a skipped
/// <see cref="AssemblyScanResult"/>, <see cref="CompletenessAssessment.ForPackage"/> reads the package as incomplete,
/// and <see cref="Program.ScanPackageExitCode"/> returns <b>3</b>.</para>
///
/// <para><b>The kind guard, and the accepted cost.</b> The same OS behaviour applies to every trailing-space name,
/// inventoried kind or not. Trimming must still never widen the kind set (no phantom binary is analysed). But since
/// 2026-11-01 (<c>tasks/entry-aliasing-coverage.md</c>, Review 1 rule (a)) every contained entry that claimed no file is
/// lost whatever its kind, so a package shipping <c>content/readme.txt </c> now exits 3 on Windows and 0 on Linux. That
/// verdict divergence on such input was the architect's explicit, fail-closed choice (the names are already
/// TrailingSpaceOrDot anomalies), measured as 0 new uninventoried entries over the 100-package benign corpus (ADR 0031
/// decision 3); both sides are pinned below so it changes only on purpose.</para>
///
/// <para>These drive a REAL scan of a real <c>.nupkg</c> rather than a hand-built report, for the same reason
/// <see cref="UninventoriedEntryCompletenessTests"/> does: what could go wrong is the wiring, and a constructed
/// <see cref="AssemblyScanResult"/> would prove nothing about whether a lost entry reaches the assessment at all.</para>
/// </summary>
public sealed class TrailingSpaceOrDotExitCodeTests : IClassFixture<TrailingNameCliPackageFixture>
{
    #region Constructors
    public TrailingSpaceOrDotExitCodeTests(TrailingNameCliPackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — the trailing space and dot (Windows: incomplete, exit 3)
    // The headline. Two payloads extracted and never analysed, so the package is NOT complete and each is named in
    // the caveats — a count with no name would leave a reviewer unable to say WHICH binary went unlooked-at. Since
    // entry-aliasing review 2 (W2) they are named by the plural NEVER-EXTRACTED caveat, not "N of M file(s) could not be
    // analysed": they are entries that claimed no file, and the one real file (the ordinary dll) was analysed.
    [WindowsExtractionFact("Windows silently drops a trailing space or dot, so the extracted file matches no entry")]
    public void ForPackage_OnWindows_ForTrailingSpaceAndDotPayloads_IsIncompleteAndNamesBoth()
    {
        var report = Scan(fixture.TrailingPath);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete, "two extracted, un-analysed payloads must not read as complete.");
        Assert.Contains(
            $"2 declared package entries were never extracted as their own file: " +
            $"{TrailingNameCliPackageFixture.TrailingSpaceEntry}, {TrailingNameCliPackageFixture.TrailingDotEntry}",
            assessment.Caveats);
        Assert.DoesNotContain(assessment.Caveats, c => c.Contains("could not be analysed", StringComparison.Ordinal));
    }

    // The exit code, with the before/after in one test: the control package is the SAME package with the two
    // trailing-name entries removed, which is exactly the report the pre-fix code produced for the hostile one —
    // the entries simply vanished. So it used to exit 0, and it now exits 3.
    [WindowsExtractionFact("only Windows loses these entries, so only there does the exit code change")]
    public void ScanPackageExitCode_OnWindows_ForTrailingSpaceAndDotPayloads_IsThreeWhereTheControlIsZero()
    {
        var lost = Scan(fixture.TrailingPath);
        var control = Scan(fixture.OrdinaryOnlyPath);

        Assert.True(CompletenessAssessment.ForPackage(control).IsComplete, "the control package must be complete.");
        Assert.Equal(0, Program.ScanPackageExitCode(control, strict: false, allowIncomplete: false));
        Assert.Equal(3, Program.ScanPackageExitCode(lost, strict: false, allowIncomplete: false));
    }

    // "…complete, exit 0, EVEN UNDER --strict" was the sharp end of the defect: no flag a CI pipeline could set made
    // the run notice. Both policy positions are pinned, since exit 3 is a coverage statement and not a verdict.
    [WindowsExtractionFact("only Windows loses these entries, so only there is there an incompleteness to gate on")]
    public void ScanPackageExitCode_OnWindows_ForTrailingSpaceAndDotPayloads_IsThreeUnderStrictToo()
    {
        var report = Scan(fixture.TrailingPath);

        Assert.Equal(3, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
        // ...and --allow-incomplete un-gates it without suppressing the caveat (ADR 0024).
        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: true));
        Assert.NotEmpty(CompletenessAssessment.ForPackage(report).Caveats);
    }

    // The over-firing guard, and the reason the Windows result above is legible as an OS limitation being disclosed
    // rather than a Silvergun policy: ext4 holds "evil.dll " and "evil.dll." verbatim, each entry claims its own
    // extracted file, and the very same package is complete and exits 0.
    //
    // "Complete" is a claim about WHAT WAS ANALYSED, so the membership is pinned before the verdict is. Asserting
    // only "no row carries a SkipReason" was vacuously satisfiable: pre-fix this report held a SINGLE row — the
    // ordinary entry — while both trailing-name payloads were extracted, never inventoried and absent from the
    // report entirely. Exit 0 over a report that lists one of three binaries is not completeness, it is a smaller
    // instance of the defect. All three rows, each with a real capability report, or the verdict means nothing.
    [LinuxExtractionFact("ext4 holds a trailing space or dot verbatim, so each entry claims its own extracted file")]
    public void ScanPackageExitCode_OnLinux_ForTrailingSpaceAndDotPayloads_IsCompleteAndExitsZero()
    {
        var report = Scan(fixture.TrailingPath);

        var analysed = report.Assemblies.Select(a => a.Assembly.RelativePath).ToArray();
        Assert.Contains(TrailingNameCliPackageFixture.OrdinaryEntry, analysed);
        Assert.Contains(TrailingNameCliPackageFixture.TrailingSpaceEntry, analysed);
        Assert.Contains(TrailingNameCliPackageFixture.TrailingDotEntry, analysed);
        Assert.Equal(3, analysed.Length);
        Assert.All(report.Assemblies, a =>
        {
            Assert.Null(a.SkipReason);
            Assert.NotNull(a.Report);
        });

        Assert.True(CompletenessAssessment.ForPackage(report).IsComplete);
        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
    }
    #endregion

    #region Methods — the kind guard (trimming must not widen the KIND set), and rule (a)'s accepted cost
    // Windows strips the trailing space from "content/readme.txt " exactly as it does from "evil.dll ". The kind guard
    // still holds: the one thing ANALYSED is the ordinary assembly, so no ".txt " content became a phantom binary. But
    // the entries claimed no file, and under rule (a) (tasks/entry-aliasing-coverage.md, Review 1) that is lost
    // coverage whatever the kind, decided without the host probe review C1 removed — so the package is incomplete and
    // exits 3. That is the ACCEPTED, fail-closed cost: the bytes were in fact written under the trimmed name, and every
    // such name is already a TrailingSpaceOrDot anomaly.
    [WindowsExtractionFact("only Windows strips the trailing space, so only there do the entries claim no file")]
    public void ScanPackageExitCode_OnWindows_ForATrailingSpaceOnAnUninventoriedKind_IsIncompleteAndThreeButAnalysesNoPhantomBinary()
    {
        var report = Scan(fixture.UninventoriedKindPath);

        var analysed = Assert.Single(report.Assemblies, a => a.SkipReason is null);
        Assert.Equal(TrailingNameCliPackageFixture.OrdinaryEntry, analysed.Assembly.RelativePath);
        Assert.Equal(
            ["content/readme.txt ", "content/evil.dll.txt "],
            report.Assemblies.Where(a => a.SkipReason is not null).Select(a => a.Assembly.RelativePath));

        var assessment = CompletenessAssessment.ForPackage(report);
        Assert.False(assessment.IsComplete);
        Assert.Contains(assessment.Caveats, c => c.Contains("never extracted as their own file", StringComparison.Ordinal)
                                               && c.Contains("content/readme.txt ", StringComparison.Ordinal));
        Assert.Equal(3, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
    }

    // On Linux ext4 holds "content/readme.txt " and "content/evil.dll.txt " verbatim, so both ARE contained and on disk,
    // both claim their own file, and both reach the trimming kind test at the gate. The inventory is therefore pinned
    // to the one ordinary assembly — if the trim ever widened the kind set, ".txt " content would appear here as a
    // binary long before it changed any exit code — and the verdict is complete, exit 0.
    [LinuxExtractionFact("ext4 holds the trailing space verbatim, so each entry claims its own file")]
    public void ScanPackageExitCode_OnLinux_ForATrailingSpaceOnAnUninventoriedKind_IsCompleteAndZero()
    {
        var report = Scan(fixture.UninventoriedKindPath);

        var analysed = Assert.Single(report.Assemblies);
        Assert.Equal(TrailingNameCliPackageFixture.OrdinaryEntry, analysed.Assembly.RelativePath);
        Assert.All(report.Assemblies, a => Assert.Null(a.SkipReason));
        Assert.True(
            CompletenessAssessment.ForPackage(report).IsComplete,
            "on Linux a trailing space on a .txt entry is its own file, so nothing was lost.");
        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
    }
    #endregion

    #region Methods — a duplicate name with DIFFERENT bytes: incomplete, exit 3 (entry-aliasing review 2, C3)
    // At the seam an operator actually sees. Zip permits one name twice with different bytes: GetEntry returns the
    // FIRST, a sequential extract-all leaves the LAST on disk (re-measured on .NET 10, both platforms, 2026-08-22). This
    // used to pin "complete, exit 0" as a deliberate carve-out that would "change consciously rather than by drift". It
    // has, on purpose: tasks/entry-aliasing-coverage.md Review 2 (C3) measured a webhook .targets followed by a
    // "<Project />" of the same name scanning clean while NuGet installed the webhook, so a duplicated name is lost once.
    // The survivor is still analysed; the overwritten copy is the never-extracted caveat, not a file that failed to load.
    [Fact]
    public void ScanPackageExitCode_ForADuplicateNameWithDifferentBytes_IsIncompleteAndThree()
    {
        var report = Scan(fixture.DuplicateDifferentBytesPath);

        // Ground truth: the archive really does declare one name twice, with different content behind each.
        using (var zip = ZipFile.OpenRead(fixture.DuplicateDifferentBytesPath))
        {
            var occurrences = zip.Entries
                .Where(e => e.FullName == TrailingNameCliPackageFixture.DuplicateEntry)
                .Select(e => e.Length)
                .ToArray();
            Assert.Equal(2, occurrences.Length);
            Assert.NotEqual(occurrences[0], occurrences[1]);
        }

        var analysed = Assert.Single(report.Assemblies, a => !a.NotInventoried);
        Assert.Equal(TrailingNameCliPackageFixture.DuplicateEntry, analysed.Assembly.RelativePath);
        Assert.Null(analysed.SkipReason);
        Assert.NotNull(analysed.Report);
        var lost = Assert.Single(report.Assemblies, a => a.NotInventoried);
        Assert.Equal(TrailingNameCliPackageFixture.DuplicateEntry, lost.Assembly.RelativePath);

        var assessment = CompletenessAssessment.ForPackage(report);
        Assert.False(assessment.IsComplete);
        Assert.Contains(
            $"1 declared package entry was never extracted as its own file: {TrailingNameCliPackageFixture.DuplicateEntry}",
            assessment.Caveats);
        Assert.DoesNotContain(assessment.Caveats, c => c.Contains("could not be analysed", StringComparison.Ordinal));
        Assert.Equal(3, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
    }
    #endregion

    #region Methods — helpers
    // A real, offline scan. resolveReferences/runYara are off so the run is deterministic and needs no network or
    // native backend; the two statuses those choices leave unset are normalized by Verified.
    private static PackageCapabilityReport Scan(string nupkgPath)
    {
        var scan = PackageScanner.Scan(nupkgPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return Verified(scan.Value);
    }

    // The OSV and YARA statuses a full CLI run would have set — PackageScanner alone cannot, and each would
    // otherwise leave a caveat of its own that makes EVERY package here incomplete and hides the one gap under test.
    // Set to isolate the variable, never to suppress a real one: no assertion above reads either status.
    private static PackageCapabilityReport Verified(PackageCapabilityReport report) =>
        report with
        {
            VulnerabilitiesStatus = VulnerabilityScanStatus.Completed,
            YaraScanStatus = YaraScanStatus.Completed,
        };
    #endregion

    #region Fields
    private readonly TrailingNameCliPackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the <c>.nupkg</c> files for <see cref="TrailingSpaceOrDotExitCodeTests"/> with pure BCL zip — no NuGet
/// client, no network. Payloads are copies of the findings-free <c>Silvergun.CLI.Tests.BenignFixture</c> assembly, so
/// an inventoried entry analyses cleanly and completely: any caveat these tests see comes from a lost entry and
/// nothing else.
/// </summary>
public sealed class TrailingNameCliPackageFixture : IDisposable
{
    #region Constructors
    public TrailingNameCliPackageFixture()
    {
        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-trailing-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var benign = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.BenignFixture.dll"));

        OrdinaryOnlyPath = Write("PkgTrailOrdinaryOnly", (OrdinaryEntry, benign));
        TrailingPath = Write("PkgTrailNames",
            (OrdinaryEntry, benign), (TrailingSpaceEntry, benign), (TrailingDotEntry, benign));
        UninventoriedKindPath = Write("PkgTrailText",
            (OrdinaryEntry, benign),
            ("content/readme.txt ", Encoding.UTF8.GetBytes("readme")),
            ("content/evil.dll.txt ", Encoding.UTF8.GetBytes("not an assembly")));

        // The padded copy is declared FIRST so the pristine, analysable one is what extraction leaves on disk.
        DuplicateDifferentBytesPath = Write("PkgTrailDuplicate",
            (DuplicateEntry, benign.Concat(new byte[64]).ToArray()), (DuplicateEntry, benign));
    }
    #endregion

    #region Properties
    /// <summary>An ordinary, analysable lib assembly — present so a lost entry is never the package's only content.</summary>
    public const string OrdinaryEntry = "lib/net8.0/Ordinary.dll";

    /// <summary>An assembly entry with a TRAILING SPACE: Windows writes it as <c>trailspace.dll</c>.</summary>
    public const string TrailingSpaceEntry = "lib/net8.0/trailspace.dll ";

    /// <summary>An assembly entry with a TRAILING DOT: Windows writes it as <c>traildot.dll</c>.</summary>
    public const string TrailingDotEntry = "lib/net8.0/traildot.dll.";

    /// <summary>The name declared twice, with different bytes behind each occurrence.</summary>
    public const string DuplicateEntry = "content/X.dll";

    /// <summary>The control: the trailing-name entries removed, so it is complete and exits 0.</summary>
    public string OrdinaryOnlyPath { get; }

    public string TrailingPath { get; }
    public string UninventoriedKindPath { get; }
    public string DuplicateDifferentBytesPath { get; }
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

    // ZipArchive.CreateEntry stores the caller's name VERBATIM (no normalization), which is what lets a trailing
    // space, a trailing dot, or a repeated name be staged at all.
    private string Write(string id, params (string Entry, byte[] Bytes)[] entries)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>Round 3 trailing-space/dot exit-code test package.</description>
                <dependencies>
                  <group targetFramework="net8.0" />
                </dependencies>
              </metadata>
            </package>
            """;

        var path = Path.Combine(rootDir, $"{id}.1.0.0.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            WriteEntry(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
            foreach (var (entry, bytes) in entries)
                WriteEntry(zip, entry, bytes);
        }
        return path;

        static void WriteEntry(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }
    #endregion

    #region Fields
    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";

    private readonly string rootDir;
    #endregion
}
