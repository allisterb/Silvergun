namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

using Spectre.Console;

using Silvergun.CLI;
using Silvergun.CLI.Reports;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The report-and-exit-code half of ADR 0030's sixth instance: <b>a declared package entry that was never
/// inventoried must make the package read INCOMPLETE, not clean.</b>
///
/// <para>Before the fix, an entry named <c>lib/net8.0/COM1.dll</c> was dropped from the inventory on Windows (the
/// path normalizer redirects DOS device names, so the containment probe judged it to escape), never analysed, and
/// never counted as missing — <c>AssembliesScanned</c> simply did not mention it and the run exited <b>0</b>.
/// <see cref="PackageScanner"/> now synthesizes an <see cref="AssemblyScanResult"/> with a
/// <see cref="AssemblyScanResult.SkipReason"/> for each such entry, which
/// <see cref="CompletenessAssessment.ForPackage"/> already reads as "a whole binary that produced no analysis" —
/// so the footer says "Not verified" and <see cref="Program.ScanPackageExitCode"/> returns <b>3</b>.</para>
///
/// <para><b>Why these drive a real scan instead of a constructed report.</b> The sibling
/// <see cref="CompletenessExitCodeTests"/> pins the truth table of the pure predicate; what could go wrong HERE is
/// the wiring — that a lost entry actually reaches the assessment at all. A hand-built
/// <see cref="AssemblyScanResult"/> would have proved nothing about that, because the defect was precisely that no
/// such result was ever produced. So each test builds a real <c>.nupkg</c>, runs the real
/// <see cref="PackageScanner.Scan"/> over it, and asserts on the shipped seams.</para>
///
/// <para><b>Platform gates.</b> Whether a contained entry can be written to disk is an OS question, so the
/// device-name and case-only-collision packages behave differently on Windows and Linux and are asserted on both
/// sides (see <see cref="WindowsExtractionFactAttribute"/>). The NUL-bearing entry name is refused by both
/// filesystems (measured 2026-08-22), which is what lets the central assertions run ungated.</para>
/// </summary>
public sealed class UninventoriedEntryCompletenessTests : IClassFixture<UninventoriedCliPackageFixture>
{
    #region Constructors
    public UninventoriedEntryCompletenessTests(UninventoriedCliPackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — the assessment (cross-platform: a name neither filesystem will write)
    // The headline statement of the fix. One entry lost, so the package is NOT complete, and the caveat names the
    // entry — a count with no name would leave a reviewer unable to tell WHICH binary went unlooked-at. Since entry-
    // aliasing review 2 (W2) that caveat is the NEVER-EXTRACTED one: a lost entry is not a file, so it is no longer
    // counted under "N of M file(s) could not be analysed" (the only file here, the ordinary dll, was analysed).
    [Fact]
    public void ForPackage_WhenADeclaredEntryWasNeverInventoried_IsIncompleteAndNamesIt()
    {
        var report = Scan(fixture.HostileNamePath);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete, "a package with an un-analysed declared entry must not read as complete.");
        Assert.Contains(
            $"1 declared package entry was never extracted as its own file: {UninventoriedCliPackageFixture.HostileEntryEscaped}",
            assessment.Caveats);
        Assert.DoesNotContain(assessment.Caveats, c => c.Contains("could not be analysed", StringComparison.Ordinal));
    }

    // The exit-code projection, and the before/after of the defect in one test. The control package is the same
    // package with the hostile entry removed — which is EXACTLY the report the pre-fix code produced for the
    // hostile one, because the entry simply vanished. So: it used to exit 0, it now exits 3.
    [Fact]
    public void ScanPackageExitCode_ForALostEntry_IsThreeWhereTheSamePackageWithoutItIsZero()
    {
        var lost = Scan(fixture.HostileNamePath);
        var control = Scan(fixture.OrdinaryOnlyPath);

        Assert.True(CompletenessAssessment.ForPackage(control).IsComplete, "the control package must be complete.");
        Assert.Equal(0, Program.ScanPackageExitCode(control, strict: false, allowIncomplete: false));
        Assert.Equal(3, Program.ScanPackageExitCode(lost, strict: false, allowIncomplete: false));
    }

    // Exit 3 is a statement about coverage, not a policy verdict, so it is not gated on --strict — and
    // --allow-incomplete un-gates it without suppressing the caveat (ADR 0024). Pinned here too because this is the
    // combination a CI pipeline actually runs, and "0 with the caveat still printed" must not silently become
    // "0 with nothing printed".
    [Fact]
    public void ScanPackageExitCode_ForALostEntry_IsUngatedByAllowIncompleteButTheCaveatRemains()
    {
        var report = Scan(fixture.HostileNamePath);

        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: false, allowIncomplete: true));
        Assert.NotEmpty(CompletenessAssessment.ForPackage(report).Caveats);
    }
    #endregion

    #region Methods — the report boundary (ADR 0031 decision 4: the name is attacker-authored)
    // The lost entry is visible in the rendered report, under the name the package author wrote — ESCAPED. The raw
    // name carries an LF and a NUL; either one reaching the terminal raw is a forged report line. Since entry-aliasing
    // review 2 (W2) it is listed in its own "Package entries never extracted" section, with its verbatim skip reason,
    // and NOT as a "skipped:" assembly node: it is an entry, not a file.
    [Fact]
    public void PackageRenderer_ForALostEntry_ShowsTheEscapedNameAndTheSkipReason()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, Verified(Scan(fixture.HostileNamePath)), "Hostile.nupkg");

        var output = writer.ToString();
        Assert.Contains("Package entries never extracted", output, StringComparison.Ordinal);
        Assert.Contains(
            output.Split('\n'),
            l => l.Contains(UninventoriedCliPackageFixture.HostileEntryEscaped, StringComparison.Ordinal)
              && l.Contains("NOT inventoried", StringComparison.Ordinal));
        Assert.DoesNotContain("skipped:", output, StringComparison.Ordinal);
    }

    // ...and nothing anywhere in that report is a raw control character. Line breaks excepted, obviously: the
    // report is made of lines — which is the whole reason a name that can inject one matters.
    [Fact]
    public void PackageRenderer_ForALostEntry_PrintsNoRawControlCharacter()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, Verified(Scan(fixture.HostileNamePath)), "Hostile.nupkg");

        var offender = writer.ToString().FirstOrDefault(IsRawControl);
        Assert.True(offender == '\0', $"the rendered report carried raw U+{(int)offender:X4}.");
    }

    // The verdict is "Not verified", not "Clean": the package produced no findings, but one of its binaries was
    // never looked at. This is the footer half of the exit code above — ADR 0024 keeps the two in lockstep.
    [Fact]
    public void PackageRenderer_ForALostEntry_ReportsNotVerifiedRatherThanClean()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, Verified(Scan(fixture.HostileNamePath)), "Hostile.nupkg");

        Assert.True(
            FooterHeadline.IsNotVerified(FooterHeadline.Of(writer)),
            $"the footer verdict was '{FooterHeadline.Of(writer)}'.");
    }
    #endregion

    #region Methods — the device name (the divergence, pinned on both sides)
    // Windows: the sixth instance of ADR 0030, end to end. A payload named COM1.dll cannot be written to disk here,
    // so it is never analysed — and the report now says so instead of exiting 0 with a clean footer.
    [WindowsExtractionFact("Windows cannot create a file named after a reserved DOS device, so the entry is lost")]
    public void ScanPackage_OnWindows_ForADeviceNamedPayload_IsIncompleteAndExitsThree()
    {
        var report = Scan(fixture.DevicePath);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Contains(
            assessment.Caveats,
            c => c.Contains(UninventoriedCliPackageFixture.DeviceEntry, StringComparison.Ordinal));
        Assert.Equal(3, Program.ScanPackageExitCode(report, strict: false, allowIncomplete: false));
    }

    // Linux: the same package, fully analysed, so there is nothing to disclose and the run is complete. Stating it
    // here is what makes the Windows result above legible as an OS limitation being reported rather than a
    // Silvergun policy — and it is the assertion that would catch the fix over-firing on the platform that CAN
    // hold the file.
    [LinuxExtractionFact("only Linux can hold a file named COM1.dll, so only there is the package complete")]
    public void ScanPackage_OnLinux_ForADeviceNamedPayload_IsCompleteAndExitsZero()
    {
        var report = Scan(fixture.DevicePath);

        Assert.All(report.Assemblies, a => Assert.Null(a.SkipReason));
        Assert.True(CompletenessAssessment.ForPackage(report).IsComplete);
        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: false, allowIncomplete: false));
    }
    #endregion

    #region Methods — the case-only collision (Windows)
    // Two entries differing only in case: NTFS holds one, so the other is analysis that never happened. The file
    // scanned is not the file shipped, and a package that ships this construction must not read as fully covered.
    [WindowsExtractionFact("NTFS is case-insensitive, so one of two case-only-distinct entries is overwritten")]
    public void ScanPackage_OnWindows_ForACaseOnlyCollision_IsIncompleteAndExitsThree()
    {
        var report = Scan(fixture.CaseOnlyPath);

        var lost = Assert.Single(report.Assemblies, a => a.SkipReason is not null);

        Assert.Contains(lost.Assembly.RelativePath, UninventoriedCliPackageFixture.CaseOnlyEntries);
        Assert.False(CompletenessAssessment.ForPackage(report).IsComplete);
        Assert.Equal(3, Program.ScanPackageExitCode(report, strict: false, allowIncomplete: false));
    }

    [LinuxExtractionFact("ext4 is case-sensitive, so both entries are written and both are analysed")]
    public void ScanPackage_OnLinux_ForACaseOnlyCollision_IsCompleteAndExitsZero()
    {
        var report = Scan(fixture.CaseOnlyPath);

        Assert.Equal(2, report.Assemblies.Count);
        Assert.All(report.Assemblies, a => Assert.Null(a.SkipReason));
        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: false, allowIncomplete: false));
    }
    #endregion

    #region Methods — helpers
    // A real, offline scan of a real .nupkg. resolveReferences/runYara are off so the run is deterministic and
    // needs no network or native backend; the two statuses those choices leave unset are normalized by Verified
    // where completeness is the subject.
    private static PackageCapabilityReport Scan(string nupkgPath)
    {
        var scan = PackageScanner.Scan(nupkgPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return Verified(scan.Value);
    }

    // The OSV and YARA statuses a full CLI run would have set. PackageScanner alone cannot: the vulnerability check
    // is the CLI's network step and YARA was disabled above, and both leave a caveat of their own that would make
    // EVERY package here incomplete and hide the one gap these tests are about. Set for the same reason
    // PackagingAnomaliesReportRendererTests sets them — to isolate the variable under test, never to suppress a
    // real one: no assertion below reads either status.
    private static PackageCapabilityReport Verified(PackageCapabilityReport report) =>
        report with
        {
            VulnerabilitiesStatus = VulnerabilityScanStatus.Completed,
            YaraScanStatus = YaraScanStatus.Completed,
        };

    private static bool IsRawControl(char c) => c is < ' ' and not '\n' and not '\r' || c == (char)0x7F;

    private static (IAnsiConsole Console, StringWriter Writer) AsciiConsole()
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = false;
        console.Profile.Width = 240;
        return (console, writer);
    }
    #endregion

    #region Fields
    private readonly UninventoriedCliPackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the <c>.nupkg</c> files for <see cref="UninventoriedEntryCompletenessTests"/> with pure BCL zip — no
/// NuGet client, no network (the same shape as <c>CompletenessCliTests.BuildNupkg</c>). Payloads are copies of the
/// findings-free <c>Silvergun.CLI.Tests.BenignFixture</c> assembly, so an inventoried entry analyses cleanly and
/// completely: any caveat these tests see therefore comes from the lost entry and nothing else.
/// </summary>
public sealed class UninventoriedCliPackageFixture : IDisposable
{
    #region Constructors
    public UninventoriedCliPackageFixture()
    {
        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-uninv-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var benign = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.BenignFixture.dll"));

        OrdinaryOnlyPath = Write("PkgOrdinaryOnly", (OrdinaryEntry, benign));
        HostileNamePath = Write("PkgHostileName", (OrdinaryEntry, benign), (HostileEntry, benign));
        DevicePath = Write("PkgDevice", (OrdinaryEntry, benign), (DeviceEntry, benign));
        CaseOnlyPath = Write("PkgCaseOnly", (CaseOnlyEntries[0], benign), (CaseOnlyEntries[1], benign));
    }
    #endregion

    #region Properties
    /// <summary>An ordinary, analysable lib assembly — present so a lost entry is never the package's only content.</summary>
    public const string OrdinaryEntry = "lib/net8.0/Ordinary.dll";

    /// <summary>The reserved-DOS-device payload name: Windows cannot write it, Linux can.</summary>
    public const string DeviceEntry = "lib/net8.0/COM1.dll";

    /// <summary>A declared name carrying an LF and a NUL — refused by both filesystems, so lost on both.</summary>
    public const string HostileEntry = "lib/net8.0/pay\nlo\0ad.dll";

    /// <summary>What <see cref="HostileEntry"/> must look like wherever it is published (ADR 0031 decision 4).</summary>
    public const string HostileEntryEscaped = @"lib/net8.0/pay\nlo\x00ad.dll";

    /// <summary>Two entries equal under a case-insensitive filesystem and distinct everywhere else.</summary>
    public static readonly string[] CaseOnlyEntries = ["lib/A.dll", "lib/a.dll"];

    /// <summary>The control package: the hostile entry removed, so it is complete and exits 0.</summary>
    public string OrdinaryOnlyPath { get; }

    public string HostileNamePath { get; }
    public string DevicePath { get; }
    public string CaseOnlyPath { get; }
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

    // ZipArchive.CreateEntry stores the caller's name VERBATIM (no normalization), which is what lets a hostile
    // entry name be staged at all.
    private string Write(string id, params (string Entry, byte[] Bytes)[] entries)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>ADR 0030 uninventoried-entry completeness test package.</description>
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

/// <summary>
/// Gates a test to <b>Windows</b>, for the ADR 0030 sixth-instance scenarios whose outcome is decided by the
/// operating system rather than by Silvergun: only there does a reserved DOS device name or a case-only duplicate
/// cost a declared entry its place in the inventory. The Linux twin asserts the opposite outcome for the same
/// package. <c>Skip</c> rather than an early return, so a run on the other platform reports <b>Skipped</b> instead
/// of a green test that never executed.
/// </summary>
public sealed class WindowsExtractionFactAttribute : FactAttribute
{
    #region Constructors
    public WindowsExtractionFactAttribute(string because)
    {
        if (!OperatingSystem.IsWindows())
            Skip = $"Windows-only by construction: {because}. The Linux behaviour of the same package is asserted "
                 + "by the paired [LinuxExtractionFact] — run the suite on both (ADR 0030, sixth instance).";
    }
    #endregion
}

/// <summary>The Linux twin of <see cref="WindowsExtractionFactAttribute"/>; see that type for why both exist.</summary>
public sealed class LinuxExtractionFactAttribute : FactAttribute
{
    #region Constructors
    public LinuxExtractionFactAttribute(string because)
    {
        if (!OperatingSystem.IsLinux())
            Skip = $"Linux-only by construction: {because}. The Windows behaviour of the same package is asserted "
                 + "by the paired [WindowsExtractionFact] — run the suite under WSL "
                 + "(dotnet test <proj> -f net10.0) for this to execute (ADR 0030, sixth instance).";
    }
    #endregion
}
