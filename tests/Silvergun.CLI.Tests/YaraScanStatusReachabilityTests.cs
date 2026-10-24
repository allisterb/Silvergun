namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0027 decision 4, "CRITICAL (code review) — decision 4's fix is PARTLY INERT" follow-up: end-to-end
/// REACHABILITY of <see cref="YaraScanStatus.Unavailable"/> through the real wiring, not a hand-built
/// <see cref="PackageCapabilityReport"/>. <see cref="CompletenessExitCodeTests"/> already pins the pure predicate
/// ("given a report with YaraScanStatus.Unavailable, ForPackage/ScanPackageExitCode produce ...") over synthetic
/// data — that is the right shape for a truth table, but it cannot catch a wiring gap where the real
/// <see cref="PackageScanner.Scan"/> path never actually PRODUCES that status in the first place, which is exactly
/// the defect this ADR section describes shipping. This test drives a genuine <see cref="PackageScanner.Scan"/>
/// call with an injected unhealthy <see cref="IYaraScanner"/> (<c>Available == false</c> — the shape a
/// never-configured <c>NullYaraScanner</c>, a <c>YaraXWorkerScanner</c> (the Windows default since ADR 0033 T6b) whose
/// worker or YARA-X DLL is missing, or a broken <c>LibYaraScanner</c> (the explicit fallback) produces in production) and follows
/// the REAL resulting report through <see cref="CompletenessAssessment.ForPackage"/>, the rendered footer, and
/// <see cref="Program.ScanPackageExitCode"/>.
/// <para>
/// <b>Why this whole test lives in Silvergun.CLI.Tests, not split across two projects:</b> every seam it touches
/// after <c>PackageScanner.Scan</c> — <c>CompletenessAssessment</c>, <c>PackageReportRenderer</c>,
/// <c>Program.ScanPackageExitCode</c> — is <c>internal</c> to <c>Silvergun.CLI</c> (via
/// <c>InternalsVisibleTo("Silvergun.CLI.Tests")</c>), and <c>Silvergun.CLI.Tests</c> already carries a transitive
/// <c>ProjectReference</c> to <c>Silvergun.PackageAnalysis.NuGet</c> through its reference to <c>Silvergun.CLI</c>
/// (see <c>CompletenessCliTests</c>, which already calls into that library directly). Nothing here needs a second
/// half in <c>Silvergun.PackageAnalysis.NuGet.Tests</c> — that project separately pins the narrower fact that
/// <c>PackageScanner.Scan</c> itself produces <c>YaraScanStatus.Unavailable</c> for an unhealthy backend
/// (<c>YaraScanPackageWiringTests.Scan_WithUnavailableFakeScanner_NeverCallsScanDirectory_AndStatusIsUnavailable</c>);
/// this test's job is the reachability of that fact through the CLI's own completeness/exit-code plumbing.
/// </para>
/// <para>
/// The package under scan is nuspec-only (no assemblies) — running in-process (not a child CLI process) is safe
/// here because nothing hostile is ever fed to CCI/AssemblyAnalyzer; only YARA's status-derivation path is
/// exercised.
/// </para>
/// </summary>
public sealed class YaraScanStatusReachabilityTests
{
    #region Methods
    [Fact]
    public void ScanPackage_WhenWiredYaraBackendIsUnavailable_IsNotVerifiedAndExitsThree()
    {
        var nupkg = BuildEmptyNupkg("SilvergunYaraReachability");
        try
        {
            var scan = PackageScanner.Scan(nupkg, yaraScanner: new UnavailableScanner());
            Assert.True(scan.IsSuccess, scan.Message);

            // The real, wired outcome — not asserted on a record literal. PackageScanner.Scan itself never touches
            // vulnerabilities (Program.RunScanPackage attaches that separately, the same "report with { ... }" way,
            // after calling Scan — see ResolveVulnerabilities/Program.cs:392-393): mark it Completed here so the
            // ONLY completeness gap under test is the YARA one, isolating the caveat this test is pinning rather
            // than also asserting on the unrelated, always-present "vulnerabilities not checked" default gap.
            var report = scan.Value with { VulnerabilitiesStatus = VulnerabilityScanStatus.Completed };
            Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
            Assert.Empty(report.YaraFindings);

            var assessment = CompletenessAssessment.ForPackage(report);
            Assert.False(assessment.IsComplete);
            Assert.Contains("the YARA malware-signature scan did not complete", assessment.Caveats);

            var (console, writer) = PlainConsole();
            PackageReportRenderer.Render(console, report, nupkg);
            Assert.Equal(
                FooterHeadline.NotVerified(console, "the YARA malware-signature scan did not complete"),
                FooterHeadline.Of(writer));

            // Exit 3 without --allow-incomplete; --allow-incomplete downgrades it to 0 (the gate is suppressed,
            // never the underlying fact — CompletenessFooterTests pins that the caveat still prints).
            Assert.Equal(3, Program.ScanPackageExitCode(report, strict: false, allowIncomplete: false));
            Assert.Equal(0, Program.ScanPackageExitCode(report, strict: false, allowIncomplete: true));
        }
        finally
        {
            TryDelete(nupkg);
        }
    }
    #endregion

    #region Nested types
    // A minimal unhealthy IYaraScanner: Available is false, mirroring NullYaraScanner/a broken LibYaraScanner.
    // ScanFile and ScanFiles are never reached (PackageScanner.ScanYara gates on Available before calling ScanFiles at
    // all), but they are implemented anyway since the interface requires them — empty, as NullYaraScanner's are.
    private sealed class UnavailableScanner : IYaraScanner
    {
        public bool Available => false;

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => Array.Empty<YaraMatch>();

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files) =>
            Array.Empty<(string, YaraMatch)>();
    }
    #endregion

    #region Methods — helpers
    private static (IAnsiConsole Console, StringWriter Writer) PlainConsole()
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Width = 240;
        return (console, writer);
    }

    // A minimal valid .nupkg (root "<id>.nuspec" only, no assemblies/scripts) using pure BCL zip — no NuGet
    // client, no network. Mirrors CompletenessCliTests.BuildNupkg's shape without the extra-entries parameter,
    // which this test does not need.
    private static string BuildEmptyNupkg(string id)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>YARA status reachability test package.</description>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-yara-reachability-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            using var entryStream = zip.CreateEntry($"{id}.nuspec").Open();
            var bytes = Encoding.UTF8.GetBytes(nuspec);
            entryStream.Write(bytes, 0, bytes.Length);
        }
        return path;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    #endregion
}
