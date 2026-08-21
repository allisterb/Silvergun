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

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// <c>docs/agent/tasks/capability-manifest-reframe.md</c>: both verb renderers now print a "Capability manifest"
/// section — EVERY <see cref="Capability"/> value, present or absent, in enum-declaration order, derived at render
/// time from the report's existing <see cref="ApiCallFinding"/> rows (<see cref="ReportTheme.CapabilityManifest"/>)
/// — alongside a one-line honesty note (<see cref="ReportTheme.CapabilityGateNote"/>).
/// <para>
/// ⚠️ ADR-0027 CORRECTION: that note used to read "...--strict still fails the build on ANY capability present
/// here", and section F below used to pin capability presence alone AS a --strict gate (exit 2). ADR-0027 measured
/// capability presence at 67-81% benign-package prevalence with zero user-would-accept hits and STOPPED it gating —
/// the note now reads "...--strict does not fail the build on capability presence alone (ADR-0027)", and section F
/// pins the new behavior (exit 0) under the same name-what-it-pins discipline the rest of this file uses.
/// </para>
/// This remains presentation only: no report record gained a member, so <c>--json</c> must stay unaffected, and
/// neither exit-code seam (<see cref="Program.AnalyzeExitCode"/> / <see cref="Program.ScanPackageExitCode"/>) may
/// move BECAUSE OF THE MANIFEST'S RENDERING — capability presence's actual (non-)effect on the exit code is a
/// separate, ADR-0027 fact pinned here regardless of whether the manifest renders at all.
/// <para>
/// Reports are constructed directly via <see cref="AnalysisCompletenessTests"/>'s fixtures (mirrors
/// <c>IndicatorHeadlineAndRenderingTests</c>' own rationale): the point is to pin the manifest's behavior over
/// arbitrary report shapes, not to depend on what one fixture assembly's real analysis happens to produce today.
/// </para>
/// </summary>
public sealed class CapabilityManifestTests
{
    #region Methods — A: every capability listed, both states (analyze)
    [Fact]
    public void Analyze_ZeroFindings_CapabilityManifestListsAllCapabilitiesAbsentWithZeroCount()
    {
        var report = AssemblyReport(methodsTotal: 5, methodsSkipped: 0);   // no findings at all
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        AssertManifestListsAllCapabilities(writer.ToString(), NoCounts);
    }

    [Fact]
    public void Analyze_MixedFindings_CapabilityManifestListsAllCapabilitiesWithCorrectPresenceAndCounts()
    {
        var report = AssemblyReport(
            methodsTotal: 5, methodsSkipped: 0,
            findings:
            [
                Finding(Capability.FileSystem), Finding(Capability.FileSystem),
                Finding(Capability.Network),
                Finding(Capability.Registry), Finding(Capability.Registry), Finding(Capability.Registry),
            ]);
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        AssertManifestListsAllCapabilities(writer.ToString(), new Dictionary<Capability, int>
        {
            [Capability.FileSystem] = 2,
            [Capability.Network] = 1,
            [Capability.Registry] = 3,
        });
    }
    #endregion

    #region Methods — B: the structural guard against a hardcoded list (⚠️ see the class comment for how this was mutation-checked)
    // The task spec's own warning: "A test hardcoding 11 would silently pass while the manifest went stale." So this
    // asserts the row count against Enum.GetValues<Capability>().Length — the SAME oracle the manifest itself is
    // built from (ReportTheme.CapabilityManifest: `foreach (var capability in Enum.GetValues<Capability>())`) — never
    // a literal "11". A test that instead wrote `Assert.Equal(11, rows.Length)` would keep passing forever even if
    // the manifest quietly reverted to a hardcoded list of today's 11 names while Capability grew a 12th value; this
    // one tracks the enum, so it fails the moment the two diverge.
    //
    // MUTATION-CHECK (documented here because it cannot be performed by editing src/, which this task forbids):
    // built a standalone scratch harness (not part of this repo) with two 11-member/12-member enum pairs and two
    // candidate row-producers — one deriving the row count from Enum.GetValues<T>().Length (the shipped pattern) and
    // one hardcoding the literal list of the original 11 names (the mutant this guard exists to catch). Comparing
    // both candidates against the oracle `Enum.GetValues<T>().Length` reproduced exactly the failure mode this test
    // is designed to catch: on the 11-member enum both candidates agree (11 == 11, guard passes either way — this is
    // also why a literal "11" in the TEST would look fine today); after appending a 12th member, the dynamic
    // candidate tracked it (12 == 12, guard still passes) while the hardcoded candidate did not (11 != 12, guard
    // FAILS) — and a test that had itself hardcoded "11" as its own expectation would have rated the mutant a PASS,
    // never noticing the regression. That is the exact defect class this test's oracle (Enum.GetValues<Capability>()
    // .Length, not a literal) is written to catch.
    [Fact]
    public void CapabilityManifest_EmitsExactlyOneRowPerEnumValue_DerivedFromTheEnumNotALiteral()
    {
        var (console, writer) = PlainConsole();

        console.Write(ReportTheme.CapabilityManifest([Finding(Capability.FileSystem)]));
        var lines = ManifestGridLines(writer.ToString());

        var expected = Enum.GetValues<Capability>().Length;   // the oracle — NEVER a literal 11
        Assert.Equal(expected, lines.Length);

        // Not just the COUNT: every current enum value must appear, exactly once — guards a mutant that emits the
        // right row count but the wrong (stale, or partially-substituted) set of names.
        foreach (var capability in Enum.GetValues<Capability>())
            Assert.Single(lines, l => l.Contains(capability.ToString(), StringComparison.Ordinal));
    }

    // Acceptance criterion 2: enum-declaration order, identical between two different packages' reports (here: one
    // `analyze` report and one `scan-package` report, carrying different finding sets, so "identical" is nontrivial).
    [Fact]
    public void CapabilityManifest_OrderIsEnumDeclarationOrder_AndIdenticalAcrossDifferentReports()
    {
        var expectedOrder = Enum.GetValues<Capability>().Select(c => c.ToString()).ToArray();

        var assemblyReport = AssemblyReport(
            methodsTotal: 5, methodsSkipped: 0,
            findings: [Finding(Capability.RuntimeControl), Finding(Capability.FileSystem)]);
        var (assemblyConsole, assemblyWriter) = PlainConsole();
        AssemblyReportRenderer.Render(assemblyConsole, assemblyReport);

        var packageReport = Package(Analyzed(
            "lib/net10.0/A.dll", 5, 0, findings: [Finding(Capability.Cryptography), Finding(Capability.NativeInterop)]));
        var (packageConsole, packageWriter) = PlainConsole();
        PackageReportRenderer.Render(packageConsole, packageReport, "Some.Package.1.0.0.nupkg");

        var assemblyOrder = ManifestCapabilityOrder(assemblyWriter.ToString());
        var packageOrder = ManifestCapabilityOrder(packageWriter.ToString());

        Assert.Equal(expectedOrder, assemblyOrder);
        Assert.Equal(expectedOrder, packageOrder);
        Assert.Equal(assemblyOrder, packageOrder);   // ... hence identical to each other, not just to the enum
    }
    #endregion

    #region Methods — C: scan-package rollup
    [Fact]
    public void ScanPackage_NoAssemblyHasFindings_CapabilityManifestListsAllCapabilitiesAbsentWithZeroCount()
    {
        var report = Package(
            Analyzed("lib/net10.0/A.dll", 5, 0),
            Analyzed("lib/net10.0/B.dll", 5, 0));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        AssertManifestListsAllCapabilities(writer.ToString(), NoCounts);
    }

    // The rollup must SUM per-capability across every analyzed assembly, including a same capability contributed by
    // more than one assembly (Network here) — not just concatenate/replace.
    [Fact]
    public void ScanPackage_CapabilityManifestRollup_SumsFindingsAcrossAllAnalyzedAssemblies()
    {
        var a = Analyzed(
            "lib/net10.0/A.dll", 5, 0,
            findings: [Finding(Capability.FileSystem), Finding(Capability.FileSystem), Finding(Capability.Network)]);
        var b = Analyzed(
            "lib/net10.0/B.dll", 5, 0,
            findings: [Finding(Capability.Network), Finding(Capability.Network), Finding(Capability.Registry)]);
        var skipped = Skipped("lib/net10.0/C.dll", "unreadable managed image");   // Report is null: must not throw or count
        var report = Package(a, b, skipped);
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        AssertManifestListsAllCapabilities(writer.ToString(), new Dictionary<Capability, int>
        {
            [Capability.FileSystem] = 2,
            [Capability.Network] = 3,   // 1 (from A) + 2 (from B) — a genuine cross-assembly sum
            [Capability.Registry] = 1,
        });
    }

    // "Must not silently drop or double-count" restated as an EQUALITY (mirrors IndicatorExitCodeInvarianceTests'
    // own rationale for preferring equality over a hand-picked literal): a skipped/failed assembly (Report is null
    // either way — AssemblyScanResult does not distinguish the two) added to an otherwise-identical package must
    // change NOTHING about the rollup.
    [Fact]
    public void ScanPackage_CapabilityManifestRollup_UnaffectedByPresenceOfSkippedOrFailedAssemblies()
    {
        var a = Analyzed("lib/net10.0/A.dll", 5, 0, findings: [Finding(Capability.FileSystem), Finding(Capability.Network)]);
        var b = Analyzed("lib/net10.0/B.dll", 5, 0, findings: [Finding(Capability.Network), Finding(Capability.Registry)]);
        var skipped = Skipped("lib/net10.0/C.dll", "unreadable managed image");

        var without = Package(a, b);
        var with = Package(a, b, skipped);

        var (consoleWithout, writerWithout) = PlainConsole();
        PackageReportRenderer.Render(consoleWithout, without, "Some.Package.1.0.0.nupkg");
        var (consoleWith, writerWith) = PlainConsole();
        PackageReportRenderer.Render(consoleWith, with, "Some.Package.1.0.0.nupkg");

        Assert.Equal(ManifestRows(writerWithout.ToString()), ManifestRows(writerWith.ToString()));
    }
    #endregion

    #region Methods — D: the gate note appears exactly once, in both renderers
    [Fact]
    public void Analyze_CapabilityGateNote_AppearsExactlyOnce()
    {
        var report = AssemblyReport(methodsTotal: 5, methodsSkipped: 0, findings: [Finding(Capability.FileSystem)]);
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        AssertGateNoteAppearsExactlyOnce(writer.ToString());
    }

    [Fact]
    public void ScanPackage_CapabilityGateNote_AppearsExactlyOnce()
    {
        var report = Package(Analyzed("lib/net10.0/A.dll", 5, 0, findings: [Finding(Capability.Network)]));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        AssertGateNoteAppearsExactlyOnce(writer.ToString());
    }

    // The note is printed alongside the manifest, not the (separately-existing) capability findings table, so a
    // zero-findings report must still carry it exactly once — the honesty statement holds even when there is
    // nothing (yet) for --strict to gate on.
    [Fact]
    public void Analyze_ZeroFindings_CapabilityGateNoteStillAppearsExactlyOnce()
    {
        var report = AssemblyReport(methodsTotal: 5, methodsSkipped: 0);
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        AssertGateNoteAppearsExactlyOnce(writer.ToString());
    }
    #endregion

    #region Methods — E: --json is unaffected (model-level: the report record itself)
    [Fact]
    public void Analyze_Json_PropertySetUnaffectedByCapabilityManifest()
    {
        var report = AssemblyReport(
            methodsTotal: 5, methodsSkipped: 0,
            findings: [Finding(Capability.FileSystem), Finding(Capability.Network)]);

        var json = report.ToJson();

        using var doc = JsonDocument.Parse(json);
        Assert.Equal(
            new[] { "Metadata", "Capabilities", "Obfuscation", "Indicators" },
            doc.RootElement.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.DoesNotContain("Manifest", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ScanPackage_Json_PropertySetUnaffectedByCapabilityManifest()
    {
        var report = PackageWith([Analyzed("lib/net10.0/A.dll", 5, 0, findings: [Finding(Capability.Registry)])]);

        var json = report.ToJson();

        using var doc = JsonDocument.Parse(json);
        var properties = doc.RootElement.EnumerateObject().Select(p => p.Name).ToHashSet();
        Assert.True(
            properties.SetEquals(PackageReportJsonProperties),
            $"unexpected top-level property set: {string.Join(", ", properties)}");
        Assert.DoesNotContain("Manifest", json, StringComparison.Ordinal);
    }

    // The end-to-end wiring (Program.cs's json branch calls report.ToJson() directly — it never touches either
    // renderer at all) driven through the real CLI process, on a real assembly with real findings, closing the loop
    // that no future refactor accidentally routes --json through the renderer path where the manifest lives.
    [Fact]
    public void Analyze_Json_EndToEnd_PropertySetUnaffectedByCapabilityManifest()
    {
        var (exit, stdout, stderr, exited) = RunCli("analyze", TargetAssembly, "--json");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.Equal(0, exit);

        using var doc = JsonDocument.Parse(stdout.TrimEnd('\r', '\n'));
        Assert.Equal(
            new[] { "Metadata", "Capabilities", "Obfuscation", "Indicators", "Completeness" },
            doc.RootElement.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.DoesNotContain("Manifest", stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("Manifest", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public void ScanPackage_Json_EndToEnd_PropertySetUnaffectedByCapabilityManifest()
    {
        // The package id deliberately avoids the substring "Manifest" — it would otherwise trip the very
        // DoesNotContain("Manifest", ...) assertion below on its own name, nothing to do with the report shape.
        var nupkg = BuildNupkgWithTargetAssembly("SilvergunCapabilityJsonCheck");
        try
        {
            var (exit, stdout, stderr, exited) =
                RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--json", "--allow-incomplete");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, exit);

            using var doc = JsonDocument.Parse(stdout.TrimEnd('\r', '\n'));
            var properties = doc.RootElement.EnumerateObject().Select(p => p.Name).ToHashSet();
            Assert.True(
                properties.SetEquals(PackageReportJsonProperties.Append("Completeness")),
                $"unexpected top-level property set: {string.Join(", ", properties)}");
            Assert.DoesNotContain("Manifest", stdout, StringComparison.Ordinal);
            Assert.DoesNotContain("Manifest", stderr, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(nupkg);
        }
    }
    #endregion

    #region Methods — F: exit-code independence (ADR-0027: capability presence alone does NOT gate --strict)
    // RENAMED from "...StillExitsTwo_..." (which asserted the policy ADR-0027 overturned): capability presence was
    // measured at 67-81% benign-package prevalence with zero user-would-accept hits and STOPPED gating --strict.
    // This now pins the opposite exit code from what it used to, by name, while still proving the manifest renders
    // regardless — the two facts (rendering vs. gating) are independent and both asserted here.
    [Fact]
    public void AnalyzeExitCode_StrictWithOnlyCapabilityFindings_DoesNotGate_WhileManifestStillRenders()
    {
        var report = AssemblyReport(methodsTotal: 5, methodsSkipped: 0, findings: [Finding(Capability.FileSystem)]);
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        Assert.Contains("Capability manifest", writer.ToString());
        Assert.Equal(0, Program.AnalyzeExitCode(report, strict: true, allowIncomplete: false));
    }

    [Fact]
    public void AnalyzeExitCode_ZeroFindingsAssembly_StillExitsZero_WithManifestAllAbsent()
    {
        var report = AssemblyReport(methodsTotal: 5, methodsSkipped: 0);
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        AssertManifestListsAllCapabilities(writer.ToString(), NoCounts);
        Assert.Equal(0, Program.AnalyzeExitCode(report, strict: true, allowIncomplete: false));
        Assert.Equal(0, Program.AnalyzeExitCode(report, strict: false, allowIncomplete: false));
    }

    [Fact]
    public void ScanPackageExitCode_StrictWithOnlyCapabilityFindings_DoesNotGate_WhileManifestStillRenders()
    {
        var report = Package(Analyzed("lib/net10.0/A.dll", 5, 0, findings: [Finding(Capability.NativeInterop)]));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        Assert.Contains("Capability manifest", writer.ToString());
        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
    }

    [Fact]
    public void ScanPackageExitCode_ZeroFindingsPackage_StillExitsZero_WithManifestAllAbsent()
    {
        var report = Package(Analyzed("lib/net10.0/A.dll", 5, 0));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        AssertManifestListsAllCapabilities(writer.ToString(), NoCounts);
        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
    }
    #endregion

    #region Methods — H: ADR-0027's CapabilityGateNote text itself (task E — this note has been wrong once already)
    // The note's text is asserted directly (not just "appears once" — see helper below), for both rich and plain,
    // because it is the report's ONE honesty statement about what the manifest does and does not control, and it has
    // already been shipped wrong once (see the class doc's CORRECTION above): a blanket "do not touch the manifest"
    // constraint preserved a now-false sentence past the moment ADR-0027 made it false. Pinning only "appears once"
    // would not have caught that regression — the note appeared exactly once either way.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CapabilityGateNote_StatesCapabilityPresenceDoesNotFailTheBuild(bool rich)
    {
        var note = ReportTheme.CapabilityGateNote(rich);

        Assert.Contains("does not fail the build", note, StringComparison.Ordinal);
        Assert.Contains("ADR-0027", note, StringComparison.Ordinal);
        Assert.DoesNotContain("still fails the build", note, StringComparison.Ordinal);
    }
    #endregion

    #region Methods — G: ASCII default mode (ADR 0014) and --rich
    // Narrower than ReportRendererTests' whole-report "AssemblyRenderer_AsciiConsole_EmitsSevenBitAsciiOnly" (which
    // already incidentally covers this section as part of the full report): isolates the manifest's OWN rows so a
    // future change localized to CapabilityManifest/CapabilityGateNote is pinned directly, not just transitively.
    [Fact]
    public void CapabilityManifest_DefaultAsciiMode_RendersWithoutBoxDrawingGlyphsOrColour()
    {
        var report = AssemblyReport(
            methodsTotal: 5, methodsSkipped: 0,
            findings: [Finding(Capability.FileSystem), Finding(Capability.Cryptography)]);
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        var rows = ManifestRows(writer.ToString());
        Assert.NotEmpty(rows);
        Assert.All(rows, row => Assert.True(
            row.All(ch => ch < 128), $"non-ASCII character in manifest row (ADR 0014 violation): '{row}'"));
        Assert.All(rows, row => Assert.DoesNotContain('', row));
    }

    [Fact]
    public void CapabilityManifest_RichMode_RendersWithoutThrowing_AndListsEveryCapability()
    {
        var report = AssemblyReport(
            methodsTotal: 5, methodsSkipped: 0,
            findings: [Finding(Capability.FileSystem), Finding(Capability.Cryptography)]);
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() => AssemblyReportRenderer.Render(console, report));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("Capability manifest", output);
        foreach (var capability in Enum.GetValues<Capability>())
            Assert.Contains(capability.ToString(), output);
    }
    #endregion

    #region Methods — helpers: manifest extraction and assertion
    // The exact section title Section(rich, "Capability manifest") renders and the gate note's most distinctive,
    // collision-free substring — the two anchors every extraction below uses to slice just this section out of a
    // full rendered report. Single pinning point (mirrors FooterHeadline's own rationale): if either literal ever
    // needs to change, it changes here once instead of in every test that locates the section.
    private const string SectionTitle = "Capability manifest";
    private const string GateNoteAnchor = "is informational";

    // Every row of the manifest GRID as rendered directly (not through a full report) — used by the structural
    // guard test, which must count ONLY the grid's own rows.
    private static string[] ManifestGridLines(string output) =>
        [.. output.Split('\n').Select(l => l.TrimEnd('\r', ' ')).Where(l => l.Length > 0)];

    // The manifest's rows as they appear inside a FULLY rendered report: everything strictly between the section
    // header and the gate note that always immediately follows it (see both renderers' Render methods).
    private static string[] ManifestRows(string output)
    {
        var lines = output.Replace("\r\n", "\n").Split('\n');
        var headerIndex = Array.FindIndex(lines, l => l.Contains(SectionTitle, StringComparison.Ordinal));
        Assert.True(headerIndex >= 0, $"no '{SectionTitle}' section header found in the rendered report.");
        var noteIndex = Array.FindIndex(lines, headerIndex + 1, l => l.Contains(GateNoteAnchor, StringComparison.Ordinal));
        Assert.True(noteIndex > headerIndex, "no capability-gate note found after the manifest header.");

        return [.. lines[(headerIndex + 1)..noteIndex].Select(l => l.TrimEnd()).Where(l => l.Length > 0)];
    }

    // The capability names in the order their rows appear — for the ordering acceptance criterion.
    private static string[] ManifestCapabilityOrder(string output) =>
        [.. ManifestRows(output).Select(row =>
            Enum.GetValues<Capability>().Select(c => c.ToString())
                .First(name => row.Contains(name, StringComparison.Ordinal)))];

    // Asserts the manifest lists EVERY current Capability value exactly once, each with the right present/absent
    // marker and the right count (0 for any capability not present in expectedCounts). Shared by every "list all 11"
    // test (analyze zero/mixed, scan-package zero/rollup, and the exit-code-independence renders) so the row-shape
    // assertion lives in exactly one place.
    private static void AssertManifestListsAllCapabilities(string output, IReadOnlyDictionary<Capability, int> expectedCounts)
    {
        var rows = ManifestRows(output);

        // Structural: exactly one row per CURRENT enum value (see the dedicated guard test for why this must never
        // be a literal count).
        Assert.Equal(Enum.GetValues<Capability>().Length, rows.Length);

        foreach (var capability in Enum.GetValues<Capability>())
        {
            var count = expectedCounts.TryGetValue(capability, out var c) ? c : 0;
            var row = Assert.Single(rows, l => l.Contains(capability.ToString(), StringComparison.Ordinal));
            Assert.Contains(count > 0 ? "present" : "absent", row);
            Assert.True(
                row.EndsWith(count.ToString(), StringComparison.Ordinal),
                $"expected the {capability} row to end in count {count}: '{row}'");
        }
    }

    // ADR-0027 re-aim: the note's WORDING changed from "--strict still fails the build on ANY capability present
    // here" to "--strict does not fail the build on capability presence alone (ADR-0027)" — this helper only checks
    // the note appears exactly once and names --strict; the exact CURRENT wording is pinned separately (and more
    // strongly) by CapabilityGateNote_StatesCapabilityPresenceDoesNotFailTheBuild above, so a future wording change
    // fails there with an unambiguous diff rather than silently loosening this shared "appears once" helper.
    private static void AssertGateNoteAppearsExactlyOnce(string output)
    {
        var lines = output.Split('\n').Select(l => l.TrimEnd('\r'));
        var line = Assert.Single(lines, l => l.Contains(GateNoteAnchor, StringComparison.Ordinal));
        Assert.Contains("--strict", line, StringComparison.Ordinal);
    }

    private static ApiCallFinding Finding(
        Capability capability, string callerType = "T", string callerMethod = "M", string calledApi = "Some.Api.Call") =>
        new(capability, ApiCallKind.Call, callerType, callerMethod, calledApi);
    #endregion

    #region Methods — helpers: consoles (duplicated, not shared, per project convention — see ApphostPath.cs)
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

    private static (IAnsiConsole Console, StringWriter Writer) RichConsole()
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.Yes,
            ColorSystem = ColorSystemSupport.Standard,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = true;
        console.Profile.Width = 240;
        return (console, writer);
    }
    #endregion

    #region Methods — helpers: real CLI process (end-to-end E), mirrors CompletenessCliTests/IndicatorEndToEndTests
    private static (int Exit, string Output, string Error, bool Exited) RunCli(params string[] args)
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
        var exited = process.WaitForExit(TimeoutMs);
        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            return (-1, string.Empty, string.Empty, false);
        }

        return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), true);
    }

    // Writes a minimal valid .nupkg carrying the real TargetAssembly as its one lib dll — mirrors
    // IndicatorEndToEndTests.BuildNupkgWithFixtureAssembly, using pure BCL zip.
    private static string BuildNupkgWithTargetAssembly(string id)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>Capability manifest --json regression package.</description>
                <dependencies>
                  <group targetFramework="netstandard2.0" />
                </dependencies>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-capability-manifest-json-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
            Write(zip, "lib/netstandard2.0/Silvergun.CodeAnalysis.IL.dll", File.ReadAllBytes(TargetAssembly));
        }
        return path;

        static void Write(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private static readonly IReadOnlyDictionary<Capability, int> NoCounts = new Dictionary<Capability, int>();

    // AssemblyAnalysisReport's own top-level property names — E's oracle for "the report record didn't change".
    private static readonly string[] PackageReportJsonProperties =
    [
        "Package", "AnalyzedAt", "Assemblies", "Scripts", "ScriptFindings", "ProjectHealth",
        "YaraFindings", "Vulnerabilities", "VulnerabilitiesStatus", "ResolvedDependencies", "DependencyResolution",
        "YaraScanStatus",
    ];

    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    // A real, non-trivial managed assembly guaranteed present in test output (same trick CompletenessCliTests uses):
    // exercises the real analyze/scan-package --json paths without needing a bespoke fixture.
    private static readonly string TargetAssembly =
        Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.dll");

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    private const int TimeoutMs = 120_000;
    #endregion
}
