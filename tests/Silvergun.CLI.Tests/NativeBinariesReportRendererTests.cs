namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The "Native binaries" section and footer count line of <see cref="PackageReportRenderer"/> (native-binaries-1).
/// Structured like <see cref="PackagingAnomaliesReportRendererTests"/>: rows / "(none)" / "(not run)" / the Unavailable
/// note with its reason; markup-injection safety and 7-bit ASCII by default; and — the facts-layer invariant — the
/// "Clean" headline is not moved by native binaries, an executable among them, or an incomplete native scan.
/// </summary>
public sealed class NativeBinariesReportRendererTests
{
    #region Methods: the section
    [Fact]
    public void PackageRenderer_WithNativeBinaries_ShowsOneRowPerBinaryWithItsFields()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Node(), MixedDll()), "Native.nupkg");

        var output = writer.ToString();
        Assert.Contains("Native binaries", output, StringComparison.Ordinal);
        var nodeRow = Assert.Single(Lines(output), l => l.Contains("tools/node", StringComparison.Ordinal));
        Assert.Contains("Executable", nodeRow, StringComparison.Ordinal);
        Assert.Contains("Elf", nodeRow, StringComparison.Ordinal);
        Assert.Contains("x64", nodeRow, StringComparison.Ordinal);
        Assert.Contains("Tools", nodeRow, StringComparison.Ordinal);
        Assert.Contains("123456", nodeRow, StringComparison.Ordinal);
        var dllRow = Assert.Single(Lines(output), l => l.Contains("lib/net8.0/mixed.dll", StringComparison.Ordinal));
        Assert.Contains("SharedLibrary", dllRow, StringComparison.Ordinal);
        Assert.Contains("PE (mixed-mode)", dllRow, StringComparison.Ordinal);
        Assert.Contains("Lib", dllRow, StringComparison.Ordinal);
    }

    // The Format column names what code a PE carries; a Native PE and every non-PE show the bare format.
    [Theory]
    [InlineData(NativeBinaryCode.MixedMode, "PE (mixed-mode)")]
    [InlineData(NativeBinaryCode.ReadyToRun, "PE (ReadyToRun)")]
    [InlineData(NativeBinaryCode.ILOnly, "PE (IL-only, not analysed)")]
    public void PackageRenderer_FormatColumn_NamesThePesCode(NativeBinaryCode code, string label)
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Pe("tools/payload", code)), "Native.nupkg");

        var row = Assert.Single(Lines(writer.ToString()), l => l.Contains("tools/payload", StringComparison.Ordinal));
        Assert.Contains(label, row, StringComparison.Ordinal);
    }

    [Fact]
    public void PackageRenderer_FormatColumn_ForANativePe_IsTheBareFormat()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Pe("lib/net8.0/native.dll", NativeBinaryCode.Native)), "Native.nupkg");

        var row = Assert.Single(Lines(writer.ToString()), l => l.Contains("lib/net8.0/native.dll", StringComparison.Ordinal));
        Assert.Matches(@"\|\s+PE\s+\|", row);
        Assert.DoesNotContain("PE (", row, StringComparison.Ordinal);
    }

    // A Malformed binary has no architecture: the cell reads "-", not blank and not a crash.
    [Fact]
    public void PackageRenderer_WithANullArchitecture_ShowsADash()
    {
        var (console, writer) = AsciiConsole();
        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Malformed()), "Native.nupkg");

        var row = Assert.Single(Lines(writer.ToString()), l => l.Contains("libx.dylib", StringComparison.Ordinal));
        Assert.Contains("Malformed", row, StringComparison.Ordinal);
        Assert.Matches(@"\|\s+-\s+\|", row);
    }

    // The section follows Packaging anomalies.
    [Fact]
    public void PackageRenderer_TheSectionFollowsPackagingAnomalies()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Node()), "Native.nupkg");

        var output = writer.ToString();
        var anomalies = output.IndexOf("Packaging anomalies", StringComparison.Ordinal);
        var native = output.IndexOf("Native binaries", StringComparison.Ordinal);
        Assert.True(anomalies >= 0 && native > anomalies, "the Native binaries section must come after Packaging anomalies.");
    }

    [Fact]
    public void PackageRenderer_WithACompletedEmptyScan_RendersNone()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed), "Managed.nupkg");

        Assert.Equal("(none)", SectionBody(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_WithANotRunScan_RendersNotRun()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.NotRun), "Managed.nupkg");

        Assert.Equal("(not run)", SectionBody(writer.ToString()));
    }

    // Unavailable and empty: the "did NOT complete" note and its reason, never "(none)".
    [Fact]
    public void PackageRenderer_WithAnUnavailableEmptyScan_ShowsTheNoteAndTheReason_NotNone()
    {
        var (console, writer) = AsciiConsole();
        var report = ReportWith(NativeBinaryScanStatus.Unavailable) with
        {
            NativeBinaryScanUnavailableReason = "1 file(s) could not be read for a native header: tools/x (IOException)",
        };

        PackageReportRenderer.Render(console, report, "Locked.nupkg");

        var body = SectionBody(writer.ToString());
        Assert.Contains("[!] native binary scan did NOT complete - the list may be missing files", body, StringComparison.Ordinal);
        Assert.Contains("Reason: 1 file(s) could not be read for a native header: tools/x (IOException)", body, StringComparison.Ordinal);
        Assert.DoesNotContain("(none)", body, StringComparison.Ordinal);
    }

    [Fact]
    // Unavailable with no binaries and no reason is the legacy default (a report that predates the field): PackageScanner
    // always sets a reason for a real Unavailable. It reads "not recorded", never the "did NOT complete" warning, and the
    // footer says the same.
    public void PackageRenderer_WithAnUnavailableScanAndNoReason_ReadsAsNotRecorded()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Unavailable), "Legacy.nupkg");

        var body = SectionBody(writer.ToString());
        Assert.Contains("(not recorded in this report)", body, StringComparison.Ordinal);
        Assert.DoesNotContain("native binary scan did NOT complete", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Reason:", body, StringComparison.Ordinal);
        Assert.Equal("Native binaries: not recorded", FooterLine(writer.ToString()));
    }

    // A real Unavailable with no binaries found: the note and its reason line.
    [Fact]
    public void PackageRenderer_WithAnUnavailableScanAndAReason_ShowsTheNoteAndReason()
    {
        var (console, writer) = AsciiConsole();
        var report = ReportWith(NativeBinaryScanStatus.Unavailable) with { NativeBinaryScanUnavailableReason = "1 file(s) could not be read" };

        PackageReportRenderer.Render(console, report, "Partial.nupkg");

        var body = SectionBody(writer.ToString());
        Assert.Contains("native binary scan did NOT complete", body, StringComparison.Ordinal);
        Assert.Contains("Reason: 1 file(s) could not be read", body, StringComparison.Ordinal);
    }

    // Unavailable with binaries: the note sits above the table, and the rows are still shown (they are real).
    [Fact]
    public void PackageRenderer_WithAnUnavailableScanAndBinaries_ShowsTheNoteAboveTheRows()
    {
        var (console, writer) = AsciiConsole();
        var report = ReportWith(NativeBinaryScanStatus.Unavailable, Node()) with { NativeBinaryScanUnavailableReason = "why" };

        PackageReportRenderer.Render(console, report, "Partial.nupkg");

        var body = SectionBody(writer.ToString());
        var note = body.IndexOf("native binary scan did NOT complete", StringComparison.Ordinal);
        var row = body.IndexOf("tools/node", StringComparison.Ordinal);
        Assert.True(note >= 0 && row > note, "the Unavailable note must precede the rows.");
        Assert.Contains("Reason: why", body, StringComparison.Ordinal);
    }

    // A report built without the fields (the record default: empty + Unavailable) renders without throwing.
    [Fact]
    public void PackageRenderer_WhenTheFieldsWereNeverPopulated_RendersWithoutThrowing()
    {
        var (console, writer) = AsciiConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, BaseReport(), "Legacy.nupkg"));

        Assert.Null(ex);
        Assert.Contains("(not recorded in this report)", writer.ToString(), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the footer
    [Fact]
    public void PackageRenderer_Footer_CountsBinariesAndExecutables()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Node(), MixedDll(), Node("tools/chromedriver")), "Native.nupkg");

        Assert.Equal("Native binaries: 3 (2 executable(s))", FooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_Footer_WithOnlyLibraries_HasNoExecutableCount()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, MixedDll()), "Native.nupkg");

        Assert.Equal("Native binaries: 1", FooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_Footer_WithNone_IsZero()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed), "Managed.nupkg");

        Assert.Equal("Native binaries: 0", FooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_Footer_WhenUnavailable_SaysIncomplete()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Unavailable, Node()), "Partial.nupkg");

        Assert.Equal("Native binaries: 1 (1 executable(s)) (scan INCOMPLETE - may be missing files)", FooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_Footer_WhenNotRunWithNoBinaries_SaysNotRun()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.NotRun), "Managed.nupkg");

        Assert.Equal("Native binaries: not run", FooterLine(writer.ToString()));
    }

    // NotRun with binaries (hand-built; PackageScanner never produces it) still counts what is there.
    [Fact]
    public void PackageRenderer_Footer_WhenNotRunWithBinaries_CountsThem()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.NotRun, MixedDll()), "Native.nupkg");

        Assert.Equal("Native binaries: 1", FooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_Footer_WithAMalformedBinary_AddsTheMalformedCount()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Malformed(), MixedDll()), "Native.nupkg");

        Assert.Equal("Native binaries: 2 (1 malformed)", FooterLine(writer.ToString()));
    }

    // Suffix order: executables, then malformed, then the INCOMPLETE note.
    [Fact]
    public void PackageRenderer_Footer_SuffixesComeInOrder()
    {
        var (console, writer) = AsciiConsole();
        var report = ReportWith(NativeBinaryScanStatus.Unavailable, Node(), Malformed(), Malformed("tools/bad")) with { NativeBinaryScanUnavailableReason = "why" };

        PackageReportRenderer.Render(console, report, "Partial.nupkg");

        Assert.Equal("Native binaries: 3 (1 executable(s)) (2 malformed) (scan INCOMPLETE - may be missing files)", FooterLine(writer.ToString()));
    }
    #endregion

    #region Methods: the verdict headline is not moved (facts layer, not gating)
    [Theory]
    [InlineData(NativeBinaryScanStatus.Completed)]
    [InlineData(NativeBinaryScanStatus.Unavailable)]
    [InlineData(NativeBinaryScanStatus.NotRun)]
    public void PackageRenderer_WithNativeExecutables_StillReportsTheCleanVerdict(NativeBinaryScanStatus status)
    {
        var (console, writer) = AsciiConsole();
        var report = ReportWith(status, Node(), MixedDll()) with
        {
            NativeBinaryScanUnavailableReason = status == NativeBinaryScanStatus.Unavailable ? "1 file(s) could not be read" : null,
        };

        PackageReportRenderer.Render(console, report, "Native.nupkg");

        Assert.Equal(FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail), FooterHeadline.Of(writer));
    }

    [Fact]
    public void PackageRenderer_WithNativeExecutables_UnicodeConsole_StillReportsTheCleanVerdict()
    {
        // Unicode glyphs (the rich path) but no ANSI, so the headline line is matchable.
        var (console, writer) = AsciiConsole();
        console.Profile.Capabilities.Unicode = true;

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Unavailable, Node()), "Native.nupkg");

        Assert.Equal(FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail), FooterHeadline.Of(writer));
    }
    #endregion

    #region Methods: encoding and markup invariants
    [Fact]
    public void PackageRenderer_WithNativeBinaries_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Unavailable, Node(), MixedDll()) with { NativeBinaryScanUnavailableReason = "why" }, "Native.nupkg");

        var output = writer.ToString();
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
        Assert.DoesNotContain("[/]", output);
        Assert.DoesNotContain("[orange1]", output);
        Assert.DoesNotContain("[yellow]", output);
    }

    // Markup in the path, the architecture and the reason renders literally in both modes; were any unescaped, the
    // unterminated tag would make Spectre throw.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PackageRenderer_WithMarkupInjectionInEveryTextField_RendersLiterallyWithoutThrowing(bool rich)
    {
        var (console, writer) = rich ? RichConsole() : AsciiConsole();
        var injected = new NativeBinary(Inject, NativeBinaryFormat.Elf, NativeBinaryKind.Executable, Inject, NativeBinaryCode.Native,
            PackageItemRole.Other, 1, new string('d', 64));
        var report = ReportWith(NativeBinaryScanStatus.Unavailable, injected) with { NativeBinaryScanUnavailableReason = Inject };

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, report, "clean.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("PWNED", output, StringComparison.Ordinal);
        Assert.Contains("[red]", output, StringComparison.Ordinal);
    }

    // The path arrives escaped at the DTO; the widget must print the escape sequence, not reintroduce the character.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PackageRenderer_WithAnEscapedPath_PrintsTheEscapeSequenceLiterally(bool rich)
    {
        var (console, writer) = rich ? RichConsole() : AsciiConsole();
        var escaped = @"tools/no\" + "u202ede";

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Node(escaped)), "Evil.nupkg");

        var output = writer.ToString();
        Assert.Contains(escaped, output, StringComparison.Ordinal);
        Assert.DoesNotContain((char)0x202E, output);
    }
    #endregion

    #region Methods: fixtures
    private static NativeBinary Node(string path = "tools/node") =>
        new(path, NativeBinaryFormat.Elf, NativeBinaryKind.Executable, "x64", NativeBinaryCode.Native, PackageItemRole.Tools, 123456, new string('a', 64));

    private static NativeBinary MixedDll() =>
        new("lib/net8.0/mixed.dll", NativeBinaryFormat.PE, NativeBinaryKind.SharedLibrary, "x86", NativeBinaryCode.MixedMode, PackageItemRole.Lib, 2048, new string('b', 64));

    private static NativeBinary Pe(string path, NativeBinaryCode code) =>
        new(path, NativeBinaryFormat.PE, NativeBinaryKind.SharedLibrary, "x64", code, PackageItemRole.Other, 4096, new string('e', 64));

    private static NativeBinary Malformed(string path = "runtimes/osx/native/libx.dylib") =>
        new(path, NativeBinaryFormat.MachOUniversal, NativeBinaryKind.Malformed, null, NativeBinaryCode.Native, PackageItemRole.Runtimes, 8, new string('c', 64));

    // Otherwise clean and fully verified (OSV, YARA, scripts Completed), so the headline is decided by native binaries alone.
    private static PackageCapabilityReport ReportWith(NativeBinaryScanStatus status, params NativeBinary[] binaries) =>
        BaseReport() with { NativeBinaries = binaries, NativeBinaryScanStatus = status };

    private static PackageCapabilityReport BaseReport() =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            VulnerabilitiesStatus: VulnerabilityScanStatus.Completed,
            YaraScanStatus: YaraScanStatus.Completed,
            ScriptScanStatus: ScriptScanStatus.Completed);

    private static string[] Lines(string output) => [.. output.Split('\n').Select(l => l.TrimEnd('\r', ' '))];

    // The footer's one "Native binaries:" count line.
    private static string FooterLine(string output) =>
        Assert.Single(Lines(output), l => l.StartsWith("Native binaries:", StringComparison.Ordinal));

    // The lines between the ASCII "-- Native binaries --" section header and the next blank line or section header,
    // trimmed and joined.
    private static string SectionBody(string output)
    {
        var lines = Lines(output);
        var header = Array.FindIndex(lines, l => l.StartsWith("-- Native binaries", StringComparison.Ordinal));
        Assert.True(header >= 0, "no Native binaries section header.");
        return string.Join("\n", lines.Skip(header + 1)
            .TakeWhile(l => l.Trim().Length > 0 && !l.StartsWith("-- ", StringComparison.Ordinal))
            .Select(l => l.Trim()));
    }

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

    #region Fields
    private const string Inject = "[red]PWNED[/][unterminated";
    #endregion
}
