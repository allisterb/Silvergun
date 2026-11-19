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
/// native-binaries-2 in <see cref="PackageReportRenderer"/>: the Kind-cell suffix for each <see cref="DotNetHost"/>, the
/// footer's apphost and single-file-bundle counts and their place in the suffix order, 7-bit ASCII and markup safety,
/// and the facts-layer invariant (the Clean headline is not moved by a bundle).
/// </summary>
public sealed class DotNetHostReportRendererTests
{
    #region Methods: the Kind cell
    [Fact]
    public void PackageRenderer_AnAppHost_IsLabelledAfterItsKind()
    {
        var row = RowFor(Exe("tools/mytool", DotNetHost.AppHost), "tools/mytool");

        Assert.Contains("Executable (.NET apphost)", row, StringComparison.Ordinal);
    }

    [Fact]
    public void PackageRenderer_ABundleWithACount_SaysItWasUnpacked()
    {
        var row = RowFor(Exe("tools/Squirrel.exe", DotNetHost.SingleFileBundle, 118), "tools/Squirrel.exe");

        Assert.Contains("Executable (.NET single-file bundle, 118 file(s), unpacked)", row, StringComparison.Ordinal);
    }

    [Fact]
    public void PackageRenderer_ABundleWithAZeroCount_ShowsTheZero()
    {
        var row = RowFor(Exe("tools/Empty.exe", DotNetHost.SingleFileBundle, 0), "tools/Empty.exe");

        Assert.Contains("(.NET single-file bundle, 0 file(s), unpacked)", row, StringComparison.Ordinal);
    }

    [Fact]
    public void PackageRenderer_ABundleWithNoCount_SaysNotUnpacked()
    {
        var row = RowFor(Exe("tools/Update.exe", DotNetHost.SingleFileBundle), "tools/Update.exe");

        Assert.Contains("Executable (.NET single-file bundle, NOT unpacked)", row, StringComparison.Ordinal);
        Assert.DoesNotContain("file(s)", row, StringComparison.Ordinal);
    }

    // native-binaries-3: a bundle nested in a bundle ("!/" in its path) is not unpacked, even with a readable count.
    [Fact]
    public void PackageRenderer_ANestedBundleWithACount_SaysNotUnpacked()
    {
        var row = RowFor(Exe("tools/App.exe!/inner.exe", DotNetHost.SingleFileBundle, 3), "tools/App.exe!/inner.exe");

        Assert.Contains("Executable (.NET single-file bundle, NOT unpacked)", row, StringComparison.Ordinal);
        Assert.DoesNotContain("file(s)", row, StringComparison.Ordinal);
    }

    [Fact]
    public void PackageRenderer_AHostTemplate_IsLabelled()
    {
        var row = RowFor(Exe("tools/apphost.exe", DotNetHost.HostTemplate), "tools/apphost.exe");

        Assert.Contains("Executable (.NET host template)", row, StringComparison.Ordinal);
    }

    // The label follows any kind, not just Executable (it describes the bytes, not the PE characteristics).
    [Fact]
    public void PackageRenderer_TheLabel_FollowsANonExecutableKind()
    {
        var lib = Exe("tools/host.dll", DotNetHost.AppHost) with { Kind = NativeBinaryKind.SharedLibrary };

        Assert.Contains("SharedLibrary (.NET apphost)", RowFor(lib, "tools/host.dll"), StringComparison.Ordinal);
    }

    [Fact]
    public void PackageRenderer_NoHost_HasNoLabel()
    {
        var row = RowFor(Exe("tools/node", DotNetHost.None), "tools/node");

        Assert.DoesNotContain(".NET", row, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the footer
    [Fact]
    public void PackageRenderer_Footer_CountsAppHostsAndBundles_ButNotTemplates()
    {
        var (console, writer) = AsciiConsole();
        var report = ReportWith(NativeBinaryScanStatus.Completed,
            Exe("tools/a", DotNetHost.AppHost), Exe("tools/b.exe", DotNetHost.AppHost),
            Exe("tools/Squirrel.exe", DotNetHost.SingleFileBundle, 118), Exe("tools/apphost.exe", DotNetHost.HostTemplate),
            Exe("tools/node", DotNetHost.None));

        PackageReportRenderer.Render(console, report, "Hosts.nupkg");

        Assert.Equal("Native binaries: 5 (5 executable(s)) (2 .NET apphost(s)) (1 .NET single-file bundle(s))", FooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_Footer_WithOnlyABundle_HasNoAppHostCount()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Exe("tools/Update.exe", DotNetHost.SingleFileBundle)), "Bundle.nupkg");

        Assert.Equal("Native binaries: 1 (1 executable(s)) (1 .NET single-file bundle(s))", FooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_Footer_WithOnlyATemplate_AddsNoHostCount()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, Exe("tools/apphost.exe", DotNetHost.HostTemplate)), "Template.nupkg");

        Assert.Equal("Native binaries: 1 (1 executable(s))", FooterLine(writer.ToString()));
    }

    // Suffix order: executables, apphosts, bundles, malformed, then the INCOMPLETE note.
    [Fact]
    public void PackageRenderer_Footer_HostCountsSitBetweenExecutablesAndMalformed()
    {
        var (console, writer) = AsciiConsole();
        var report = ReportWith(NativeBinaryScanStatus.Unavailable,
            Exe("tools/a", DotNetHost.AppHost), Exe("tools/Squirrel.exe", DotNetHost.SingleFileBundle, 118), Malformed())
            with { NativeBinaryScanUnavailableReason = "why" };

        PackageReportRenderer.Render(console, report, "Partial.nupkg");

        Assert.Equal(
            "Native binaries: 3 (2 executable(s)) (1 .NET apphost(s)) (1 .NET single-file bundle(s)) (1 malformed) (scan INCOMPLETE - may be missing files)",
            FooterLine(writer.ToString()));
    }
    #endregion

    #region Methods: the verdict headline is not moved
    [Fact]
    public void PackageRenderer_WithABundleAndAnAppHost_StillReportsTheCleanVerdict()
    {
        var (console, writer) = AsciiConsole();
        var report = ReportWith(NativeBinaryScanStatus.Completed,
            Exe("tools/Squirrel.exe", DotNetHost.SingleFileBundle, 118), Exe("tools/a", DotNetHost.AppHost));

        PackageReportRenderer.Render(console, report, "Hosts.nupkg");

        Assert.Equal(FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail), FooterHeadline.Of(writer));
    }
    #endregion

    #region Methods: encoding and markup invariants
    [Fact]
    public void PackageRenderer_WithEveryHostLabel_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, AllLabels()), "Hosts.nupkg");

        var output = writer.ToString();
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
        Assert.DoesNotContain("[/]", output);
        Assert.DoesNotContain("[grey]", output);
        Assert.DoesNotContain("[orange1]", output);
    }

    // Rich mode renders the labels (markup balanced, so Spectre does not throw) with their text intact.
    [Fact]
    public void PackageRenderer_WithEveryHostLabel_RichConsole_RendersTheLabels()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, AllLabels()), "Hosts.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("(.NET apphost)", output, StringComparison.Ordinal);
        Assert.Contains("(.NET single-file bundle, 118 file(s), unpacked)", output, StringComparison.Ordinal);
        Assert.Contains("(.NET single-file bundle, NOT unpacked)", output, StringComparison.Ordinal);
        Assert.Contains("(.NET host template)", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[/]", output);
    }

    // A labelled row with markup in its path and architecture still renders those literally, in both modes.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PackageRenderer_ALabelledRowWithMarkupInjection_RendersLiterallyWithoutThrowing(bool rich)
    {
        var (console, writer) = rich ? RichConsole() : AsciiConsole();
        var injected = Exe(Inject, DotNetHost.SingleFileBundle, 5) with { Architecture = Inject };

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, injected), "clean.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("PWNED", output, StringComparison.Ordinal);
        Assert.Contains("[red]", output, StringComparison.Ordinal);
        Assert.Contains("(.NET single-file bundle, 5 file(s), unpacked)", output, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: fixtures
    private static string RowFor(NativeBinary binary, string path)
    {
        var (console, writer) = AsciiConsole();
        PackageReportRenderer.Render(console, ReportWith(NativeBinaryScanStatus.Completed, binary), "Hosts.nupkg");
        return Assert.Single(Lines(writer.ToString()), l => l.Contains(path, StringComparison.Ordinal) && l.Contains('|'));
    }

    private static NativeBinary[] AllLabels() =>
    [
        Exe("tools/a", DotNetHost.AppHost),
        Exe("tools/Squirrel.exe", DotNetHost.SingleFileBundle, 118),
        Exe("tools/Update.exe", DotNetHost.SingleFileBundle),
        Exe("tools/apphost.exe", DotNetHost.HostTemplate),
    ];

    private static NativeBinary Exe(string path, DotNetHost host, int? bundled = null) =>
        new(path, NativeBinaryFormat.PE, NativeBinaryKind.Executable, "x64", NativeBinaryCode.Native, PackageItemRole.Tools, 150016,
            new string('a', 64), host, bundled);

    private static NativeBinary Malformed() =>
        new("runtimes/osx/native/libx.dylib", NativeBinaryFormat.MachOUniversal, NativeBinaryKind.Malformed, null, NativeBinaryCode.Native,
            PackageItemRole.Runtimes, 8, new string('c', 64));

    // Otherwise clean and fully verified, so the headline is decided by native binaries alone.
    private static PackageCapabilityReport ReportWith(NativeBinaryScanStatus status, params NativeBinary[] binaries) =>
        new PackageCapabilityReport(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            VulnerabilitiesStatus: VulnerabilityScanStatus.Completed,
            YaraScanStatus: YaraScanStatus.Completed,
            ScriptScanStatus: ScriptScanStatus.Completed) with { NativeBinaries = binaries, NativeBinaryScanStatus = status };

    private static string[] Lines(string output) => [.. output.Split('\n').Select(l => l.TrimEnd('\r', ' '))];

    private static string FooterLine(string output) =>
        Assert.Single(Lines(output), l => l.StartsWith("Native binaries:", StringComparison.Ordinal));

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
