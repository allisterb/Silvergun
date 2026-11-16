namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// <c>docs/agent/tasks/hidden-payloads-1.md</c> §7: obfuscation findings name their source when it is not a whole
/// constant, and images-only obfuscation is listed but never sets the "attention" headline or the "present" footer.
/// Reports are constructed directly so the tests pin the renderer's predicate, not what an analysis happens to produce.
/// </summary>
public sealed class ObfuscationSourceRenderingTests
{
    #region Methods — source suffix
    [Theory]
    [InlineData(HiddenContentSource.Substring, "(inside a constant)")]
    [InlineData(HiddenContentSource.Folded, "(concatenated constants)")]
    [InlineData(HiddenContentSource.FieldData, "(field data)")]
    [InlineData(HiddenContentSource.Resource, "(embedded resource)")]
    public void ObfuscationDetected_NonConstantSource_AppendsSourceText(HiddenContentSource source, string suffix) =>
        Assert.Equal($"Windows PE {suffix}", ReportTheme.ObfuscationDetected(Finding(HiddenContentKind.EncodedExecutable, "Windows PE", source)));

    [Fact]
    public void ObfuscationDetected_ConstantSource_IsDetectedAsUnchanged() =>
        Assert.Equal("Windows PE", ReportTheme.ObfuscationDetected(Finding(HiddenContentKind.EncodedExecutable, "Windows PE")));

    [Fact]
    public void IsAttentionObfuscation_OnlyImagesAreExcluded()
    {
        foreach (var kind in Enum.GetValues<HiddenContentKind>())
            Assert.Equal(kind != HiddenContentKind.EncodedImage, ReportTheme.IsAttentionObfuscation(Finding(kind, "x")));
    }

    [Fact]
    public void AssemblyRenderer_FoldedFinding_ShowsSourceInDetectedAs()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyWith(Finding(HiddenContentKind.EncodedExecutable, "Windows PE", HiddenContentSource.Folded)));

        Assert.Contains("Windows PE (concatenated constants)", writer.ToString());
    }

    [Fact]
    public void AssemblyRenderer_ConstantFinding_ShowsNoSourceSuffix()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyWith(Finding(HiddenContentKind.EncodedExecutable, "Windows PE")));

        Assert.Contains("Windows PE", writer.ToString());
        Assert.DoesNotContain("Windows PE (", writer.ToString());
    }

    [Fact]
    public void PackageRenderer_ResourceFinding_ShowsSourceInDetectedAs()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, PackageWith(Finding(HiddenContentKind.EncodedExecutable, "Windows PE", HiddenContentSource.Resource)), "P.1.0.0.nupkg");

        Assert.Contains("Windows PE (embedded resource)", writer.ToString());
    }
    #endregion

    #region Methods — images do not set attention (assembly)
    [Fact]
    public void AssemblyRenderer_ImagesOnly_ListsImageButHeadlineStaysClean()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyWith(Finding(HiddenContentKind.EncodedImage, "PNG", HiddenContentSource.Resource)));

        var output = writer.ToString();
        Assert.Contains("PNG", output);
        Assert.Equal(FooterHeadline.Clean(console, FooterHeadline.AssemblyCleanDetail), FooterHeadline.Of(writer));
        Assert.Contains("Obfuscation: 1 embedded image(s) only", output);
        Assert.DoesNotContain("finding(s)", ObfuscationFooterLine(output));
    }

    [Fact]
    public void AssemblyRenderer_ImageAndExecutable_HeadlineReadsFindingsPresent()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyWith(
            Finding(HiddenContentKind.EncodedImage, "PNG"),
            Finding(HiddenContentKind.EncodedExecutable, "Windows PE", HiddenContentSource.FieldData)));

        Assert.Equal(FooterHeadline.FindingsPresent(console), FooterHeadline.Of(writer));
        Assert.Equal("Obfuscation: 2 finding(s)", ObfuscationFooterLine(writer.ToString()));
    }

    [Theory]
    [InlineData(HiddenContentKind.EncodedText, "UTF-16LE text")]
    [InlineData(HiddenContentKind.HighEntropyBlob, "high-entropy base64")]
    [InlineData(HiddenContentKind.EncodedArchive, "zip")]
    public void AssemblyRenderer_NonImageFinding_HeadlineReadsFindingsPresent(HiddenContentKind kind, string detected)
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyWith(Finding(kind, detected)));

        Assert.Equal(FooterHeadline.FindingsPresent(console), FooterHeadline.Of(writer));
    }
    #endregion

    #region Methods — images do not set attention (package)
    [Fact]
    public void PackageRenderer_ImagesOnly_HeadlineStaysCleanAndFooterSaysImagesOnly()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, PackageWith(Finding(HiddenContentKind.EncodedImage, "PNG", HiddenContentSource.Resource)), "P.1.0.0.nupkg");

        Assert.Equal(FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail), FooterHeadline.Of(writer));
        Assert.Equal("Obfuscation: embedded images only", ObfuscationFooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_NonImageFinding_HeadlineReadsFindingsPresent()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, PackageWith(Finding(HiddenContentKind.EncodedText, "UTF-8 text", HiddenContentSource.Substring)), "P.1.0.0.nupkg");

        Assert.Equal(FooterHeadline.FindingsPresent(console), FooterHeadline.Of(writer));
        Assert.Equal("Obfuscation: present", ObfuscationFooterLine(writer.ToString()));
    }
    #endregion

    #region Methods — truncated reports and the package tree node
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AssemblyRenderer_TruncatedObfuscation_ShowsTheFloorLine(bool withFindings)
    {
        var (console, writer) = PlainConsole();
        var findings = withFindings ? new[] { Finding(HiddenContentKind.EncodedExecutable, "Windows PE", HiddenContentSource.Folded) } : Array.Empty<ObfuscationFinding>();

        AssemblyReportRenderer.Render(console, AssemblyReport(methodsTotal: 5, methodsSkipped: 0) with { Obfuscation = Report(findings) with { Truncated = true } });

        var output = writer.ToString();
        Assert.Contains("obfuscation analysis TRUNCATED", output);
        Assert.Contains("FLOOR", output);
    }

    [Fact]
    public void AssemblyRenderer_UntruncatedObfuscation_ShowsNoFloorLine()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyWith(Finding(HiddenContentKind.EncodedExecutable, "Windows PE")));

        Assert.DoesNotContain("obfuscation analysis TRUNCATED", writer.ToString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PackageRenderer_TruncatedObfuscation_ShowsTheFloorLine(bool withFindings)
    {
        var (console, writer) = PlainConsole();
        var findings = withFindings ? new[] { Finding(HiddenContentKind.EncodedImage, "PNG", HiddenContentSource.Resource) } : Array.Empty<ObfuscationFinding>();
        var package = Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 5, methodsSkipped: 0) with { Obfuscation = Report(findings) with { Truncated = true } });

        PackageReportRenderer.Render(console, package, "P.1.0.0.nupkg");

        Assert.Contains("obfuscation: TRUNCATED", writer.ToString());
        Assert.Contains("FLOOR", writer.ToString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AssemblyRenderer_TruncatedObfuscation_FooterLineCarriesTheCaveat(bool withFindings)
    {
        var (console, writer) = PlainConsole();
        var findings = withFindings ? new[] { Finding(HiddenContentKind.EncodedExecutable, "Windows PE") } : Array.Empty<ObfuscationFinding>();

        AssemblyReportRenderer.Render(console, AssemblyReport(methodsTotal: 5, methodsSkipped: 0) with { Obfuscation = Report(findings) with { Truncated = true } });

        Assert.EndsWith("(truncated - floor, not a total)", ObfuscationFooterLine(writer.ToString()));
    }

    [Fact]
    public void AssemblyRenderer_UntruncatedObfuscation_FooterLineHasNoCaveat()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyWith(Finding(HiddenContentKind.EncodedExecutable, "Windows PE")));

        Assert.DoesNotContain("truncated", ObfuscationFooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_TruncatedObfuscation_FooterLineNamesTheAssembly_AndTheTreeNodeUsesTheAsciiDash()
    {
        var (console, writer) = PlainConsole();
        var package = Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 5, methodsSkipped: 0) with { Obfuscation = Report() with { Truncated = true } });

        PackageReportRenderer.Render(console, package, "P.1.0.0.nupkg");

        var output = writer.ToString();
        Assert.Contains("(TRUNCATED for lib/net10.0/A.dll - a floor, not a total)", ObfuscationFooterLine(output));
        Assert.Contains("obfuscation: TRUNCATED (a blob or fold budget was spent) - these findings are a FLOOR, not a total", output);
    }

    [Fact]
    public void PackageRenderer_UntruncatedObfuscation_FooterLineHasNoCaveat()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, PackageWith(Finding(HiddenContentKind.EncodedExecutable, "Windows PE")), "P.1.0.0.nupkg");

        Assert.DoesNotContain("TRUNCATED", ObfuscationFooterLine(writer.ToString()));
    }

    [Fact]
    public void PackageRenderer_ImagesOnlyTreeNode_ReadsEmbeddedImagesNotFindings()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, PackageWith(Finding(HiddenContentKind.EncodedImage, "PNG", HiddenContentSource.Resource)), "P.1.0.0.nupkg");

        Assert.Contains("obfuscation: 1 embedded image(s)", writer.ToString());
        Assert.DoesNotContain("obfuscation: 1 finding(s)", writer.ToString());
    }

    [Fact]
    public void PackageRenderer_NonImageTreeNode_ReadsFindings()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, PackageWith(Finding(HiddenContentKind.EncodedImage, "PNG"), Finding(HiddenContentKind.EncodedText, "UTF-8 text", HiddenContentSource.Substring)), "P.1.0.0.nupkg");

        Assert.Contains("obfuscation: 2 finding(s)", writer.ToString());
    }
    #endregion

    #region Methods — helpers
    private static ObfuscationFinding Finding(HiddenContentKind kind, string detected, HiddenContentSource source = HiddenContentSource.Constant) =>
        new(kind, detected, "Evil.Loader", "Decode", 128, 5.5, source);

    private static ObfuscationReport Report(params ObfuscationFinding[] findings) =>
        new("Sample.dll", "lib/net10.0/Sample.dll", Epoch, findings);

    private static AssemblyAnalysisReport AssemblyWith(params ObfuscationFinding[] findings) =>
        AssemblyReport(methodsTotal: 5, methodsSkipped: 0) with { Obfuscation = Report(findings) };

    private static PackageCapabilityReport PackageWith(params ObfuscationFinding[] findings) =>
        Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 5, methodsSkipped: 0) with { Obfuscation = Report(findings) });

    // The one footer line carrying the "Obfuscation:" label (the section heading is not a "label: value" line).
    private static string ObfuscationFooterLine(string output) =>
        Assert.Single(output.Split('\n').Select(l => l.TrimEnd('\r', ' ')), l => l.StartsWith("Obfuscation:", StringComparison.Ordinal));

    private static (IAnsiConsole Console, StringWriter Writer) PlainConsole()
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = false;   // the default (ASCII) mode: Dash is '-'
        console.Profile.Width = 240;
        return (console, writer);
    }
    #endregion
}
