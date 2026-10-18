namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The rendered-report half of the ADR 0031 decision 4 fix, driven through a real <c>.nupkg</c> and the real
/// <see cref="PackageScanner"/>. The defect measured in
/// <c>docs/agent/measurements/packaging-anomalies-top100-2026-08-22.md</c> was that an <c>InvisibleCharacter</c>
/// anomaly reached the human-readable report with the invisible character <b>still in it</b> — the literal bytes
/// <c>E2 80 8B</c> were found in a report. A finding a reader cannot see is not a finding.
///
/// <para><b>Why the renderer is the load-bearing channel for the ASTRAL case.</b> Measured 2026-08-22 on .NET 10:
/// System.Text.Json escapes every astral code point under <i>both</i> the default and the
/// <c>UnsafeRelaxedJsonEscaping</c> encoder, so a raw U+E0041 in the model is invisible in any JSON payload. The
/// Spectre console path writes to a <see cref="StringWriter"/> and passes through no encoder at all, so this is
/// where a Tag-block character that survived escaping would actually show up.</para>
///
/// <para><b>Why nothing here pipes CLI stdout to a file.</b> Console redirection transcodes — measured the same
/// day, an é became <c>0x82</c> (CP437) and an emoji became <c>??</c> — so "no raw invisible bytes" read off a
/// piped transcript is a statement about the console encoder, not about us. The in-process writer is the
/// unconfounded channel; the CLI's own <c>--output &lt;file&gt;</c> path is the only redirect that writes UTF-8
/// directly, and it shares this exact renderer.</para>
///
/// <para>Structured like <see cref="FoldingCollisionAndHostileNameCliTests"/>, whose bidi-override twin this is:
/// both render modes, because <c>--rich</c> and the ASCII default are separate paths through the widgets.</para>
/// </summary>
public sealed class InvisibleCharacterEntryNameCliTests : IClassFixture<InvisibleNameCliPackageFixture>
{
    #region Constructors
    public InvisibleCharacterEntryNameCliTests(InvisibleNameCliPackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — the scan really produced the findings under test
    // Vacuity guard first: without these four anomalies every sweep below passes trivially.
    [Fact]
    public void ScanPackage_ForInvisibleEntryNames_ReportsAnInvisibleCharacterAnomalyPerHostileEntry()
    {
        var invisible = Scan()
            .PackagingAnomalies
            .Where(a => a.Category == PackagingAnomalyCategory.InvisibleCharacter)
            .ToArray();

        Assert.Equal(4, invisible.Length);
        Assert.All(invisible, a => Assert.Contains("U+", a.Detail, StringComparison.Ordinal));
    }
    #endregion

    #region Methods — the escape sequences reach the terminal, in both render modes
    // What an operator must actually see: the escape sequence, in the entry-name column. \U000E0041 is the astral
    // Tag-block form and the only uppercase-hex escape in the scheme, so it is pinned literally.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PackageRenderer_ForInvisibleEntryNames_PrintsTheEscapeSequencesLiterally(bool rich)
    {
        var (console, writer) = rich ? RichConsole() : AsciiConsole();

        PackageReportRenderer.Render(console, Scan(), "Invisible.nupkg");

        var output = writer.ToString();
        Assert.Contains(@"zero\u200bwidth.bin", output, StringComparison.Ordinal);
        Assert.Contains(@"soft\xadhyphen.bin", output, StringComparison.Ordinal);
        Assert.Contains(@"bom\ufeff.bin", output, StringComparison.Ordinal);
        Assert.Contains(@"tag\U000E0041.bin", output, StringComparison.Ordinal);
    }

    // ...and the report carries no raw invisible CODE POINT anywhere, in either mode. Asserted on runes rather
    // than chars: the Tag block is one code point spelled as two chars, and a char-wise check is precisely the
    // mistake that produced the defect. Rich mode is the mode that matters — the ASCII path could pass this by
    // dropping non-ASCII wholesale, which is why the escape sequences above are asserted separately.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PackageRenderer_ForInvisibleEntryNames_PrintsNoRawInvisibleCodePoint(bool rich)
    {
        var (console, writer) = rich ? RichConsole() : AsciiConsole();

        PackageReportRenderer.Render(console, Scan(), "Invisible.nupkg");

        var offenders = writer.ToString()
            .EnumerateRunes()
            .Select(r => r.Value)
            .Where(IsInvisible)
            .Distinct()
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            "the rendered report carried raw invisible code point(s) "
            + string.Join(", ", offenders.Select(cp => $"U+{cp:X4}")) + '.');
    }

    // The byte-level form of the same statement, on UTF-8 taken straight from the in-process writer — no console,
    // no redirect, no transcoding. E2 80 8B is the exact triple the top-100 measurement found in a report.
    [Fact]
    public void PackageRenderer_ForInvisibleEntryNames_EmitsNoRawInvisibleUtf8Bytes()
    {
        var (console, writer) = RichConsole();

        PackageReportRenderer.Render(console, Scan(), "Invisible.nupkg");

        var bytes = Encoding.UTF8.GetBytes(writer.ToString()).AsSpan();
        foreach (var (name, needle) in RawUtf8Sequences)
            Assert.True(bytes.IndexOf(needle) < 0, $"the rendered report carried the raw UTF-8 bytes of {name}.");
    }

    // The negative control: the same sweep run against a report whose EntryName still holds the raw characters —
    // i.e. the pre-fix behaviour — must FAIL to find them absent. Without this, all three tests above could be
    // passing because the renderer drops the column, not because the escaper works.
    [Fact]
    public void PackageRenderer_ForARawInvisibleEntryName_WouldShowIt()
    {
        var (console, writer) = RichConsole();
        var raw = Scan() with
        {
            PackagingAnomalies =
            [
                new PackagingAnomaly(
                    PackagingAnomalyCategory.InvisibleCharacter,
                    "content/zero\u200Bwidth.bin",           // RAW, as the defect reported it
                    "contains invisible character(s) U+200B"),
                new PackagingAnomaly(
                    PackagingAnomalyCategory.InvisibleCharacter,
                    "content/tag\U000E0041.bin",             // ...and the astral half
                    "contains invisible character(s) U+E0041"),
            ],
        };

        PackageReportRenderer.Render(console, raw, "Invisible.nupkg");

        var codePoints = writer.ToString().EnumerateRunes().Select(r => r.Value).ToHashSet();
        Assert.Contains(0x200B, codePoints);
        Assert.Contains(0xE0041, codePoints);
    }
    #endregion

    #region Methods — helpers
    private PackageCapabilityReport Scan()
    {
        var scan = PackageScanner.Scan(fixture.NupkgPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value with
        {
            VulnerabilitiesStatus = VulnerabilityScanStatus.Completed,
            YaraScanStatus = YaraScanStatus.Completed,
        };
    }

    // Everything YaraPathSafety.Escape renders unprintable-proof: the soft hyphen, the zero-width characters and
    // directional marks, the word joiner and invisible operators, the BOM, and the astral Tag block.
    private static bool IsInvisible(int cp) =>
        cp is 0x00AD
             or >= 0x200B and <= 0x200F
             or >= 0x2060 and <= 0x2064
             or 0xFEFF
             or >= 0xE0000 and <= 0xE007F;

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
    private static readonly (string Name, byte[] Bytes)[] RawUtf8Sequences =
    [
        ("U+200B ZERO WIDTH SPACE", [0xE2, 0x80, 0x8B]),
        ("U+00AD SOFT HYPHEN", [0xC2, 0xAD]),
        ("U+FEFF ZERO WIDTH NO-BREAK SPACE", [0xEF, 0xBB, 0xBF]),
        ("U+E0041 TAG LATIN CAPITAL LETTER A", [0xF3, 0xA0, 0x81, 0x81]),
    ];

    private readonly InvisibleNameCliPackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages one <c>.nupkg</c> whose declared entry names each carry an invisible character — a zero-width space, a
/// soft hyphen, a BOM and an astral Tag-block character — plus one ordinary name. Pure BCL zip, no NuGet client
/// and no network; <see cref="ZipArchive.CreateEntry(string)"/> stores the name verbatim, and ADR 0031 analyses
/// the CENTRAL DIRECTORY, so nothing here depends on whether a filesystem can hold such a name.
/// </summary>
public sealed class InvisibleNameCliPackageFixture : IDisposable
{
    #region Constructors
    public InvisibleNameCliPackageFixture()
    {
        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-invisible-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        const string id = "PkgInvisibleNamesCli";
        var payload = Encoding.UTF8.GetBytes("not an assembly\n");
        NupkgPath = Path.Combine(rootDir, $"{id}.1.0.0.nupkg");

        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>ADR 0031 decision 4 invisible-entry-name regression package.</description>
                <dependencies>
                  <group targetFramework="net8.0" />
                </dependencies>
              </metadata>
            </package>
            """;

        using var stream = new FileStream(NupkgPath, FileMode.Create, FileAccess.Write);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Create);
        Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
        Write(zip, "content/zero\u200Bwidth.bin", payload);    // ZERO WIDTH SPACE
        Write(zip, "content/soft\u00ADhyphen.bin", payload);   // SOFT HYPHEN
        Write(zip, "content/bom\uFEFF.bin", payload);          // ZERO WIDTH NO-BREAK SPACE / BOM
        Write(zip, "content/tag\U000E0041.bin", payload);      // TAG LATIN CAPITAL LETTER A — ASTRAL
        Write(zip, "content/plain.bin", payload);              // ...and one with nothing wrong with it
    }
    #endregion

    #region Properties
    public string NupkgPath { get; }
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

    private static void Write(ZipArchive zip, string name, byte[] bytes)
    {
        using var s = zip.CreateEntry(name).Open();
        s.Write(bytes, 0, bytes.Length);
    }
    #endregion

    #region Fields
    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";

    private readonly string rootDir;
    #endregion
}
