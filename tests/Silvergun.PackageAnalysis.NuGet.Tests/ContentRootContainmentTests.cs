namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Xunit;

/// <summary>
/// Unit tests for <see cref="NuGetPackage.EscapesContentRoot"/> — the single definition of "this declared zip entry
/// does not name a file inside the package content root", used both to DROP zip-slip entries from the inventory
/// (ADR 0008) and to REPORT them (<see cref="PackageEntryNameAnalyzer"/>, ADR 0031).
///
/// <para><b>Why this file exists.</b> The predicate used to be <c>Path.GetFullPath(Path.Combine(root, name))
/// .StartsWith(root)</c>. On Windows the path normalizer redirects DOS device names — measured 2026-08-22,
/// <c>Path.GetFullPath(@"C:\root\content\COM1.dll")</c> is <c>\\.\COM1</c> — so a perfectly contained
/// <c>lib/net8.0/COM1.dll</c> was judged to ESCAPE, was dropped from the contained set, and the extracted file then
/// failed the inventory gate: never inventoried, never IL-analysed, never counted as missing, report reads clean.
/// A payload renamed <c>COM1.dll</c> was invisible to the analyzer on Windows and analysed normally on Linux
/// (ADR 0030, sixth instance). The fix makes the decision <b>lexical</b> — a pure, total function of the name.</para>
///
/// <para><b>The point of these tests is cross-platform EQUALITY.</b> Every case below is asserted with no platform
/// gate at all, and the suite is run on Windows and on Linux/WSL; agreement between the two runs is the assertion
/// the fix exists to make. <see cref="EscapesContentRoot_ForEveryRepresentativeName_AnswersExactlyThis"/> is the
/// same shape as <c>PackageEntryNameAnalyzerTests</c>' pin table, and for the same reason: one failure message that
/// names every divergent row is what a platform comparison actually needs.</para>
///
/// <para>The one deliberately platform-gated test is
/// <see cref="EscapesContentRoot_OnWindows_DisagreesWithThePlatformPathNormalizer"/>: it pins the OS fact that
/// caused the defect, so re-deriving containment from <c>Path.GetFullPath</c> turns red instead of silently
/// costing a file its analysis.</para>
/// </summary>
public sealed class ContentRootContainmentTests
{
    #region Methods — contained names (the entries that must STAY in the inventory)
    // A reserved DOS device name is a perfectly ordinary relative path as far as containment is concerned: it names
    // a file under the root, on both platforms. Windows may later refuse to CREATE it — that is a different fact,
    // reported through UninventoriedEntryNames, never by pretending the entry escaped.
    [Theory]
    [InlineData("lib/net8.0/COM1.dll")]      // <- the ADR 0030 sixth-instance payload name
    [InlineData("CON.txt")]
    [InlineData("content/../a.bin")]         // walks back INTO the root: contained
    [InlineData("content/./a.bin")]          // "." is a no-op segment
    [InlineData("a//b/x.dll")]               // an empty segment is a no-op too
    [InlineData("content/..evil/x.dll")]     // a segment that merely STARTS with dots is not a ".." segment
    public void EscapesContentRoot_ForANameThatStaysInsideTheRoot_IsFalse(string name) =>
        Assert.False(
            NuGetPackage.EscapesContentRoot(name),
            $"'{name}' names a file inside the content root, so dropping it would cost that file its analysis.");
    #endregion

    #region Methods — escaping names (ADR 0008 containment, which the fix must not weaken)
    // Rooted, drive-qualified and upward-walking names still escape — on EVERY platform, tested structurally. On
    // Unix "C:\evil.dll" is a legal relative filename, so a platform normalizer would happily call it contained.
    // The degenerate names that resolve TO the root ("", ".", "content/..") escape as well: they name no file under
    // it, so nothing can be inventoried for them either.
    [Theory]
    [InlineData("../../evil.dll")]
    [InlineData("..\\..\\evil.dll")]         // entry names may use either separator
    [InlineData("content/../../evil.dll")]
    [InlineData("/etc/x")]
    [InlineData("\\\\server\\share\\x")]
    [InlineData("C:\\x")]
    [InlineData("c:/x")]
    [InlineData("D:x")]                      // drive-RELATIVE: still an absolute location's business, not ours
    [InlineData("")]
    [InlineData(".")]
    [InlineData("content/..")]
    public void EscapesContentRoot_ForANameThatDoesNotNameAFileUnderTheRoot_IsTrue(string name) =>
        Assert.True(
            NuGetPackage.EscapesContentRoot(name),
            $"'{name}' does not name a file strictly inside the content root and must not be inventoried.");
    #endregion

    #region Methods — the exact table (run unchanged on Windows and Linux — the platform pin)
    // Every row above, in one place, asserted as an exact expected answer. Run on both platforms; agreement between
    // the two runs IS the cross-platform assertion the fix is about, and the failure message names every divergent
    // row at once so a platform comparison can be read off a single run.
    [Fact]
    public void EscapesContentRoot_ForEveryRepresentativeName_AnswersExactlyThis()
    {
        (string Name, bool Escapes)[] table =
        [
            // --- contained: must stay inventoried ---
            ("lib/net8.0/COM1.dll", false),
            ("CON.txt", false),
            ("content/../a.bin", false),
            ("content/./a.bin", false),
            ("a//b/x.dll", false),
            ("content/..evil/x.dll", false),
            ("lib/netstandard2.0/Foo.dll", false),
            ("lib\\netstandard2.0\\Foo.dll", false),
            ("_rels/.rels", false),
            ("[Content_Types].xml", false),

            // --- escaping: ADR 0008 must keep dropping these ---
            ("../../evil.dll", true),
            ("..\\..\\evil.dll", true),
            ("content/../../evil.dll", true),
            ("/etc/x", true),
            ("\\\\server\\share\\x", true),
            ("C:\\x", true),
            ("c:/x", true),
            ("D:x", true),
            ("", true),
            (".", true),
            ("content/..", true),
        ];

        var divergent = table
            .Where(row => NuGetPackage.EscapesContentRoot(row.Name) != row.Escapes)
            .Select(row => $"  '{row.Name}': expected escapes={row.Escapes}, got {!row.Escapes}")
            .ToArray();

        Assert.True(
            divergent.Length == 0,
            $"{divergent.Length} entry name(s) got the wrong containment answer on {PlatformName}:\n"
            + string.Join('\n', divergent));
    }
    #endregion

    #region Methods — the platform fact that caused the defect
    // The measurement, pinned. Windows' normalizer turns a device-named path into "\\.\COM1", which does not start
    // with the content root — that is what the old probe consulted, and why COM1.dll was dropped. The assertion
    // that matters is the second one: containment does NOT agree with the normalizer. If someone re-adds
    // Path.GetFullPath as "defence in depth", it can only ever SUBTRACT entries, and this turns red.
    //
    // Gated with Skip rather than an early return so the Windows run shows it PASSED and the Linux run shows it
    // SKIPPED — a test that silently no-ops is the false assurance this whole ADR is about.
    [WindowsExtractionFact("the DOS device-name redirect is a Windows path-normalizer behaviour")]
    public void EscapesContentRoot_OnWindows_DisagreesWithThePlatformPathNormalizer()
    {
        var contentRoot = Path.Combine(Path.GetTempPath(), "silvergun-containment-probe");

        var normalized = Path.GetFullPath(Path.Combine(contentRoot, "content", "COM1.dll"));

        Assert.StartsWith(@"\\.\", normalized, StringComparison.Ordinal);          // ground truth: the redirect is real
        Assert.False(normalized.StartsWith(contentRoot, StringComparison.Ordinal)); // ...and it reads as "escaping"
        Assert.False(NuGetPackage.EscapesContentRoot("content/COM1.dll"));          // ...but containment does not care
    }

    // The Linux half of the same measurement, so both runs state the platform fact rather than one of them being
    // silent about it: there is no redirect there, and the lexical answer is the SAME one Windows gives.
    [LinuxExtractionFact("the absence of a device-name redirect is the Linux half of the same measurement")]
    public void EscapesContentRoot_OnLinux_AgreesWithThePlatformPathNormalizer()
    {
        var contentRoot = "/tmp/silvergun-containment-probe";

        var normalized = Path.GetFullPath(Path.Combine(contentRoot, "content", "COM1.dll"));

        Assert.Equal("/tmp/silvergun-containment-probe/content/COM1.dll", normalized);
        Assert.False(NuGetPackage.EscapesContentRoot("content/COM1.dll"));
    }
    #endregion

    #region Methods — ResolvedDepth, the three-valued reading EscapesContentRoot is defined in terms of
    // The predicate collapses two different situations into "true", and the difference matters to the report:
    // -1 is "walks ABOVE the root" (zip slip, an attack), 0 is "resolves TO the root itself" (malformed, names no
    // file, not an attack — PackageEntryNameAnalyzer carves it out of PathTraversal on exactly this test), and > 0
    // is a contained file at that depth. Tested directly here, because a caller now depends on the distinction.
    [Theory]
    // --- above the root: -1 ---
    [InlineData("..", -1)]
    [InlineData("../x.dll", -1)]
    [InlineData("content/../../x.dll", -1)]
    [InlineData("content/../..", -1)]
    [InlineData("a/../../b", -1)]
    [InlineData("..\\..\\evil.dll", -1)]                 // entry names may use either separator
    [InlineData("a/b/../../../c", -1)]
    // --- the root itself: 0 ---
    [InlineData("", 0)]
    [InlineData(".", 0)]
    [InlineData("./", 0)]
    [InlineData("content/..", 0)]
    [InlineData("content\\..", 0)]
    [InlineData("content/./..", 0)]
    [InlineData("a/b/../..", 0)]
    [InlineData("//", 0)]                                 // empty segments are no-ops, so this resolves nowhere
    // --- inside the root: > 0 ---
    [InlineData("x.dll", 1)]
    [InlineData("a/b/c.dll", 3)]
    [InlineData("a//b", 2)]                               // an empty segment costs no depth
    [InlineData("a/./b", 2)]
    [InlineData("a\\b\\c", 3)]                            // backslash-separated, same answer
    [InlineData("lib/net8.0/COM1.dll", 3)]
    [InlineData("content/../a.bin", 1)]                   // walks back INTO the root
    [InlineData("content/..evil/x.dll", 3)]               // a segment that merely STARTS with dots is not ".."
    public void ResolvedDepth_ForARepresentativeName_IsExactlyThis(string name, int expected) =>
        Assert.Equal(expected, NuGetPackage.ResolvedDepth(name));

    // -1 is a SHORT-CIRCUIT, not a running total: once a name has walked above the root, coming back down does not
    // make it contained again. "../a/b" is a zip-slip target however deep the path continues.
    [Theory]
    [InlineData("../a/b/c.dll")]
    [InlineData("content/../../back/in/again.dll")]
    public void ResolvedDepth_OnceAboveTheRoot_StaysNegativeHoweverDeepTheRestGoes(string name) =>
        Assert.Equal(-1, NuGetPackage.ResolvedDepth(name));

    // The two are one definition, not two: for every relative (non-rooted, non-drive-qualified) name, containment
    // is exactly "resolved depth <= 0". Pinned so the pair cannot drift apart — the analyzer's carve-out reads
    // ResolvedDepth while the inventory gate reads EscapesContentRoot, and they must be describing the same name.
    [Fact]
    public void EscapesContentRoot_ForEveryRelativeName_AgreesWithResolvedDepth()
    {
        string[] names =
        [
            "x.dll", "a/b/c.dll", "content/../a.bin", "content/./a.bin", "a//b", "lib/net8.0/COM1.dll",
            "content/..evil/x.dll", ".", "content/..", "a/b/../..", "", "..", "../x.dll",
            "content/../../evil.dll", "a/../../b",
        ];

        var divergent = names
            .Where(n => NuGetPackage.EscapesContentRoot(n) != (NuGetPackage.ResolvedDepth(n) <= 0))
            .ToArray();

        Assert.True(
            divergent.Length == 0,
            $"containment and resolved depth disagree on: {string.Join(", ", divergent.Select(n => $"'{n}'"))}");
    }

    // Total and pure, like the predicate it backs: a pathological name yields a number, never an exception. It is
    // reached from NuGetPackage.Open and from the analyzer, where a throw would sink a whole package scan.
    [Fact]
    public void ResolvedDepth_ForPathologicalNames_NeverThrows()
    {
        string[] pathological =
        [
            "lib/pay\0load.dll", "..\0/..\0/evil.dll", new string('a', 40_000),
            "../" + new string('b', 40_000) + "/x.bin", string.Join('/', Enumerable.Repeat("..", 10_000)),
            "/", "\\", "//", "...", "....", "://", "C:", ":", " ", "\U0000202E", "\0",
        ];

        var thrown = Record.Exception(() =>
        {
            foreach (var name in pathological)
                _ = NuGetPackage.ResolvedDepth(name);
        });

        Assert.Null(thrown);
    }
    #endregion

    #region Methods — totality (the predicate runs inside Open and must never sink a package)
    // Lexical means TOTAL: no platform normalizer is left to refuse a pathological name. The embedded-NUL rows are
    // the ones that matter — Path.GetFullPath throws ArgumentException on those, and this predicate is called from
    // NuGetPackage.Open, where a throw costs the whole package scan.
    [Fact]
    public void EscapesContentRoot_ForPathologicalNames_NeverThrows()
    {
        string[] pathological =
        [
            "lib/pay\0load.dll", "../pay\0load.dll", "..\0/..\0/evil.dll",
            new string('a', 40_000), "../" + new string('b', 40_000) + "/x.bin",
            "/", "\\", "//", "..", ".", "...", "....", "://", "C:", "c:", "1:x", ":", " ", "   ",
            "\u202E", "\u200B", "\uFEFF", "\0", "con", "CON.", "CON ",
        ];

        var thrown = Record.Exception(() =>
        {
            foreach (var name in pathological)
                _ = NuGetPackage.EscapesContentRoot(name);
        });

        Assert.Null(thrown);
    }

    // Purity: the same names always get the same answers. The predicate reads no clock, no filesystem and no
    // ambient state — a containment decision that could differ between two calls in one process would be a
    // different flavour of the same defect. (The working directory is deliberately NOT mutated to prove this:
    // xunit runs collections in parallel, and one test changing it would break unrelated ones.)
    [Fact]
    public void EscapesContentRoot_ForTheSameNamesTwice_IsDeterministic()
    {
        string[] names = ["lib/net8.0/COM1.dll", "content/../a.bin", "../../evil.dll", "C:\\x", ".", ""];

        Assert.Equal(
            names.Select(NuGetPackage.EscapesContentRoot).ToArray(),
            names.Select(NuGetPackage.EscapesContentRoot).ToArray());
    }
    #endregion

    #region Methods — helpers
    private static string PlatformName =>
        OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsLinux() ? "Linux" : "this platform";
    #endregion
}
