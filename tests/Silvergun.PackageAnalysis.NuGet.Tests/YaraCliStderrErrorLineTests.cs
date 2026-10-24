namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0032 decision 7 (review item C1): <b>a <c>yara -r</c> pass that exits 0 is not proof that every file was
/// scanned.</b> Real <c>yara -r</c> (4.1.3, measured on WSL) prints <c>error scanning &lt;path&gt;: could not open
/// file</c> on stderr for a file it could not open, and still exits 0. Its <c>--timeout</c> is one deadline for the whole
/// run: only the ONE file being scanned when it passes gets a <c>…: scanning timed out</c> line, and every file still
/// queued then is dropped with no line at all — which is why stderr is not the coverage signal (ADR 0032 decision 9,
/// <see cref="YaraCliCoverageSentinelTests"/>), only a defence in depth. Before the fix
/// <see cref="YaraCliScanner"/> looked only at the exit code, so the package read <see cref="YaraScanStatus.Completed"/>
/// with the skipped file's matches silently missing — attacker-reachable through yara's own <c>--timeout</c>.
///
/// <para>The rule pinned here: after a run that exited 0, any stderr line whose <b>trimmed start</b> is
/// <c>error</c> (case-insensitive) makes the scan incomplete; <c>warning:</c> lines and lines that merely
/// <i>contain</i> the word do not. The message names the lines, escaped and capped like every other package text.</para>
///
/// <para><b>Deliberately written against the public surface that predates ADR 0032</b> — nothing here touches
/// <c>YaraScanIncompleteException.PartialFindings</c> — so this file compiles against <c>944ea9c</c> and its
/// behavioural tests can be shown RED there by assertion, not merely by a compile error. The assertions on the carried
/// hits themselves live in <c>YaraCliStderrErrorPartialFindingsTests</c>; the report-level tests here observe
/// the same hits through <see cref="PackageCapabilityReport.YaraFindings"/>, which predates the ADR.</para>
///
/// <para>The engine is the <c>FakeYaraProbe</c> (see <see cref="FakeYaraBinary"/>, knob <c>batchStdErr</c>), so these
/// run on Windows and Linux alike, except where a hostile file name or a non-ASCII stderr byte is needed.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliStderrErrorLineTests
{
    #region Methods
    // --- The scanner seam ------------------------------------------------------------------------------------

    // C1 at its source: exit 0, nothing matched, one `error scanning` line. Before the fix this returned an empty list
    // — a clean, completed scan of a package one of whose files yara never opened. Not a timeout of OUR process, so
    // there is no inner exception.
    [Fact]
    public void ScanDirectory_WhenTheBatchExitsZeroButPrintsAnErrorLine_ThrowsIncompleteWithNoInnerException()
    {
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        using var fake = new FakeYaraBinary(batchStdErr: "error scanning content/locked.bin: could not open file");

        using var scanner = new YaraCliScanner();
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Null(ex.InnerException);
        Assert.Contains("exited 0 but reported 1 error line(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'error scanning content/locked.bin: could not open file'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        Assert.Contains("0 hit(s) found in the files that were scanned", ex.Message, StringComparison.Ordinal);
    }

    // The false-positive guard. yara prints `warning:` lines in ordinary operation (e.g. a rule that may slow scanning,
    // or the uncompiled-rules fallback), and the ADR is explicit that they do not count. A package whose only stderr is
    // a warning must still complete, with its hit — otherwise every such package would read Unavailable.
    [Fact]
    public void ScanDirectory_WhenTheBatchPrintsOnlyWarnings_CompletesWithItsHits()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "real.bin",
            batchStdErr: "warning: rule \"Fake_Rule\" in silvergun-rules.yara(12): string \"$a\" may slow down scanning"
                         + "\\nwarning: another one");

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(Path.Combine(tree.Root, "content", "real.bin"), hit.FullPath);
        Assert.Equal("Fake_Rule", hit.Match.Rule);
    }

    // Case and leading whitespace do not hide an error line: the rule is "the TRIMMED line starts with `error`,
    // OrdinalIgnoreCase". (TAB is written as an escape; it is C0 and must never sit raw in this source.)
    [Theory]
    [InlineData("ERROR scanning content/locked.bin: could not open file")]
    [InlineData("Error: could not open file")]
    [InlineData("   error scanning content/locked.bin: scanning timed out")]
    [InlineData("\terror scanning content/locked.bin: could not open file")]
    [InlineData("warning: first\\nerror scanning content/locked.bin: could not open file")]
    public void ScanDirectory_ForAnyLineWhoseTrimmedStartIsError_ThrowsIncomplete(string stderr)
    {
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        using var fake = new FakeYaraBinary(batchStdErr: stderr);

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("exited 0 but reported 1 error line(s)", ex.Message, StringComparison.Ordinal);
    }

    // ...and a line that merely CONTAINS the word later on is not an error line. Each of these completing proves the
    // predicate is a start-of-line test, not a substring search (which would flip benign packages to Unavailable).
    [Theory]
    [InlineData("warning: rule \"r\" is slow; an error-prone pattern")]
    [InlineData("  warning: error")]
    [InlineData("scan error in content/x.bin")]
    [InlineData("note: 0 errors")]
    public void ScanDirectory_ForALineThatOnlyContainsErrorLaterOn_Completes(string stderr)
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(batchEchoRule: "Fake_Rule", batchEchoName: "real.bin", batchStdErr: stderr);

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        Assert.Equal("Fake_Rule", Assert.Single(hits).Match.Rule);
    }

    // The lines are package-influenced (yara echoes package paths in them) and the message is logged verbatim, so a
    // package that makes yara fail on thousands of files must not be able to flood it: ten lines, then a count. The
    // count reads ", and N more" — the one rendering every YARA message shares since round D (YaraPathSafety.Bounded,
    // which also renders IYaraScanner.DescribeUnscanned's list); it was "(+N more)" while the CLI backend had its own.
    [Fact]
    public void ScanDirectory_WithMoreThanTenErrorLines_NamesTenAndCountsTheRest()
    {
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        var lines = Enumerable.Range(0, 12).Select(i => $"error scanning content/f{i:D2}.bin: could not open file");
        using var fake = new FakeYaraBinary(batchStdErr: string.Join("\\n", lines));

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("exited 0 but reported 12 error line(s)", ex.Message, StringComparison.Ordinal);
        Assert.Equal(10, Regex.Matches(ex.Message, @"'error scanning content/f\d\d\.bin: could not open file'").Count);
        Assert.Contains("f09.bin", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("f10.bin", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("f11.bin", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'error scanning content/f09.bin: could not open file', and 2 more", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("(+", ex.Message, StringComparison.Ordinal);
    }

    // A C0 control character inside an error line (yara echoes a hostile file name verbatim) reaches the message
    // escaped, never raw: a raw ESC would let a package drive the operator's terminal from our own log line. ESC and
    // BEL are used because, unlike CR/LF, they do not split the line before the scanner sees it.
    [Fact]
    public void ScanDirectory_EscapesControlCharactersInsideErrorLines()
    {
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        var line = "error scanning content/a" + Esc + "[31mred" + Bel + ".bin: could not open file";
        using var fake = new FakeYaraBinary(batchStdErr: line);

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains(@"content/a\x1b[31mred\x07.bin", ex.Message, StringComparison.Ordinal);
        AssertNoRawControlOrBidi(ex.Message);
    }

    // The same for bidi controls. Linux-only, and not because of the file system: the stderr bytes of a child process
    // on Windows are decoded through the console code page, which cannot carry U+202E at all, so the character would
    // arrive as '?' and the test would pass without exercising the escaper.
    [Utf8StderrFact]
    public void ScanDirectory_EscapesBidiControlsInsideErrorLines()
    {
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        var line = "error scanning content/exe." + Rlo + "txt.bin" + Lri + ": could not open file";
        using var fake = new FakeYaraBinary(batchStdErr: line);

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("content/exe." + EscapedRlo + "txt.bin" + EscapedLri, ex.Message, StringComparison.Ordinal);
        AssertNoRawControlOrBidi(ex.Message);
    }

    // --- The report: what the CLI's exit code and renderer consume -------------------------------------------

    // C1 end to end. The batch pass matched the payload, exited 0, and said on stderr that it could not open another
    // file. The package must read Unavailable (not every file was examined) AND report the payload hit (it is real).
    // Before the fix: Completed, one finding — the skipped file's coverage silently missing.
    [Fact]
    public void Scan_WhenTheBatchExitsZeroWithAnErrorLine_ReportsUnavailableAndTheBatchHit()
    {
        using var tree = new TempTree();
        var nupkg = WritePackage(tree, "PkgStderrError",
            [("content/payload.bin", "ordinary content\n"), ("content/locked.bin", "ordinary content\n")]);
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin",
            batchStdErr: "error scanning content/locked.bin: could not open file");

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("content/payload.bin", finding.RelativePath);
        Assert.Equal("Fake_Rule", finding.RuleName);
    }

    // The same with no hit at all: Unavailable, zero findings — the "nothing matched" that is NOT "clean".
    [Fact]
    public void Scan_WhenTheBatchExitsZeroWithAnErrorLineAndNoHits_ReportsUnavailable()
    {
        using var tree = new TempTree();
        var nupkg = WritePackage(tree, "PkgStderrErrorNoHits", [("content/locked.bin", "ordinary content\n")]);
        using var fake = new FakeYaraBinary(batchStdErr: "error scanning content/locked.bin: scanning timed out");

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Empty(scan.Value.YaraFindings);
    }

    // The control for the two above: the same package and engine with a warning-only stderr completes. Without it,
    // "Unavailable" above could be an artefact of the fake rather than of the error line.
    [Fact]
    public void Scan_WhenTheBatchPrintsOnlyAWarning_ReportsCompletedWithTheHit()
    {
        using var tree = new TempTree();
        var nupkg = WritePackage(tree, "PkgStderrWarning",
            [("content/payload.bin", "ordinary content\n"), ("content/locked.bin", "ordinary content\n")]);
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin",
            batchStdErr: "warning: rule \"Fake_Rule\": string \"$a\" may slow down scanning");

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        Assert.Equal("content/payload.bin", Assert.Single(scan.Value.YaraFindings).RelativePath);
    }

    // ADR 0029 decision 17 and decision 7 firing in the same pass: an unattributable hit AND an error line. One
    // exception, both sets of hits — the attributed payload and the ghost under the path yara echoed. Before ADR 0032
    // the d17 guard threw them all away: Unavailable, zero findings.
    [Fact]
    public void Scan_WhenTheBatchHasAnUnattributableHitAndAnErrorLine_ReportsBothHits()
    {
        using var tree = new TempTree();
        var nupkg = WritePackage(tree, "PkgStderrAndGhost", [("content/payload.bin", "ordinary content\n")]);
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", batchGhost: "ghost.bin",
            batchStdErr: "error scanning content/locked.bin: could not open file");

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Equal(2, scan.Value.YaraFindings.Count);
        Assert.Single(scan.Value.YaraFindings, f => f.RelativePath == "content/payload.bin");
        Assert.Single(scan.Value.YaraFindings, f => f.RelativePath == "content/ghost.bin");
    }

    // ADR 0032 decision 7a, the reason the throw sits AFTER the recovery pass. The payload is shipped under a
    // control-character name, so the batch pass defers it and only the individual pass can find it; one other file
    // makes yara print an error line. Had the error line been thrown from ScanBatch, the recovery pass would never run
    // and this package would read Unavailable with ZERO findings — a new evasion. Both hits must be reported.
    [LinuxFact]
    public void Scan_WhenTheBatchHasAnErrorLineAndAPayloadUnderAnUnsafeName_StillReportsTheRecoveredHit()
    {
        using var tree = new TempTree();
        var nupkg = WritePackage(tree, "PkgStderrAndDeferred",
            [("content/payload.bin", "ordinary content\n")], [("content/pay\nload.bin", "ordinary content\n")]);
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule",
            batchStdErr: "error scanning content/slow.bin: scanning timed out");

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Equal(2, scan.Value.YaraFindings.Count);
        Assert.Single(scan.Value.YaraFindings, f => f.RelativePath == "content/payload.bin");
        Assert.Single(scan.Value.YaraFindings, f => f.RelativePath == @"content/pay\nload.bin");
    }
    #endregion

    #region Helpers
    // The hostile characters, built from their code points so this source never carries them raw, and the escapes
    // YaraPathSafety.Escape renders them as.
    private const char Esc = (char)0x1B;
    private const char Bel = (char)0x07;
    private const char Rlo = (char)0x202E;   // RIGHT-TO-LEFT OVERRIDE
    private const char Lri = (char)0x2066;   // LEFT-TO-RIGHT ISOLATE
    private const string EscapedRlo = @"\" + "u202e";
    private const string EscapedLri = @"\" + "u2066";

    internal static string WritePackage(
        TempTree tree, string id, (string Name, string Text)[] entries, (string Name, string Text)[]? rawEntries = null) =>
        WritePackageBytes(tree, id, entries.Select(e => (e.Name, Encoding.UTF8.GetBytes(e.Text))).ToArray(),
            (rawEntries ?? []).Select(e => (e.Name, Encoding.UTF8.GetBytes(e.Text))).ToArray());

    internal static string WritePackageBytes(
        TempTree tree, string id, (string Name, byte[] Bytes)[] entries, (string Name, byte[] Bytes)[] rawEntries)
    {
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(
            nupkg,
            [
                ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                    id, "1.0.0", "Silvergun Tests", "ADR 0032 decision 7 stderr-error package.", "netstandard2.0", []))),
                .. entries,
            ],
            rawEntries);
        return nupkg;
    }

    // No C0, DEL/C1, line/paragraph separator, or bidi control — the predicate YaraCliScannerUnsafePathTests uses.
    internal static void AssertNoRawControlOrBidi(string message) =>
        Assert.All(message, c => Assert.False(
            c < ' ' || c is >= (char)0x7F and <= (char)0x9F or (char)0x2028 or (char)0x2029
                        or >= (char)0x202A and <= (char)0x202E or >= (char)0x2066 and <= (char)0x2069,
            $"YaraScanIncompleteException.Message carried raw U+{(int)c:X4}."));
    #endregion
}

/// <summary>
/// ADR 0032 decision 7 against the <b>real</b> engine: the measured shape itself, not a fake's imitation of it. A
/// readable matching file and a mode-000 copy of it; real <c>yara -r</c> prints <c>error scanning …: could not open
/// file</c> for the copy and exits 0. The scan must be incomplete, and the readable file's hit must survive. Report
/// level here (API-neutral, so it can be shown red against <c>944ea9c</c>); the scanner-level twin asserting
/// <c>YaraScanIncompleteException.PartialFindings</c> is in <c>YaraCliStderrErrorRealEngineTests</c>.
///
/// <para>A mode-000 file cannot be shipped inside a <c>.nupkg</c> (the extractor does not restore modes), so the
/// test injects a decorator that revokes the copy's permissions inside the extraction root immediately before the
/// real <see cref="YaraCliScanner"/> runs — the backend itself is untouched.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliStderrErrorRealEngineReportTests
{
    #region Constructors
    public YaraCliStderrErrorRealEngineReportTests() => YaraCliProbe.EnforceBinaryRequirement();
    #endregion

    #region Methods
    [LinuxYaraNonRootFact]
    public void Scan_WhenRealYaraCannotOpenOneFile_ReportsUnavailableAndTheReadableFilesHit()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var nupkg = YaraCliStderrErrorLineTests.WritePackageBytes(tree, "PkgRealUnopenable",
            [("content/payload.bin", HermeticWiperSample.Bytes), ("content/locked.bin", HermeticWiperSample.Bytes)], []);
        using var cli = new YaraCliScanner();
        var backend = new RevokeBeforeScan(cli, "locked.bin");
        Assert.True(backend.Available, "The Linux integration tier requires a real yara binary.");

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: backend);

        // The arrange step happened inside the scan; check it really did deny this process, else the test is vacuous.
        Assert.True(backend.Revoked, "The decorator must have found the copy and made it unreadable to this process.");
        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("content/payload.bin", finding.RelativePath);
        Assert.Equal(HermeticWiperSample.RuleName, finding.RuleName);
    }
    #endregion

    #region Nested types
    // Revokes every permission on the files named `fileName` under the scanned root, then delegates. It records whether
    // the revocation took (a process that can still read the file — root — would make the test inert) rather than
    // asserting here, where a throw would be swallowed by PackageScanner's catch-all; and it restores the mode
    // afterwards so the extraction tree's cleanup does not depend on unlink semantics.
    private sealed class RevokeBeforeScan(IYaraScanner inner, string fileName) : IYaraScanner
    {
        public bool Available => inner.Available;

        public bool Revoked { get; private set; }

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => inner.ScanFile(fullPath);

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir) =>
            WhileRevoked(rootDir, () => inner.ScanDirectory(rootDir));

        // What PackageScanner.ScanYara calls since ADR 0034 (the package's extraction inventory): the same revocation
        // first, then the real backend's own ScanFiles.
        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files) =>
            WhileRevoked(rootDir, () => inner.ScanFiles(rootDir, files));

        private IReadOnlyList<(string FullPath, YaraMatch Match)> WhileRevoked(
            string rootDir, Func<IReadOnlyList<(string FullPath, YaraMatch Match)>> scan)
        {
            if (!OperatingSystem.IsLinux())
                throw new InvalidOperationException("[LinuxYaraNonRootFact] must have gated this test to Linux.");

            var targets = Directory.GetFiles(rootDir, fileName, SearchOption.AllDirectories);
            foreach (var target in targets)
                File.SetUnixFileMode(target, UnixFileMode.None);
            Revoked = targets.Length > 0 && targets.All(IsUnreadable);

            try
            {
                return scan();
            }
            finally
            {
                foreach (var target in targets)
                    File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }

        private static bool IsUnreadable(string path)
        {
            try
            {
                File.ReadAllBytes(path);
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return true;
            }
        }
    }
    #endregion
}

/// <summary>
/// <see cref="LinuxYaraFactAttribute"/> plus one more condition: the process must not run as root. These tests make a
/// file unreadable with mode 000 so that real <c>yara</c> cannot open it, and root can read a mode-000 file — under
/// root yara would scan it, nothing would be incomplete, and the test would assert nothing. A visible skip, never a
/// silent pass.
/// </summary>
public sealed class LinuxYaraNonRootFactAttribute : FactAttribute
{
    #region Constructors
    public LinuxYaraNonRootFactAttribute() =>
        Skip = YaraCliProbe.SkipReason(OperatingSystem.IsLinux(), YaraCliProbe.YaraBinary is not null, YaraCliProbe.BinaryRequired)
            ?? LinuxNonRootFactAttribute.PrivilegedSkipReason();
    #endregion
}

/// <summary>
/// <see cref="LinuxFactAttribute"/> plus "not privileged", for the fake-engine tests that make a file unreadable with
/// mode 000 so that the scanner cannot COPY it (an unrecoverable unsafe name). A privileged process reads a mode-000
/// file anyway, the arrange step's "this process is denied" check then fails, and the test would be red for a reason
/// that has nothing to do with the code under test — so it is a visible skip that says why.
/// <see cref="Environment.IsPrivilegedProcess"/> (root on Unix) replaces the hand-rolled <c>geteuid</c> P/Invoke.
/// </summary>
public sealed class LinuxNonRootFactAttribute : FactAttribute
{
    #region Constructors
    public LinuxNonRootFactAttribute() =>
        Skip = !OperatingSystem.IsLinux()
            ? "ADR 0029/0032 regression: requires an extracted file name that NTFS cannot represent, and a POSIX mode-000 "
              + "file. Run the suite under WSL (dotnet test <proj> -f net10.0) for this to execute."
            : PrivilegedSkipReason();
    #endregion

    #region Methods
    internal static string? PrivilegedSkipReason() =>
        OperatingSystem.IsLinux() && Environment.IsPrivilegedProcess
            ? "ADR 0032: this test makes a file unreadable with mode 000, and the suite is running privileged (root), which "
              + "can read it anyway — the file would be scanned and the test would be inert. Run as a normal user."
            : null;
    #endregion
}

/// <summary>
/// Linux-only, for a test that needs a child process's stderr to carry a non-ASCII character to the scanner. On
/// Windows the redirected stream is decoded through the console code page, which cannot represent a bidi control, so
/// the character would arrive as <c>?</c> and the test would pass without exercising anything.
/// </summary>
public sealed class Utf8StderrFactAttribute : FactAttribute
{
    #region Constructors
    public Utf8StderrFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = "Needs a child process's stderr to round-trip a bidi control (UTF-8); a redirected stream on Windows "
                 + "is decoded through the console code page, which cannot carry it. Run under WSL (-f net10.0).";
    }
    #endregion
}
