namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;
using Xunit.Abstractions;

/// <summary>
/// ADR 0032 decision 9 against the <b>real</b> <c>yara</c> (Linux-gated): the measured shape itself, not a fake's
/// imitation of it. In <c>-r</c> mode yara 4.1.3's <c>--timeout</c> is one global deadline and the files still queued
/// when it passes are dropped with exit 0 and no stderr; before the coverage sentinel the scanner read that as
/// <see cref="YaraScanStatus.Completed"/> with detections missing.
///
/// <para>The positive control is <see cref="HermeticWiperSample"/> (built from the embedded rule's own literal
/// bytes). Where a test needs to count how many processes a scan spawned — "no re-scans" — the real binary is fronted
/// by a two-line <c>/bin/sh</c> wrapper that logs <c>batch</c> or <c>single</c> and then <c>exec</c>s it.</para>
///
/// <para><b>Not covered: <c>-p</c>.</b> The task suggested pinning the thread count to make the deadline shape more
/// reliable; the scanner builds its <c>YaraOptions</c> internally and exposes no thread knob, so the test makes the
/// deadline likely by volume instead (hundreds of MiB against a one-second deadline) and asserts an invariant that
/// holds whatever the timing.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliCoverageSentinelRealEngineTests
{
    #region Constructors
    public YaraCliCoverageSentinelRealEngineTests(ITestOutputHelper output)
    {
        YaraCliProbe.EnforceBinaryRequirement();
        _output = output;
    }
    #endregion

    #region Methods
    // Item 12, the global-deadline shape. 20 matching payloads among 120 bulky (4 MiB, random) files, a 1 s budget —
    // yara's one --timeout=1 deadline for the whole recursive run — so some files are normally still queued when it
    // passes. Which ones, and whether the individual pass can then recover them all inside its own budget, varies run
    // to run, so no single outcome is asserted. The INVARIANT is, on every iteration: either a complete result holding
    // a hit for EVERY payload, or YaraScanIncompleteException whose PartialFindings are all genuine payload hits (and
    // never a sentinel). What must never happen — and, measured against the Round C scanner, did in roughly every
    // second iteration — is a complete result that is missing matches; the iterations are what make one test run
    // reliably red there.
    //
    // Round E (W2) tightens the incomplete branch from "whatever was carried is genuine" to "nothing was LOST": every
    // payload is either carried or among the files the message admits it could not scan. So when the message says
    // `could not scan N of …`, at least payloads − N distinct payloads are carried; when it names no such count (the
    // incompleteness came from elsewhere, e.g. an `error` line, and every re-scan succeeded), all of them are. Each
    // iteration logs whether yara's deadline actually dropped files (the scanner's "no coverage line" warning), so a run
    // whose iterations never hit it — and so tested only the easy branch — is visible in the output.
    //
    // That bound is WEAK here, and the output says so. With 140 files against a one-second deadline, N is usually at least
    // the number of payloads (the Round E review measured N >= payloads in 4 of 5 incomplete iterations), and then
    // `carried >= payloads - N` holds for any carried count — including zero. Such an iteration is logged as "bound
    // vacuous (N >= payloads)" and counted in the summary line; it still checks that every carried hit is a genuine
    // payload hit and never a sentinel, but not that nothing was lost. This test is the real-engine shape check, NOT the
    // primary guard for carried hits. The primary guards are the deterministic fake-engine tests, which control exactly
    // which files go uncovered: the recovery-cap test's `Assert.Equal(65, ex.PartialFindings.Count)`
    // (YaraCliCoverageSentinelTests), the dedupe recovery-pass rethrow
    // (YaraCliHitDedupeTests.ScanDirectory_WhenTheRecoveryPassFails_CarriesTheDoubledFilesHitOnce), and
    // YaraCliPartialFindingsTests.
    [LinuxYaraFact]
    [Trait("Category", "Slow")]
    public void ScanDirectory_WhenRealYarasGlobalDeadlinePasses_NeverCompletesWithAMatchMissing()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var bulk = new byte[4 << 20];
        new Random(20261019).NextBytes(bulk);
        for (var i = 0; i < 120; i++)
            tree.Write($"content/bulk{i:D3}.bin", bulk);
        var payloads = Enumerable.Range(0, 20)
            .Select(i => tree.Write($"content/p{i:D2}.dll", HermeticWiperSample.Bytes))
            .Order(StringComparer.Ordinal)
            .ToArray();

        using var scanner = new YaraCliScanner(scanTimeoutMs: 1_000);
        Assert.True(scanner.Available, "The Linux integration tier requires a real yara binary.");
        using var warnings = new WarningCapture();
        var outcomes = new List<string>();
        var deadlineHits = 0;
        var incompletes = 0;
        var vacuousBounds = 0;

        for (var iteration = 0; iteration < Iterations; iteration++)
        {
            var warned = warnings.Warnings.Count;
            try
            {
                var hits = scanner.ScanDirectory(tree.Root);
                outcomes.Add($"completed:{hits.Count}");

                Assert.All(hits, h => Assert.Equal(HermeticWiperSample.RuleName, h.Match.Rule));
                Assert.Equal(payloads, hits.Select(h => h.FullPath).Distinct().Order(StringComparer.Ordinal));
            }
            catch (YaraScanIncompleteException ex)
            {
                var carried = ex.PartialFindings.Select(h => h.FullPath).Distinct().Count();
                var unscanned = Regex.Match(ex.Message, @"could not scan (\d+) of");
                int? couldNotScan = unscanned.Success ? int.Parse(unscanned.Groups[1].Value) : null;
                var vacuous = couldNotScan >= payloads.Length;   // then `carried >= payloads - N` holds for any carried
                incompletes++;
                vacuousBounds += vacuous ? 1 : 0;
                outcomes.Add($"incomplete:carried={carried}:couldNotScan={couldNotScan?.ToString() ?? "-"}"
                    + (vacuous ? "; bound vacuous (N >= payloads)" : string.Empty));

                Assert.All(ex.PartialFindings, h =>
                {
                    Assert.Equal(HermeticWiperSample.RuleName, h.Match.Rule);
                    Assert.Contains(h.FullPath, payloads);
                });
                Assert.DoesNotContain(YaraCliCoverageSentinelTests.SentinelPrefix, ex.Message, StringComparison.OrdinalIgnoreCase);
                if (couldNotScan is int n)
                    Assert.True(
                        carried >= payloads.Length - n,
                        $"Only {carried} of {payloads.Length} payloads were carried, but the scan admits to only {n} unscanned file(s): {ex.Message}");
                else
                    Assert.True(carried == payloads.Length, $"Only {carried} of {payloads.Length} payloads were carried, and the scan names no unscanned file count: {ex.Message}");
            }
            finally
            {
                var hitTheDeadline = warnings.Warnings.Skip(warned)
                    .Any(w => w.Contains("printed no coverage line for", StringComparison.Ordinal));
                deadlineHits += hitTheDeadline ? 1 : 0;
                _output.WriteLine($"iteration {iteration}: {(outcomes.Count > iteration ? outcomes[^1] : "threw")}; yara's deadline dropped files: {hitTheDeadline}");
            }
        }

        _output.WriteLine($"yara's global deadline dropped files in {deadlineHits} of {Iterations} iteration(s).");
        _output.WriteLine(
            $"the carried-hit bound was vacuous (N >= payloads) in {vacuousBounds} of {incompletes} incomplete iteration(s); "
            + "the deterministic fake-engine tests are the primary guard for carried hits.");
    }

    // Item 13, the false-positive guard: an ordinary package with many zero-byte NuGet `_._` placeholders. yara's
    // `condition: true` sentinel fires for an EMPTY file too, so every file is covered by the one recursive launch —
    // nothing is re-scanned, and the result is complete with exactly the payload hits.
    [LinuxYaraFact]
    public void ScanDirectory_WithManyZeroBytePlaceholders_CompletesWithTheExactHitsAndNoReScans()
    {
        using var wrapper = new LoggingYaraWrapper(YaraCliProbe.YaraBinary!, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        for (var i = 0; i < 100; i++)
            tree.Write($"lib/tfm{i:D3}/_._", Array.Empty<byte>());
        for (var i = 0; i < 10; i++)
            tree.Write($"content/readme{i:D2}.txt", $"benign text file {i}\n");
        var payloads = Enumerable.Range(0, 5)
            .Select(i => tree.Write($"lib/net8.0/p{i:D2}.dll", HermeticWiperSample.Bytes))
            .Order(StringComparer.Ordinal)
            .ToArray();

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        Assert.Equal(5, hits.Count);
        Assert.Equal(payloads, hits.Select(h => h.FullPath).Order(StringComparer.Ordinal));
        Assert.All(hits, h => Assert.Equal(HermeticWiperSample.RuleName, h.Match.Rule));
        Assert.Equal(new[] { "batch" }, wrapper.Launches);
    }

    // Item 8 with the real engine: no yarac beside the wrapper and none configured, so yara gets the rule SOURCE (it
    // compiles at scan time). The sentinel is in that source too: every file is covered in one launch.
    [LinuxYaraFact]
    public void ScanDirectory_WithUncompiledRules_CoversEveryFileInOneLaunch()
    {
        using var wrapper = new LoggingYaraWrapper(YaraCliProbe.YaraBinary!, yarac: null);
        using var tree = new TempTree();
        tree.Write("content/readme.txt", "benign text\n");
        tree.Write("lib/net8.0/_._", Array.Empty<byte>());
        var payloads = Enumerable.Range(0, 3)
            .Select(i => tree.Write($"lib/net8.0/p{i}.dll", HermeticWiperSample.Bytes))
            .Order(StringComparer.Ordinal)
            .ToArray();

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        Assert.Equal(payloads, hits.Select(h => h.FullPath).Order(StringComparer.Ordinal));
        Assert.Equal(new[] { "batch" }, wrapper.Launches);
    }

    // Item 10 with the real engine: `yara -r -N` does not follow a symlink, so it prints no coverage line for one. The
    // link must be left unrecovered (never handed to a single-file yara, which would follow it out of the package), the
    // scan incomplete, and the readable payload's hit carried. Before decision 9 this read Completed.
    [LinuxYaraFact]
    public void ScanDirectory_WhenRealYaraSkipsASymlink_ReportsItUnrecoveredAndCarriesThePayloadHit()
    {
        using var outside = new TempTree();
        var elsewhere = outside.Write("outside-the-package.dll", HermeticWiperSample.Bytes);
        using var wrapper = new LoggingYaraWrapper(YaraCliProbe.YaraBinary!, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var payload = tree.Write("content/payload.dll", HermeticWiperSample.Bytes);
        File.CreateSymbolicLink(Path.Combine(tree.Root, "content", "link.dll"), elsewhere);

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("link.dll", ex.Message, StringComparison.Ordinal);
        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal(new[] { "batch" }, wrapper.Launches);
    }
    #endregion

    #region Fields
    private const int Iterations = 4;

    private readonly ITestOutputHelper _output;
    #endregion

    #region Nested types
    // A /bin/sh stand-in that appends "batch" (last argument a directory) or "single" to a log and then execs the real
    // yara with the scanner's argument list unchanged. Named so YaraCliScanner's "derive yarac beside yara" step finds
    // nothing; the real yarac is passed explicitly when the compiled path is wanted.
    private sealed class LoggingYaraWrapper : IDisposable
    {
        public LoggingYaraWrapper(string yara, string? yarac)
        {
            if (!OperatingSystem.IsLinux())
                throw new InvalidOperationException("This wrapper is a /bin/sh script; [LinuxYaraFact] must have gated its caller.");

            _dir = Path.Combine(Path.GetTempPath(), "silvergun-yara-wrapper-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
            _log = Path.Combine(_dir, "launches.log");
            var script = Path.Combine(_dir, "logging-stand-in");
            if ((yara + _log).Any(c => c is '\'' or '\\' || c < ' '))
                throw new ArgumentException("The wrapper embeds its paths in single quotes; keep them plain.");
            File.WriteAllText(script,
                "#!/bin/sh\n"
                + "for a in \"$@\"; do last=$a; done\n"
                + $"if [ -d \"$last\" ]; then echo batch >> '{_log}'; else echo single >> '{_log}'; fi\n"
                + $"exec '{yara}' \"$@\"\n");
            File.SetUnixFileMode(script,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            _env = new YaraEnvScope(script, yarac);
        }

        public string[] Launches => File.Exists(_log) ? File.ReadAllLines(_log).Where(l => l.Length > 0).ToArray() : [];

        public void Dispose()
        {
            _env.Dispose();
            try { Directory.Delete(_dir, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
        }

        private readonly string _dir;
        private readonly string _log;
        private readonly YaraEnvScope _env;
    }
    #endregion
}
