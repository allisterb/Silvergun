#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;

// The mixed-mode C++/CLI wrapper over native libyara 4.5, reached transitively through
// Silvergun.PackageAnalysis.NuGet's net10.0-windows PackageReference (no PackageReference is added here —
// CLAUDE.md forbids it). Used DIRECTLY for two things only: keeping one YaraContext alive for this class
// (see the constructor) and enumerating the ruleset the product actually published. Reproducing the ADR 0028
// poison is deliberately NOT done in this process any more — see the canary test.
using libyaraNET;

using Xunit;
using Xunit.Abstractions;

/// <summary>
/// Regression coverage for ADR 0028 — "never build a YARA ruleset from a compiler that has errored".
///
/// <para><b>Why this file is net10.0-windows-only.</b> <see cref="LibYaraScanner"/> exists solely under
/// <c>#if WINDOWS</c>, so every Yara-named test in the <c>net10.0</c> suite could never execute a line of it —
/// which is exactly how a defect that disabled the entire in-process YARA backend on Windows shipped unnoticed.
/// The test project therefore multi-targets <c>net10.0;net10.0-windows</c> on Windows (see the csproj) and this
/// whole file is compiled only into the Windows TFM. It needs the real native library, so the inner build pins
/// <c>win-x64</c>: an AnyCPU host cannot load <c>libyara.NET.dll</c> at all.</para>
///
/// <para><b>The defect.</b> <c>BuildEngine</c> added all embedded rule sources to ONE <c>Compiler</c>, swallowed
/// the <c>CompilationException</c> thrown by the one source this native build cannot compile
/// (<c>ReversingLabs.virus.Linux.Virus.Vit.yara</c>, <c>unknown module "elf"</c>), and then called
/// <c>GetRules()</c> on that same errored compiler. The resulting <c>YR_RULES</c> is not a valid ruleset:
/// scanning with it did not terminate in any observed bound — a <b>4-byte</b> all-zero input blew the probe's
/// 120,000 ms watchdog (<c>yara-inprocess-timing-2026-08-21.tsv</c>, E3 <c>zeros-4</c>). Cleanly built
/// rulesets in the same TSV are milliseconds at every size measured (E4 <c>first302</c>: 26,653 B in 5 ms
/// against 302 rule files; E3 at 128 rule files: 1 B in 1 ms, 1,048,576 B in 15 ms), but note that no clean
/// row exists for a 4-byte input, so this is not a like-for-like pair. The fix is a two-pass compile
/// (decision 8) plus a startup canary scan (decision 9), with the 30 s per-file bound kept as defence in
/// depth (decision 10).</para>
///
/// <para><b>Reflection.</b> The two-pass validator, the canary and the two bounds are private statics with no
/// injection seam, and the compiled ruleset is never handed out. Four members are therefore reached by
/// reflection from this file (<c>CompilesCleanly</c>, <c>sharedEngine</c>, <c>scanTimeout</c>,
/// <c>canaryTimeout</c>) and one more (<c>CanaryScanCompletes</c>) from the out-of-process check below; each
/// lookup asserts before it is used, so a rename fails loudly instead of silently skipping the check.
/// Everything else goes through the public surface (<see cref="LibYaraScanner.Available"/>,
/// <see cref="LibYaraScanner.ScanFile"/>, <see cref="PackageScanner.Scan"/>).</para>
///
/// <para><b>One check does not run in this process.</b> Proving the canary can go red means actually scanning
/// a ruleset built from an errored compiler, which abandons a native thread walking a corrupt
/// <c>YR_RULES</c> — undefined behaviour per ADR 0028, i.e. a potential uncatchable native crash (the
/// ADR 0021 hazard class) that would kill the whole test host with no failing test to point at. That one
/// check therefore runs in a child process and is asserted on by exit code; see
/// <see cref="Canary_OnARulesetBuiltFromAnErroredCompiler_RefusesToPublishIt"/>.</para>
///
/// <para><b>Deliberate gap.</b> ADR 0028's "all sources invalid ⇒ log <c>No YARA rules compiled</c> ⇒ unavailable
/// backend" branch is not covered here: <c>BuildEngine</c> reads <c>YaraRuleResources.ReadAll()</c> with no
/// parameter, so no test can hand it an empty or all-invalid rule set without a source change (out of scope —
/// tests only). Its consequence, "an unavailable backend yields <see cref="YaraScanStatus.Unavailable"/>, never
/// <see cref="YaraScanStatus.Completed"/>", is already pinned cross-platform by
/// <c>YaraScanPackageWiringTests.Scan_WithUnavailableFakeScanner_NeverCallsScanDirectory_AndStatusIsUnavailable</c>;
/// the healthy half of that same wiring is pinned here against the REAL backend.</para>
/// </summary>
public sealed class LibYaraScannerPoisoningTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public LibYaraScannerPoisoningTests(PackageFixture fixture, ITestOutputHelper output)
    {
        this.fixture = fixture;   // also initializes the Silvergun runtime, which LibYaraScanner logs through
        this.output = output;

        // "All yara operations must take place within the scope of a YaraContext"
        // (reference/projects/libyara.NET/YaraContext.h) — a YaraContext is the RAII wrapper for
        // yr_initialize/yr_finalize. The tests that reach `new Compiler()` through the product's pass-1
        // validator do not otherwise force LibYaraScanner's own context to exist, and xUnit guarantees no
        // ordering within a class, so nothing may assume an earlier test initialized libyara. One
        // process-wide context is created here instead; yr_initialize is reference-counted, so this simply
        // pins the library up for the run. Deliberately never disposed: yr_finalize while an abandoned
        // native scan thread is still in flight would be a use-after-free (ADR 0028).
        sharedContext ??= new YaraContext();
    }
    #endregion

    #region Methods
    // ADR 0028 decision 8, pass 1. The premise of this whole file is that the embedded ruleset still contains at
    // least one source THIS native build rejects (no ELF module) — without it every other test here would pass
    // vacuously. The product's own validator is run over every embedded source: the bad one(s) must be rejected
    // and every other source must survive, which is only possible if each is validated in its own compiler.
    // Counts are measured, never pinned: the ReversingLabs submodule grows.
    [Fact]
    public void Pass1Validation_RejectsTheSourcesThisNativeBuildCannotCompile_AndKeepsEveryOther()
    {
        var sources = YaraRuleResources.ReadAll().ToArray();
        Assert.NotEmpty(sources);

        var outcomes = sources.Select(s => (s.ResourceName, Ok: CompilesCleanly(s.ResourceName, s.Text))).ToArray();
        var rejected = outcomes.Where(o => !o.Ok).Select(o => o.ResourceName).ToArray();
        var accepted = outcomes.Count(o => o.Ok);
        output.WriteLine($"{sources.Length} embedded rule source(s): {accepted} validated, {rejected.Length} rejected.");
        foreach (var name in rejected)
            output.WriteLine("  rejected: " + name);

        // The trigger is still in the ruleset...
        Assert.NotEmpty(rejected);
        // ...and it took nothing else down with it: every remaining source validated.
        Assert.Equal(sources.Length - rejected.Length, accepted);
        // Sanity that "kept every other" is a real statement and not a ruleset that is nearly all rejects.
        Assert.True(accepted > rejected.Length * 10, $"Only {accepted} of {sources.Length} sources validated; the ruleset itself is broken.");
    }

    // ADR 0028 decision 8: "a throwaway compiler that errors is discarded and never asked for rules". The
    // observable consequence is order independence — validating a source that CANNOT compile must not leave any
    // state behind that makes the next (perfectly good) source fail too. Synthetic sources, so this pins the
    // isolation itself rather than today's ELF accident.
    [Fact]
    public void Pass1Validation_AfterASourceThatCannotCompile_StillAcceptsTheNextGoodSource()
    {
        const string bad = "rule silvergun_not_yara_at_all { condition: this is not yara }";
        const string good = "rule silvergun_ok { strings: $a = \"silvergun\" condition: $a }";

        Assert.False(CompilesCleanly("synthetic-bad.yara", bad));
        Assert.True(CompilesCleanly("synthetic-good.yara", good));
        // ...and the reverse order behaves identically: neither validation can see the other's compiler.
        Assert.True(CompilesCleanly("synthetic-good.yara", good));
        Assert.False(CompilesCleanly("synthetic-bad.yara", bad));
    }

    // ADR 0028 decision 8, pass 2: the published ruleset is built from the SURVIVORS, not from an errored
    // compiler and not from nothing. A ruleset with zero rules would also be "available" and fast, so the
    // enumeration is the assertion that pass 2 actually added the validated sources. Every embedded source that
    // validates holds at least one rule, so the surviving-source count is a lower bound that needs no pinned
    // magic number. Enumeration is bounded: walking a corrupt YR_RULES is undefined behaviour, so a hang here
    // must fail the test rather than wedge the run.
    [Fact]
    public async Task PublishedRuleset_HoldsAtLeastOneCompiledRulePerSurvivingSource()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; every assertion below would be vacuous.");

        var surviving = YaraRuleResources.ReadAll().Count(s => CompilesCleanly(s.ResourceName, s.Text));
        var engine = PublishedEngine();
        Assert.NotNull(engine);

        var enumerate = Task.Run(() => engine!.Value.Rules.GetRules().Count);
        var finished = await Task.WhenAny(enumerate, Task.Delay(EnumerationBound));
        Assert.True(ReferenceEquals(finished, enumerate), $"Enumerating the published ruleset did not complete within {EnumerationBound}.");
        var compiled = await enumerate;
        output.WriteLine($"published ruleset holds {compiled} compiled rule(s) from {surviving} surviving source file(s).");

        Assert.True(compiled >= surviving, $"The published ruleset holds {compiled} rule(s) but {surviving} source file(s) survived validation.");
    }

    // ADR 0028's headline symptom, in the cheapest form that reproduces it: against the poisoned ruleset a scan
    // of a 4-byte all-zero file did not complete in 120,000 ms (and, once the 30 s ScanTimeout existed, threw
    // TimeoutException). Neither input size below was measured against a clean ruleset, so the healthy cost is
    // bracketed rather than quoted: every clean row in yara-inprocess-timing-2026-08-21.tsv is milliseconds, and
    // the nearest ones (E3, 128 rule files) are 1 ms at 1 B and 15 ms at 262,144 B. HealthyScanBound is 5 s —
    // >300x that, so the test cannot be flaky on a loaded machine, and still 6x below the 30 s bound that the
    // pre-fix engine blew through.
    [Theory]
    [InlineData(4)]        // the ADR's minimal reproducer
    [InlineData(65536)]
    public void ScanFile_OnASmallFile_CompletesWellInsideTheScanTimeout(int size)
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; the timing below would measure nothing.");

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-yara-canary-{size}-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, new byte[size]);
        try
        {
            var sw = Stopwatch.StartNew();
            var matches = scanner.ScanFile(path);   // a TimeoutException here is the pre-fix behaviour, and fails the test
            sw.Stop();
            output.WriteLine($"scanned {size} B in {sw.ElapsedMilliseconds} ms, {matches.Count} match(es).");

            Assert.True(sw.Elapsed < HealthyScanBound, $"Scanning {size} bytes took {sw.Elapsed}, which is not a healthy in-process scan (< {HealthyScanBound}).");
        }
        finally
        {
            // Best-effort: a scan that blew the 30 s bound leaves the abandoned native thread holding this
            // file's handle open (ADR 0028's secondary symptom), so deleting it throws IOException and would
            // MASK the TimeoutException that is the actual failure. Losing a temp file beats losing the reason.
            try { File.Delete(path); } catch (IOException) { }
        }
    }

    // ADR 0028 decision 9, the direct proof that the canary can go red: hand it a ruleset built EXACTLY the way
    // the defect built one (all sources into one Compiler, swallow the CompilationException, GetRules() anyway)
    // and it must refuse to publish it, within its own bound. Without this, "the canary passes on a healthy
    // ruleset" would be an unfalsifiable guard.
    //
    // THIS CHECK DOES NOT RUN IN THE TEST HOST. Performing it means scanning the poisoned ruleset, and the
    // canary's bound expires while the native yr_rules_scan_mem call is still walking a corrupt YR_RULES; that
    // call cannot be cancelled from managed code (the product abandons it the same way), so the thread runs on
    // for the rest of the process. ADR 0028 calls walking a corrupt YR_RULES undefined behaviour, not merely
    // slow: if that thread ever faulted it would be an uncatchable native crash — ADR 0021's hazard class, no
    // managed exception, no failing test — that took every other test in the run with it and would be
    // undiagnosable months later. So the check lives in a child process (the YaraTimingProbe's --poison-canary
    // mode, which already loads native libyara under -r win-x64) and this test asserts on its exit code. A
    // crash of the abandoned thread now costs exactly one red test, and names itself.
    //
    // A missing probe binary FAILS this test rather than passing it: a vacuous pass on the one mutation test
    // that proves the guard works is worse than a red build with a build command in the message.
    [Fact]
    public void Canary_OnARulesetBuiltFromAnErroredCompiler_RefusesToPublishIt()
    {
        var probe = FindPoisonCanaryProbe(out var searched);
        Assert.True(probe is not null,
            $"The ADR 0028 canary mutation check runs out of process and its probe was not found. Build it with:{Environment.NewLine}" +
            $"  dotnet build {ProbeProject} -c {Configuration} -r win-x64{Environment.NewLine}" +
            $"Looked for:{Environment.NewLine}  " + string.Join(Environment.NewLine + "  ", searched));

        var (exitCode, transcript) = RunToCompletion(probe!, PoisonCanarySwitch, ProbeBound);
        output.WriteLine(transcript);

        Assert.True(exitCode == PoisonCanaryPass,
            $"The out-of-process ADR 0028 canary check exited {exitCode} ({DescribePoisonCanaryExit(exitCode)}).{Environment.NewLine}{transcript}");
    }

    // ADR 0028 decision 9 end to end, through the real backend: a healthy engine passes its startup canary, is
    // published, and a package scan therefore reports Completed. This is the user-visible regression — before the
    // fix the in-process backend had never produced a scan on Windows, reporting Unavailable (after burning 30 s)
    // on every package.
    [Fact]
    public void Scan_WithTheRealInProcessBackend_YieldsCompleted()
    {
        var sw = Stopwatch.StartNew();
        var scan = PackageScanner.Scan(fixture.PkgAPath, resolveReferences: false, runYara: true, yaraScanner: new LibYaraScanner());
        sw.Stop();
        output.WriteLine($"scanned {Path.GetFileName(fixture.PkgAPath)} in {sw.ElapsedMilliseconds} ms: {scan.Value.YaraScanStatus}, {scan.Value.YaraFindings.Count} finding(s).");

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
    }

    // ADR 0028 decision 10 / ADR 0027 decision 4: the per-file bound is unchanged at 30 s and stays defence in
    // depth, while the NEW startup canary bound is far shorter because it scans 64 bytes — anything but instant
    // there means the ruleset is unusable. Pinned by inspection: provoking either bound for real costs 30 s of
    // wall clock (and, for the poisoned case, an abandoned native thread per file).
    [Fact]
    public void Timeouts_StartupCanaryBoundIsFarShorterThanTheUnchangedPerFileScanBound()
    {
        var scanTimeout = ScanBound();
        var canaryTimeout = CanaryBound();

        Assert.Equal(TimeSpan.FromSeconds(30), scanTimeout);
        Assert.True(canaryTimeout < scanTimeout / 2, $"The canary bound ({canaryTimeout}) must be far shorter than the per-file bound ({scanTimeout}).");
        Assert.True(canaryTimeout > TimeSpan.Zero);
    }

    // C1 (ADR 0027 decision 4 / ADR 0016 "never throws"): a NATIVE scan fault is a single file's problem and must
    // be logged and swallowed, never propagated. The reviewed regression let a faulted bounded scan escape
    // ScanFile as an AggregateException, which PackageScanner.ScanYara turns into a whole-package
    // YaraScanStatus.Unavailable — a false Unavailable that also discards every other file's findings.
    //
    // The seam is deterministic and needs no fault injection into src/: hold the target open with
    // FileShare.None. Our own File.Exists guard is satisfied (GetFileAttributes does not need the share), but
    // libyara.NET's Scanner::ScanFile opens the path with FILE_SHARE_READ, so its CreateFile fails and the native
    // wrapper throws — exactly the "CreateFile failing on a share-denied path even after File.Exists said
    // otherwise" path named in ScanFile's own contract.
    [Fact]
    public void ScanFile_WhenTheNativeScanFaults_ReturnsEmptyAndDoesNotThrow()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; ScanFile would short-circuit before reaching the native call.");

        using var tree = new TempTree();
        var target = tree.Write("target.bin", 4096);
        using var exclusive = OpenDenyingShare(target);

        // The precondition that makes this the RIGHT path: the product's own missing-file guard passes, so the
        // failure can only come from the native scan.
        Assert.True(File.Exists(target), "The share-denied file must still exist for File.Exists, or this test would only be covering the missing-file branch.");

        IReadOnlyList<YaraMatch>? matches = null;
        var thrown = Record.Exception(() => matches = scanner.ScanFile(target));
        output.WriteLine($"ScanFile over a share-denied file threw {thrown?.GetType().Name ?? "nothing"} and returned {matches?.Count.ToString() ?? "<no result>"} match(es).");

        Assert.Null(thrown);
        Assert.NotNull(matches);
        Assert.Empty(matches!);
    }

    // C1's user-visible consequence, and the reason it was Critical: one unreadable file must not sink the rest of
    // the package. Over a tree holding several readable files and one share-denied file, the ScanDirectory loop
    // must visit EVERY file and return normally; pre-fix the native fault escaped the first faulting ScanFile,
    // aborted the loop, and PackageScanner reported the whole package Unavailable with zero findings.
    //
    // "Visited every file" is observed through a pass-through decorator rather than by asserting on returned hits:
    // the embedded ReversingLabs ruleset has no benign trigger (no EICAR-style rule), so no file this test is
    // willing to write can be made to match, and an all-empty result would be indistinguishable from an aborted
    // loop. The decorator overrides nothing but ScanFile, so the loop under test is the same default-interface
    // ScanDirectory the product runs.
    [Fact]
    public void ScanDirectory_WhenOneFileFaults_StillScansEveryOtherFileAndDoesNotThrow()
    {
        var real = new LibYaraScanner();
        Assert.True(real.Available, "The in-process engine did not build; every file below would short-circuit.");

        using var tree = new TempTree();
        var locked = tree.Write("0-locked.bin", 4096);
        var readable = new[] { tree.Write("1-readable.bin", 1024), tree.Write("2-readable.bin", 1024), tree.Write("nested/3-readable.bin", 1024) };
        using var exclusive = OpenDenyingShare(locked);

        IYaraScanner observed = new RecordingScanner(real);
        IReadOnlyList<(string FullPath, YaraMatch Match)>? hits = null;
        var thrown = Record.Exception(() => hits = observed.ScanDirectory(tree.Root));
        var visited = ((RecordingScanner)observed).Visited;
        output.WriteLine($"ScanDirectory over 1 share-denied + {readable.Length} readable file(s) threw {thrown?.GetType().Name ?? "nothing"}, visited {visited.Count} file(s), returned {hits?.Count.ToString() ?? "<no result>"} hit(s).");

        Assert.Null(thrown);
        Assert.NotNull(hits);
        // The faulting file did not abort the loop: every readable file was still handed to the backend...
        Assert.All(readable, file => Assert.Contains(file, visited));
        Assert.Contains(locked, visited);
        Assert.Equal(readable.Length + 1, visited.Count);
        // ...and the file that could not be read contributed no hits of its own.
        Assert.DoesNotContain(hits!, hit => string.Equals(hit.FullPath, locked, StringComparison.OrdinalIgnoreCase));
    }

    // The other half of C1: swallowing must NOT have been widened into swallowing the deliberate carve-out. Past
    // its bound ScanFile still throws TimeoutException (ADR 0028 decision 10), naming the path and the bound so
    // PackageScanner.ScanYara can report the package Unavailable rather than a false Completed.
    //
    // The 30 s production bound is shortened for the duration of this test only. FieldInfo.SetValue cannot write
    // an initonly static field on CoreCLR, so a DynamicMethod emitting stsfld with skipVisibility does it; the
    // original value is restored in a finally and re-read from the field to prove the restore. This class is its
    // own xUnit collection (IClassFixture) and is the only place in the suite that touches the real backend, so
    // the window cannot be observed by another test.
    //
    // KNOWN HAZARD, read this before "fixing" an intermittent red here. The JIT is entitled to treat a
    // static readonly as a CONSTANT once the type's cctor has run and to bake its value into already-compiled
    // code — increasingly likely at tier 1, and by the time this test runs the other tests in this class have
    // called ScanFile many times, so ScanFile may well have been re-jitted with 30 s inlined. In that case the
    // stsfld below still lands in the field but ScanFile never observes it, and this test fails with
    // "nothing thrown". Note that the guard on the next line does NOT catch that: reflection reads the real
    // field, so it happily reports the shortened bound while the compiled code uses the old one. A failure
    // here is therefore either a genuine regression in the timeout carve-out or this JIT effect — check
    // whether ScanFile actually returned quickly (JIT effect) or slowly (real).
    [Fact]
    public void ScanFile_PastItsBound_StillThrowsTimeoutExceptionNamingThePathAndBound()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; ScanFile would return before ever starting a bounded scan.");

        var original = ScanBound();
        Assert.Equal(TimeSpan.FromSeconds(30), original);   // guard: never restore a value this test invented

        using var tree = new TempTree();
        // Big enough that a healthy scan cannot finish inside the shortened bound, small enough that the
        // abandoned native thread it leaves behind is done in a few tens of milliseconds (TempTree.Dispose
        // waits it out, so nothing is leaked).
        //
        // 8 MiB is measured, not guessed, and is NOT over-provisioned: the enforced bound is not really 1 ms.
        // TryRunBounded enforces it with Thread.Join(TimeSpan), i.e. WaitForSingleObject, whose expiry is
        // quantized to the system timer interval — 15.6 ms by default on Windows. So the effective bound is
        // somewhere in 1..~16 ms and the input has to cost comfortably more than THAT, not more than 1 ms.
        // Measured 2026-08-21 with the same probe on the same box as yara-inprocess-timing-2026-08-21.tsv, over
        // a clean 302-file ruleset (`--experiments E1,E3 --max-rules 302`; these rows are not in that TSV,
        // which docs/ owns): 1 MiB all-zero 9 ms, 2 MiB 8 ms, 4 MiB 20 ms, 8 MiB 33 ms. 1 MiB sits UNDER the
        // timer quantum and this test then goes red with "nothing thrown" — verified, not hypothesized.
        // 8 MiB is the smallest of those with a 2x margin over the quantum.
        var target = tree.Write("slow-enough.bin", 8 * 1024 * 1024);

        Exception? thrown;
        try
        {
            SetScanBound(ShortenedBound);
            Assert.Equal(ShortenedBound, ScanBound());   // the stsfld actually took, so a pass below is not vacuous
            thrown = Record.Exception(() => scanner.ScanFile(target));
        }
        finally
        {
            SetScanBound(original);
        }

        Assert.Equal(original, ScanBound());   // no mutated global bound is left behind for the rest of the suite
        output.WriteLine($"ScanFile under a {ShortenedBound} bound threw: {thrown?.GetType().Name ?? "nothing"} — {thrown?.Message}");

        var timeout = Assert.IsType<TimeoutException>(thrown);
        Assert.Contains(target, timeout.Message, StringComparison.Ordinal);
        Assert.Contains(ShortenedBound.ToString(), timeout.Message, StringComparison.Ordinal);
    }
    #endregion

    #region Helpers
    // Pass-1 validation as the product performs it. Private static with no seam (see the class doc).
    private static bool CompilesCleanly(string resource, string text) =>
        (bool)PrivateMethod("CompilesCleanly", typeof(string), typeof(string)).Invoke(null, [resource, text])!;

    private static TimeSpan CanaryBound() => (TimeSpan)PrivateField("canaryTimeout").GetValue(null)!;

    // The per-file wall-clock bound ScanFile enforces (ADR 0028 decision 10).
    private static TimeSpan ScanBound() => (TimeSpan)PrivateField("scanTimeout").GetValue(null)!;

    // The engine LibYaraScanner actually published (null when it refused to publish one).
    private static (YaraContext Context, Rules Rules, Scanner Scanner)? PublishedEngine()
    {
        var field = typeof(LibYaraScanner).GetField("sharedEngine", Flags);
        Assert.True(field is not null, "LibYaraScanner.sharedEngine is gone; this test can no longer see the published ruleset.");
        return ((Lazy<(YaraContext Context, Rules Rules, Scanner Scanner)?>)field!.GetValue(null)!).Value;
    }

    // Locates the child process that performs the ADR 0028 canary mutation check (see the canary test). The
    // probe is a separate project with its own bin\, so it is found by walking up to the repo root (the
    // directory holding CLAUDE.md) — the same trick the probe itself uses to find the repo. This build's
    // configuration is tried first, then the other, because either is a legitimate way to have built it.
    private static string? FindPoisonCanaryProbe(out IReadOnlyList<string> searched)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "CLAUDE.md")))
            root = root.Parent;

        var candidates = (root is null ? Array.Empty<string>() :
            new[] { Configuration, Configuration == "Release" ? "Debug" : "Release" }
                .Select(c => Path.Combine(root.FullName, "tests", ProbeDirectory, "bin", c, "net10.0-windows", "win-x64", ProbeDirectory + ".exe"))
                .ToArray());

        searched = candidates.Length > 0 ? candidates : ["<repo root not found above " + AppContext.BaseDirectory + ">"];
        return candidates.FirstOrDefault(File.Exists);
    }

    // Runs a child process to completion under a wall-clock bound, returning its exit code and a transcript of
    // everything it said. Both streams are drained on their own tasks: a child that fills a redirected pipe
    // while the parent blocks in WaitForExit would deadlock, which would read here as an infinite hang.
    private static (int ExitCode, string Transcript) RunToCompletion(string exe, string argument, TimeSpan bound)
    {
        var start = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(exe)!,
        };
        start.ArgumentList.Add(argument);

        using var child = Process.Start(start);
        Assert.True(child is not null, $"Could not start the probe process '{exe}'.");

        var stdout = child!.StandardOutput.ReadToEndAsync();
        var stderr = child.StandardError.ReadToEndAsync();
        if (!child.WaitForExit((int)bound.TotalMilliseconds))
        {
            try { child.Kill(entireProcessTree: true); } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            Assert.Fail($"The probe process '{exe} {argument}' did not exit within {bound}; it was killed. Its output so far is not recoverable.");
        }

        child.WaitForExit();   // the timed overload does not guarantee the redirected streams are drained
        var transcript = $"[{Path.GetFileName(exe)} {argument}] exit={child.ExitCode}{Environment.NewLine}{stdout.Result}{stderr.Result}".TrimEnd();
        return (child.ExitCode, transcript);
    }

    // Mirrors PoisonCanaryCheck's exit-code contract so a red build says what actually went wrong instead of
    // printing a bare number. An unrecognized code is the interesting case: that is where a native crash of
    // the abandoned scan thread (the whole reason this runs out of process) would show up.
    private static string DescribePoisonCanaryExit(int code) => code switch
    {
        0 => "pass",
        20 => "no embedded rule source failed to compile, so the ruleset was not poisoned and the check proved nothing",
        21 => "the startup canary ACCEPTED a ruleset built from an errored compiler — ADR 0028 decision 9's guard no longer goes red",
        22 => "the canary refused the poisoned ruleset but was not bounded while doing it",
        23 => "a reflected LibYaraScanner member the check depends on is gone",
        24 => "the check threw",
        25 => "the native libyara.NET assembly could not be loaded",
        _ => "UNDOCUMENTED — most likely the probe process died on the abandoned native scan thread, which is exactly the crash this test is isolated to contain",
    };

    private static MethodInfo PrivateMethod(string name, params Type[] parameters)
    {
        var method = typeof(LibYaraScanner).GetMethod(name, Flags, binder: null, parameters, modifiers: null);
        Assert.True(method is not null, $"LibYaraScanner.{name} is gone; the ADR 0028 guard it backs is no longer testable.");
        return method!;
    }

    private static FieldInfo PrivateField(string name)
    {
        var field = typeof(LibYaraScanner).GetField(name, Flags);
        Assert.True(field is not null, $"LibYaraScanner.{name} is gone; the ADR 0028 bound it backs is no longer testable.");
        return field!;
    }

    // Opens the path for reading while DENYING every share mode. libyara.NET's Scanner::ScanFile calls CreateFile
    // with FILE_SHARE_READ, so its open fails for as long as this handle lives — a native scan fault with no
    // fault injection and no source seam. File.Exists (GetFileAttributes) is unaffected, so the product's own
    // missing-file guard still passes and the failure lands where the C1 finding says it lands.
    private static FileStream OpenDenyingShare(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.None);

    // Writes LibYaraScanner.scanTimeout. FieldInfo.SetValue throws FieldAccessException ("Cannot set initonly
    // static field ... after type ... is initialized") on CoreCLR; a DynamicMethod owned by the target type with
    // skipVisibility can still emit stsfld against it.
    private static void SetScanBound(TimeSpan value)
    {
        var field = PrivateField("scanTimeout");
        var setter = new DynamicMethod("silvergun_set_scanTimeout", returnType: null, [typeof(TimeSpan)], typeof(LibYaraScanner), skipVisibility: true);
        var il = setter.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Stsfld, field);
        il.Emit(OpCodes.Ret);
        setter.CreateDelegate<Action<TimeSpan>>()(value);
    }
    #endregion

    #region Nested types
    // A pass-through IYaraScanner that records which paths the ScanDirectory loop actually reached before
    // delegating to the real backend. It overrides ONLY the ScanFile primitive, so ScanDirectory is the very same
    // default-interface loop PackageScanner.ScanYara drives — the decorator observes that loop, it does not
    // replace it.
    private sealed class RecordingScanner(IYaraScanner inner) : IYaraScanner
    {
        public bool Available => inner.Available;

        public List<string> Visited { get; } = [];

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
        {
            Visited.Add(fullPath);
            return inner.ScanFile(fullPath);
        }
    }

    // A self-cleaning temp tree. Files are all-zero bytes: cheap to create, and the shape the ADR's own timing
    // work used, so no synthetic content here can accidentally trip a real malware signature.
    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), "silvergun-yara-fault-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string Write(string relative, int size)
        {
            var full = Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllBytes(full, new byte[size]);
            return full;
        }

        // Best-effort, exactly as elsewhere in this file: an IOException here must never propagate, because it
        // would MASK the real assertion failure.
        //
        // But best-effort used to mean "leaks 8 MiB into %TEMP% on every single run": the timeout test's scan
        // is abandoned mid-flight and the native call keeps the target's handle open until it finishes (~33 ms
        // for that input), which is always still true when this runs microseconds later. So the delete is
        // retried for a bounded moment instead of being given up on immediately. One retry is normally enough.
        public void Dispose()
        {
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    if (Directory.Exists(Root))
                        Directory.Delete(Root, recursive: true);
                    return;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    if (attempt == CleanupAttempts)
                        return;   // give up quietly: a leaked temp file is not worth failing a green test over
                    Thread.Sleep(CleanupRetryDelay);
                }
            }
        }

        // 20 x 100 ms: ~60x what the abandoned 8 MiB scan needs (33 ms measured), and still a bounded cost
        // — and only ever paid at all when a scan really was abandoned. In practice one retry suffices.
        private const int CleanupAttempts = 20;
        private static readonly TimeSpan CleanupRetryDelay = TimeSpan.FromMilliseconds(100);
    }
    #endregion

    #region Fields
    private const BindingFlags Flags = BindingFlags.NonPublic | BindingFlags.Static;

    // Every healthy scan measured for ADR 0028 is milliseconds — the slowest clean row in
    // yara-inprocess-timing-2026-08-21.tsv is 18 ms (E3, 1 MiB of random bytes against 128 rule files) — while
    // the poisoned ruleset did not finish a 4-byte input in 120,000 ms. Anything in between is a defect, so the
    // bound only has to separate the two, with enough headroom that a loaded machine cannot fail it.
    private static readonly TimeSpan HealthyScanBound = TimeSpan.FromSeconds(5);

    // Same idea for walking the compiled ruleset in memory: milliseconds when it is valid, unbounded when it is not.
    private static readonly TimeSpan EnumerationBound = TimeSpan.FromSeconds(5);

    // The per-file bound scanTimeout is temporarily lowered to while the TimeoutException carve-out is
    // exercised. Non-zero so the test proves the bound is ENFORCED rather than that Join(0) never observes a
    // started thread. Note that Thread.Join quantizes this to the system timer interval (~15.6 ms on Windows),
    // which is what actually sizes the input the timeout test scans — see that test.
    private static readonly TimeSpan ShortenedBound = TimeSpan.FromMilliseconds(1);

    // Wall-clock bound for the out-of-process canary check. Its own work is process start plus one compile of
    // every embedded source into one compiler (226 ms and 295 ms in the TSV's two E1 compile-all rows) plus the
    // product's own 5 s canary bound — ~6 s end to end, observed. This is an order of magnitude more, and
    // exists only so a wedged child cannot hang the suite.
    private static readonly TimeSpan ProbeBound = TimeSpan.FromSeconds(120);

    // The child process that performs the poisoned-ruleset canary check, and the mode that selects it. Kept in
    // sync with tests/Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe/PoisonCanaryCheck.cs, whose exit
    // codes DescribePoisonCanaryExit mirrors.
    private const string ProbeDirectory = "Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe";
    private const string ProbeProject = "tests/" + ProbeDirectory + "/" + ProbeDirectory + ".csproj";
    private const string PoisonCanarySwitch = "--poison-canary";
    private const int PoisonCanaryPass = 0;

#if DEBUG
    private const string Configuration = "Debug";
#else
    private const string Configuration = "Release";
#endif

    // Keeps libyara initialized for the lifetime of this class's tests (see the constructor).
    private static YaraContext? sharedContext;

    private readonly PackageFixture fixture;
    private readonly ITestOutputHelper output;
    #endregion
}
#endif
