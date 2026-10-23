#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;

/// <summary>
/// The hidden <c>__worker yara --protocol 1</c> verb of the REAL net10.0-windows CLI, against the real pinned
/// <c>yara_x_capi.dll</c> and the real embedded rules (ADR 0033 FINAL FORM; <c>docs/agent/tasks/yarax-worker.md</c> T3, T5).
///
/// <para><b>Where these live (amendment (m)).</b> <c>Silvergun.CLI.Tests</c> builds net10.0 only, where the verb correctly
/// answers <c>fatal</c> "engine unavailable on this platform" (pinned there). This project has a net10.0-windows TFM and
/// takes the CLI as a net10.0-windows ProjectReference, so <c>Silvergun.CLI.exe</c> is in this test bin and is launched
/// here exactly as the parent launches it: an argument array, raw redirected streams, requests written on their own
/// task.</para>
///
/// <para><b>The rules cache is never the user's.</b> The worker's cache is <c>%LOCALAPPDATA%\Silvergun\yara-x-rules</c>, and
/// LocalApplicationData follows <c>USERPROFILE</c> (measured), so every child gets a private temp USERPROFILE. One per test
/// class (warm after the first run); the planted-ruleset timeout test has its own.</para>
///
/// <para>The positive is <see cref="HermeticWiperSample"/>: inert bytes derived at run time from the embedded rule.</para>
/// </summary>
public sealed class YaraWorkerVerbWindowsTests(YaraWorkerVerbWindowsTests.Profile profile) : IClassFixture<YaraWorkerVerbWindowsTests.Profile>
{
    #region Methods: ready
    // The real worker's ready satisfies G1: the parent's own hash of its embedded rules (G9), rules loaded, canary passed,
    // no source with compile errors. Pinned byte for byte except the rule count.
    [Fact]
    public void Ready_IsGenuine_AndCarriesTheParentsOwnRulesHash()
    {
        var run = Run(WorkerArgs, []);

        Assert.Equal(0, run.Exit);
        var lines = Lines(run);
        Assert.Equal(2, lines.Length);
        var ready = ReadyPattern.Match(lines[0]);
        Assert.True(ready.Success, $"the ready line is not the genuine shape: {lines[0]}");
        Assert.Equal(YaraXRules.SourcesSha256Of(YaraRuleResources.ReadAll()), ready.Groups["sha"].Value);
        Assert.Equal(YaraXWorkerScanner.ExpectedRulesSha256, ready.Groups["sha"].Value);
        Assert.True(int.Parse(ready.Groups["count"].Value) > 300, $"only {ready.Groups["count"].Value} rules");
        Assert.Equal("{\"type\":\"done\",\"count\":0}", lines[1]);
    }
    #endregion

    #region Methods: files
    // A plain path to a real file named like a DOS device opens the DEVICE (spike: SUCCESS, no hits). The worker opens
    // each request's file through its \\?\ form, so these are scanned as the files they are and the positive is found.
    [Fact]
    public void RealFilesNamedNulConAndNulTxt_AreScannedAsFiles_AndThePositiveIsFound()
    {
        using var tree = new ScanTree("verb-devices");
        string[] names = ["NUL", "CON", "nul.txt", "aux", "COM1.bin", @"lpt1\inside.bin", @"foo.\inside.bin"];
        var paths = names.Select(n => tree.Write(n, HermeticWiperSample.Bytes)).ToArray();

        var run = Run(WorkerArgs, Requests(paths));

        Assert.Equal(0, run.Exit);
        var outcome = Outcome(run, paths.Length);
        Assert.True(outcome.Done, run.Stdout);
        for (var i = 0; i < paths.Length; i++)
        {
            Assert.Equal("scanned", outcome.Results[i].Status);
            Assert.Contains(HermeticWiperSample.RuleName, outcome.Results[i].Rules);
        }
        AssertNoCanary(outcome);
    }

    // G7: the worker opens with read sharing only, so a file someone holds open for WRITE (who could change or truncate it
    // under a mapped scan) cannot be opened: that file is an error, and the next file is still scanned.
    [Fact]
    public void AFileHeldOpenForWrite_IsAnError_AndTheNextFileIsStillScanned()
    {
        using var tree = new ScanTree("verb-held");
        var held = tree.Write("held.bin", HermeticWiperSample.Bytes);
        var next = tree.Write("next.bin", HermeticWiperSample.Bytes);
        using var writer = new FileStream(held, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);

        var run = Run(WorkerArgs, Requests(held, next));

        var outcome = Outcome(run, 2);
        Assert.True(outcome.Done, run.Stdout);
        Assert.Equal("error", outcome.Results[0].Status);
        Assert.StartsWith("could not open the file: IOException", outcome.Results[0].Reason, StringComparison.Ordinal);
        Assert.Equal("scanned", outcome.Results[1].Status);
        Assert.Contains(HermeticWiperSample.RuleName, outcome.Results[1].Rules);
    }

    // A byte-range lock held by someone with read access only: the worker can open the file, but the read fails, which is
    // an error, never a short or empty scan.
    [Fact]
    public void AFileWithAByteRangeLock_IsAnError_AndTheNextFileIsStillScanned()
    {
        using var tree = new ScanTree("verb-locked");
        var locked = tree.Write("locked.bin", HermeticWiperSample.Bytes);
        var next = tree.Write("next.bin", HermeticWiperSample.Bytes);
        using var locker = new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.Read);
        locker.Lock(0, locker.Length);

        var run = Run(WorkerArgs, Requests(locked, next));

        var outcome = Outcome(run, 2);
        Assert.True(outcome.Done, run.Stdout);
        Assert.Equal("error", outcome.Results[0].Status);
        Assert.StartsWith("could not read the file: IOException", outcome.Results[0].Reason, StringComparison.Ordinal);
        Assert.Equal("scanned", outcome.Results[1].Status);
        locker.Unlock(0, locker.Length);
    }

    [Fact]
    public void AMissingFile_IsAnError_AndTheNextFileIsStillScanned()
    {
        using var tree = new ScanTree("verb-missing");
        var next = tree.Write("next.bin", HermeticWiperSample.Bytes);

        var run = Run(WorkerArgs, Requests(Path.Combine(tree.Root, "not-there.bin"), next));

        var outcome = Outcome(run, 2);
        Assert.True(outcome.Done, run.Stdout);
        Assert.Equal("error", outcome.Results[0].Status);
        Assert.StartsWith("could not open the file: FileNotFoundException", outcome.Results[0].Reason, StringComparison.Ordinal);
        Assert.Equal("scanned", outcome.Results[1].Status);
    }

    // G2, worker side: a request path out of the protocol's form is refused by the worker too (a parent bug errs safe).
    [Theory]
    [InlineData("relative.bin")]
    [InlineData(@"C:\a\b.bin:ads")]
    [InlineData(@"\\?\C:\Windows\win.ini")]
    [InlineData(@"C:\Windows\..\Windows\win.ini")]
    public void ARequestPathOutOfForm_IsAnError_InvalidPathForm(string path)
    {
        var run = Run(WorkerArgs, Requests(path));

        var outcome = Outcome(run, 1);
        Assert.True(outcome.Done, run.Stdout);
        Assert.Equal(("error", "invalid path form"), (outcome.Results[0].Status, outcome.Results[0].Reason));
    }

    // The canary is never a finding: a file holding this worker's own canary marker (read back from the entry the worker
    // cached; the next run loads that same canary from the cache) is scanned and reports nothing.
    [Fact]
    public void TheCanaryMarker_IsNeverReportedAsAHit()
    {
        Run(WorkerArgs, []);   // warm: the cache entry (and with it the canary every later run loads) exists
        var entry = Directory.GetFiles(profile.CacheDirectory, "rules-*.sgyx").Single();
        var marker = File.ReadAllBytes(entry).AsSpan(88, YaraXCanary.MarkerBytes).ToArray();
        using var tree = new ScanTree("verb-canary");
        var bare = tree.Write("marker.bin", marker);
        var embedded = tree.Write("embedded.bin", [.. HermeticWiperSample.Bytes, .. new byte[1000], .. marker]);   // the rule needs MZ at 0

        var run = Run(WorkerArgs, Requests(bare, embedded));

        Assert.Contains("from the rules cache", run.Stderr, StringComparison.Ordinal);
        var outcome = Outcome(run, 2);
        Assert.True(outcome.Done, run.Stdout);
        Assert.Equal("scanned", outcome.Results[0].Status);
        Assert.Empty(outcome.Results[0].Rules);
        Assert.Contains(HermeticWiperSample.RuleName, outcome.Results[1].Rules);
        AssertNoCanary(outcome);
    }
    #endregion

    #region Methods: --timeout reaches the engine (G3)
    // The embedded rules hold nothing slow, so the worker is given a planted ruleset: an entry in its PRIVATE cache, under
    // the embedded rules' key, holding the quadratic slow rule plus a marker rule (the tamper shape the owner-only directory
    // exists to stop, used here on purpose). `--timeout 2` reaches the engine: the slow file is `timeout` with the engine's
    // own wording, and the file after it is still scanned.
    [Fact]
    [Trait("Category", "Slow")]
    public void Timeout_ReachesTheEngine_ASlowFileTimesOut_AndTheNextIsStillScanned()
    {
        using var own = new Profile();
        var marker = YaraX.Marker();
        PlantRuleset(own, YaraX.SlowRule, YaraX.MarkerRule("after_the_timeout", marker));
        using var tree = new ScanTree("verb-timeout");
        var slow = tree.Write("slow.bin", new byte[64 * 1024]);
        var next = tree.Write("next.bin", marker);

        var clock = Stopwatch.StartNew();
        var run = Run([.. WorkerArgs, "--timeout", "2"], Requests(slow, next), profileRoot: own.Root);
        clock.Stop();

        Assert.Equal(0, run.Exit);
        var outcome = Outcome(run, 2);
        Assert.True(outcome.Done, run.Stdout + run.Stderr);
        Assert.Contains("ruleCount\":2,", Lines(run)[0], StringComparison.Ordinal);   // the planted ruleset really loaded
        Assert.Equal(("timeout", "the scan did not finish within the engine timeout of 2 s"), (outcome.Results[0].Status, outcome.Results[0].Reason));
        Assert.Equal(new[] { "after_the_timeout" }, outcome.Results[1].Rules);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(60), $"the run took {clock.Elapsed}");
        Assert.Contains("per-file timeout 2 s", run.Stderr, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("3601")]
    public void Timeout_OutOfRange_IsFatalBeforeTheEngineLoads(string value)
    {
        var record = Path.Combine(profile.Root, $"modules-{Guid.NewGuid():N}.txt");

        var run = Run([.. WorkerArgs, "--timeout", value], [], ModuleRecording(record));

        Assert.Equal(3, run.Exit);
        Assert.Equal($"invalid --timeout '{value}'; expected whole seconds from 2 to 3600", FatalReason(Assert.Single(Lines(run))));
        Assert.DoesNotContain(Modules(record), m => m.StartsWith("yara_x_capi", StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Methods: a worker command line that does not parse (FR2.3)
    // The net10.0 build's twin is Silvergun.CLI.Tests' YaraWorkerVerbCliTests. Anything under `__worker` that does not
    // resolve to the yara worker's own action is exactly one `fatal` on stdout and exit 3, never System.CommandLine's help
    // or error text on stdout (exit 1); and, decided before any engine, the YARA-X DLL never loads for it.
    public static TheoryData<string, string[]> WorkerCommandLinesThatDoNotParse() => new()
    {
        { "a repeated --timeout", ["__worker", "yara", "--protocol", "1", "--timeout", "5", "--timeout", "6"] },
        { "a repeated --protocol", ["__worker", "yara", "--protocol", "1", "--protocol", "1"] },
        { "an unknown option", ["__worker", "yara", "--protocol", "1", "--bogus"] },
        { "an unknown positional token", ["__worker", "yara", "--protocol", "1", "extra"] },
        { "--protocol without its value", ["__worker", "yara", "--protocol"] },
        { "__worker yara --help", ["__worker", "yara", "--help"] },
        { "-h after valid arguments", ["__worker", "yara", "--protocol", "1", "-h"] },
        { "-? on the yara worker", ["__worker", "yara", "-?"] },
        { "a bare __worker", ["__worker"] },
        { "__worker --help", ["__worker", "--help"] },
        { "an unknown worker", ["__worker", "il", "--protocol", "1"] },
    };

    [Theory]
    [MemberData(nameof(WorkerCommandLinesThatDoNotParse))]
    public void Worker_ACommandLineThatDoesNotParse_IsOneFatalOnStdout_AndExitThree(string what, string[] args)
    {
        var record = Path.Combine(profile.Root, $"modules-{Guid.NewGuid():N}.txt");

        var run = Run(args, Utf8(Request(0) + "\n"), ModuleRecording(record));

        Assert.True(run.Exit == 3, $"{what}: exit {run.Exit}");
        var reason = FatalReason(Assert.Single(Lines(run)));
        Assert.Matches(@"^the worker's arguments (did not parse \([0-9]+ error\(s\)\)|asked for something other than a worker session); expected __worker yara --protocol 1 \[--timeout <seconds>\]$", reason);
        Assert.DoesNotContain("Usage", run.Stdout, StringComparison.Ordinal);
        Assert.Contains("[ERR] yara worker: fatal: the worker's arguments", run.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain(Modules(record), m => m.StartsWith("yara_x_capi", StringComparison.OrdinalIgnoreCase));
    }

    // Outside worker mode nothing changed on this build either: help on stdout, the parser's error on stderr, exit 1.
    [Fact]
    public void NormalMode_AParseError_StillPrintsHelpToStdout_AndExitsOne()
    {
        var run = Run(["scan-package", "x.nupkg", "--bogus"], []);

        Assert.Equal(1, run.Exit);
        Assert.Contains("Usage:", run.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("\"type\":\"fatal\"", run.Stdout, StringComparison.Ordinal);
        Assert.Contains("Unrecognized command or argument '--bogus'", run.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    public void NormalMode_RootHelp_StillPrintsHelpToStdout_AndExitsZero_WithoutTheHiddenVerb()
    {
        var run = Run(["--help"], []);

        Assert.Equal(0, run.Exit);
        Assert.Contains("scan-package", run.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("__worker", run.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("\"type\":\"fatal\"", run.Stdout, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: malformed request streams (moved from Silvergun.CLI.Tests, T1's stub, amendment (m))
    // Each malformed stream: the real ready, one `error` per accepted request (these test paths are relative, so "invalid
    // path form"), then `fatal` "malformed request stream", exit 3, and never `done`.
    [Fact]
    public void AnUnknownRequestField_IsReadyThenFatal()
    {
        var run = Run(WorkerArgs, Utf8("{\"index\":0,\"path\":\"a.bin\",\"extra\":1}\n"));

        AssertReadyErrorsThenFatal(run, results: 0, "malformed request stream");
    }

    [Fact]
    public void AnOutOfOrderIndex_KeepsTheEarlierResults_ThenFatal()
    {
        var run = Run(WorkerArgs, Utf8(Request(0) + "\n" + Request(1) + "\n" + Request(3) + "\n" + Request(2) + "\n"));

        Assert.Contains("out of order", AssertReadyErrorsThenFatal(run, results: 2, "malformed request stream"), StringComparison.Ordinal);
    }

    [Fact]
    public void ATruncatedLastRequest_KeepsTheEarlierResult_ThenFatal()
    {
        var run = Run(WorkerArgs, Utf8(Request(0) + "\n" + Request(1)));

        Assert.Contains("truncated", AssertReadyErrorsThenFatal(run, results: 1, "malformed request stream"), StringComparison.Ordinal);
    }

    [Fact]
    public void ARequestLineOverOneMiB_IsFatal()
    {
        var run = Run(WorkerArgs, Utf8("{\"index\":0,\"path\":\"" + new string('a', 1024 * 1024) + "\"}\n"));

        Assert.Contains("exceeds 1048576 bytes", AssertReadyErrorsThenFatal(run, results: 0, "malformed request stream"), StringComparison.Ordinal);
    }

    [Fact]
    public void InvalidUtf8InARequest_IsFatal()
    {
        var bytes = Utf8(Request(0) + "\n").Concat(Utf8("{\"index\":1,\"path\":\"a")).Concat(new byte[] { 0xFF, 0xFE }).Concat(Utf8("\"}\n")).ToArray();

        var run = Run(WorkerArgs, bytes);

        Assert.Contains("UTF-8", AssertReadyErrorsThenFatal(run, results: 1, "malformed request stream"), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: stdout is protocol only, and what loads where
    // W2: worker mode replaces Console.Out with TextWriter.Null. The startup hook writes through Console.Out at process
    // exit, after the verb has finished; none of it may reach stdout, which must hold exactly the protocol records.
    [Fact]
    public void AConsoleOutWriteInWorkerMode_NeverReachesStdout()
    {
        var run = Run(WorkerArgs, [], new Dictionary<string, string?>
        {
            ["DOTNET_STARTUP_HOOKS"] = HookDll,
            ["SILVERGUN_TEST_CONSOLE_OUT_AT_EXIT"] = "LEAKED-THROUGH-CONSOLE-OUT\n",
        });

        Assert.Equal(0, run.Exit);
        Assert.DoesNotContain("LEAKED", run.Stdout, StringComparison.Ordinal);
        Assert.Equal(2, Lines(run).Length);
    }

    // The windows worker DOES load the YARA-X DLL (that is its job), from the application directory; it still loads none
    // of the analysis code (ADR 0033 decision 5): the app-local assemblies are exactly the verb's.
    [Fact]
    public void WorkerMode_LoadsTheYaraXDllFromTheAppDirectory_AndNoAnalysisCode()
    {
        var record = Path.Combine(profile.Root, $"modules-{Guid.NewGuid():N}.txt");
        using var tree = new ScanTree("verb-modules");
        var file = tree.Write("a.bin", [1, 2, 3]);

        var run = Run(WorkerArgs, Requests(file), ModuleRecording(record));

        Assert.Equal(0, run.Exit);
        var (assemblies, modules) = Record(record);
        Assert.Contains(modules, m => string.Equals(m.Path, Path.Combine(AppContext.BaseDirectory, "yara_x_capi.dll"), StringComparison.OrdinalIgnoreCase));
        var appLocal = assemblies.Where(a => a.Location.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase))
            .Select(a => a.Name).Where(n => n != "Silvergun.CLI.Tests.LoadedAssembliesHook").ToArray();
        Assert.Empty(appLocal.Except(AllowedWorkerAssemblies, StringComparer.Ordinal));
        Assert.DoesNotContain(assemblies, a => a.Name is "Silvergun.CodeAnalysis.IL" or "Silvergun.Intel" or "libyara.NET" or "Spectre.Console" or "Serilog.Sinks.File"
            || a.Name.StartsWith("NuGet.", StringComparison.Ordinal) || a.Name.Contains("Cci", StringComparison.OrdinalIgnoreCase));
    }

    // ADR 0033 decision 5, the remaining round-1 item: a NORMAL CLI run never loads yara_x_capi.dll. Since T6b the default
    // engine IS the YARA-X worker, so the default and SILVERGUN_YARA_ENGINE=yarax behave alike: the scan really runs on the
    // worker (Completed), only the worker children load the DLL, and never the scan-package process itself.
    [Theory]
    [InlineData(null)]
    [InlineData("yarax")]
    public void ScanPackage_NeverLoadsTheYaraXDll_InItsOwnProcess(string? engine)
    {
        var records = Path.Combine(profile.Root, $"scan-{Guid.NewGuid():N}");
        Directory.CreateDirectory(records);
        using var dir = new YaraXTempDir("verb-scan");
        var nupkg = YaraXWorkerScannerProtocolTests.Nupkg(dir, "SilvergunNeverLoadsYaraX");
        var env = ModuleRecording(Path.Combine(records, "{pid}.txt"));
        env["SILVERGUN_YARA_ENGINE"] = engine;

        var run = Run(["scan-package", nupkg, "--json", "--no-vulns", "--no-resolve"], [], env, workingDirectory: dir.Root);

        Assert.True(File.Exists(Path.Combine(records, $"{run.Pid}.txt")), "the scan-package process wrote no module record\n" + run.Stderr);
        var (assemblies, modules) = Record(Path.Combine(records, $"{run.Pid}.txt"));
        Assert.Contains(assemblies, a => a.Name == "Silvergun.PackageAnalysis.NuGet");   // the scan path really ran in it
        Assert.DoesNotContain(modules, m => m.Name.StartsWith("yara_x_capi", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(assemblies, a => a.Name.StartsWith("libyara", StringComparison.OrdinalIgnoreCase));
        using var json = JsonDocument.Parse(run.Stdout);
        Assert.Equal("Completed", json.RootElement.GetProperty("YaraScanStatus").GetString());
        var children = ChildRecords(records, run.Pid);
        Assert.Equal(2, children.Length);   // the probe and the scan
        Assert.All(children, c => Assert.Contains(Record(c).Modules, m => m.Name.Equals("yara_x_capi.dll", StringComparison.OrdinalIgnoreCase)));
    }

    // T6b: SILVERGUN_YARA_ENGINE=libyara is the explicit in-process fallback, and it is honoured as asked: in this plain
    // build libyara cannot run, so the scan reports Unavailable, and it does NOT quietly switch to YARA-X instead. No worker
    // child is started (the startup hook records every .NET process's PID: only the scan-package process is there), and
    // yara_x_capi.dll is loaded nowhere.
    [Fact]
    public void ScanPackage_WithLibYara_InAPlainBuild_IsUnavailable_AndNeverFallsBackToYaraX()
    {
        var records = Path.Combine(profile.Root, $"libyara-{Guid.NewGuid():N}");
        Directory.CreateDirectory(records);
        var pids = Path.Combine(records, "pids.txt");
        using var dir = new YaraXTempDir("verb-libyara");
        var nupkg = YaraXWorkerScannerProtocolTests.Nupkg(dir, "SilvergunExplicitLibYara");
        var env = ModuleRecording(Path.Combine(records, "{pid}.txt"));
        env["SILVERGUN_TEST_PID_OUT"] = pids;
        env["SILVERGUN_YARA_ENGINE"] = YaraXWorkerScanner.LibYaraEngineValue;

        var (run, json, log) = ScanPackageToFile(nupkg, records, env, dir.Root);

        Assert.Equal("Unavailable", json.GetProperty("YaraScanStatus").GetString());
        Assert.Equal(0, json.GetProperty("YaraFindings").GetArrayLength());
        Assert.Contains("scan-package: YARA malware-signature scanning did NOT run", run.Stderr, StringComparison.Ordinal);
        Assert.Contains("YARA scanning UNAVAILABLE for SilvergunExplicitLibYara", log, StringComparison.Ordinal);
        Assert.DoesNotContain("YARA-X", log, StringComparison.Ordinal);
        Assert.Equal(new[] { run.Pid }, PidRecords(pids).Select(p => p.Pid));   // no worker child, not even a probe
        Assert.Empty(ChildRecords(records, run.Pid));
        var (assemblies, modules) = Record(Path.Combine(records, $"{run.Pid}.txt"));
        Assert.Contains(assemblies, a => a.Name == "Silvergun.PackageAnalysis.NuGet");
        Assert.DoesNotContain(modules, m => m.Name.StartsWith("yara_x_capi", StringComparison.OrdinalIgnoreCase));
    }

    // T6b, ADR 0027 decision 4: the DEFAULT engine whose worker cannot run stays Unavailable; it never falls back to libyara.
    // A copy of the CLI WITHOUT yara_x_capi.dll is a CLI whose worker (itself, amendment (o)) answers `fatal`: the probe
    // fails, the scan reports Unavailable with the real cause in its log, the one worker started (the probe) is gone, and
    // neither engine's code ever reaches the scan-package process (no libyara.NET, no yara_x_capi.dll) or the worker.
    [Fact]
    public void ScanPackage_ByDefault_WithTheYaraXDllMissing_IsUnavailable_SaysWhy_AndNeverFallsBackToLibYara()
    {
        using var copy = YaraXWorkerScannerProcessTests.CopyOfTestOutputWithout(YaraXNative.LibraryFileName);
        var records = Path.Combine(profile.Root, $"nodll-{Guid.NewGuid():N}");
        Directory.CreateDirectory(records);
        var pids = Path.Combine(records, "pids.txt");
        using var dir = new YaraXTempDir("verb-nodll");
        var nupkg = YaraXWorkerScannerProtocolTests.Nupkg(dir, "SilvergunDefaultNoDll");
        var env = ModuleRecording(Path.Combine(records, "{pid}.txt"));
        env["SILVERGUN_TEST_PID_OUT"] = pids;

        var (run, json, log) = ScanPackageToFile(nupkg, records, env, dir.Root, cliExe: copy.Combine("Silvergun.CLI.exe"));

        Assert.Equal("Unavailable", json.GetProperty("YaraScanStatus").GetString());
        Assert.Equal(0, json.GetProperty("YaraFindings").GetArrayLength());
        Assert.Contains("scan-package: YARA malware-signature scanning did NOT run", run.Stderr, StringComparison.Ordinal);
        Assert.Contains("YARA-X worker scanning UNAVAILABLE: the worker reported a fatal error", log, StringComparison.Ordinal);
        Assert.Contains("yara_x_capi.dll is not in the application directory", log, StringComparison.Ordinal);
        Assert.Contains("YARA scanning UNAVAILABLE for SilvergunDefaultNoDll", log, StringComparison.Ordinal);
        // libyara never ran: whether its assembly fails to load in this build or loads and fails to initialise, its
        // failure is logged naming it, and neither may appear.
        Assert.DoesNotContain("in-process YARA engine", log, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("libyara", log, StringComparison.OrdinalIgnoreCase);

        var processes = PidRecords(pids);
        Assert.Equal(run.Pid, processes[0].Pid);
        var workers = processes.Skip(1).ToArray();
        Assert.Single(workers);   // the availability probe; with no engine there is no scan run
        Assert.All(workers, w => Assert.Equal(WorkerProcesses.CliName, w.Name));
        WorkerProcesses.AssertGone(workers.Select(w => w.Pid), WorkerProcesses.CliName);
        // The scan-package process's own record always exists; the worker's only when it exited before the parent, having
        // read its `fatal`, killed it (a killed process runs no exit handler), so it is checked when present.
        Assert.True(File.Exists(Path.Combine(records, $"{run.Pid}.txt")), "the scan-package process wrote no module record\n" + run.Stderr);
        foreach (var record in new[] { run.Pid }.Concat(workers.Select(w => w.Pid)).Select(p => Path.Combine(records, $"{p}.txt")).Where(File.Exists))
        {
            var (assemblies, modules) = Record(record);
            Assert.Contains(assemblies, a => a.Name == "Silvergun.PackageAnalysis.NuGet");
            Assert.DoesNotContain(assemblies, a => a.Name.StartsWith("libyara", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(modules, m => m.Name.StartsWith("yara_x_capi", StringComparison.OrdinalIgnoreCase) || m.Name.StartsWith("libyara", StringComparison.OrdinalIgnoreCase));
        }
    }

    // The polish round: the CLI advisory says WHY. A copy of the CLI without yara_x_capi.dll: the "did NOT run" line ends
    // with "Reason: " and the report's YaraUnavailableReason (the worker's fatal, through the backend's UnavailableReason),
    // on one line with no raw control character; the JSON report carries the same reason.
    [Fact]
    public void ScanPackage_WithTheYaraXDllMissing_TheAdvisorySaysWhy_OnOneEscapedLine()
    {
        using var copy = YaraXWorkerScannerProcessTests.CopyOfTestOutputWithout(YaraXNative.LibraryFileName);
        var records = Path.Combine(profile.Root, $"reason-{Guid.NewGuid():N}");
        Directory.CreateDirectory(records);
        using var dir = new YaraXTempDir("verb-reason");
        var nupkg = YaraXWorkerScannerProtocolTests.Nupkg(dir, "SilvergunReasonNoDll");

        var (run, json, _) = ScanPackageToFile(nupkg, records, new(), dir.Root, cliExe: copy.Combine("Silvergun.CLI.exe"));

        Assert.Equal("Unavailable", json.GetProperty("YaraScanStatus").GetString());
        var reason = json.GetProperty("YaraUnavailableReason").GetString()!;
        Assert.StartsWith("no working YARA backend: the worker reported a fatal error: ", reason, StringComparison.Ordinal);
        Assert.Contains("yara_x_capi.dll is not in the application directory", reason, StringComparison.Ordinal);
        Assert.True(reason.Length <= 512, $"the reason is {reason.Length} chars");
        var advisory = Assert.Single(run.Stderr.Split('\n'), l => l.StartsWith("scan-package: YARA malware-signature scanning did NOT run", StringComparison.Ordinal)).TrimEnd('\r');
        Assert.EndsWith(" Reason: " + reason, advisory, StringComparison.Ordinal);
        Assert.DoesNotContain(advisory, c => c < ' ' || c is >= (char)0x7F and <= (char)0x9F || c == (char)0x202E);
    }

    // ADR 0033 amendment of 2026-10-22: SILVERGUN_YARA_RULES_CACHE no longer exists. A real worker run with it set (to a
    // directory only the user controls, which the old code would have cached in) and a FRESH private profile: the worker
    // is ready, its rules cache is created in that profile's default location (so it is the default location, not one left
    // by an earlier run), nothing is created in the named directory, and nothing it writes to stderr mentions the variable
    // or warns about the rules cache.
    [Fact]
    [Trait("Category", "Slow")]   // a fresh profile: the real rules are compiled (~3 s measured)
    public void TheWorker_WithTheRemovedRulesCacheVariableSet_CachesInTheDefaultLocation_AndCreatesNothingThere()
    {
        using var fresh = new ControlledTempDir("verb-nooverride-profile");
        using var named = new ControlledTempDir("verb-nooverride");
        var env = new Dictionary<string, string?> { ["SILVERGUN_YARA_RULES_CACHE"] = named.Root };

        var run = Run(WorkerArgs, [], env, profileRoot: fresh.Root);

        Assert.Equal(0, run.Exit);
        Assert.Matches(ReadyPattern, Lines(run)[0]);
        var cache = Path.Combine(fresh.Root, "AppData", "Local", "Silvergun", "yara-x-rules");
        Assert.Single(Directory.GetFiles(cache, "rules-*.sgyx"));
        Assert.Empty(Directory.EnumerateFileSystemEntries(named.Root));
        Assert.DoesNotContain("SILVERGUN_YARA_RULES_CACHE", run.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain(run.Stderr.Split('\n'), l => l.Contains("WRN]", StringComparison.Ordinal) && l.Contains("rules cache", StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Methods: helpers
    private string AssertReadyErrorsThenFatal(WorkerRun run, int results, string reasonPrefix)
    {
        Assert.Equal(3, run.Exit);
        var lines = Lines(run);
        Assert.Equal(results + 2, lines.Length);
        Assert.Matches(ReadyPattern, lines[0]);
        for (var i = 0; i < results; i++)
            Assert.Equal($"{{\"type\":\"result\",\"index\":{i},\"status\":\"error\",\"reason\":\"invalid path form\"}}", lines[i + 1]);
        var reason = FatalReason(lines[^1]);
        Assert.StartsWith(reasonPrefix, reason, StringComparison.Ordinal);
        Assert.True(reason.Length <= 512);
        Assert.DoesNotContain("\"type\":\"done\"", run.Stdout, StringComparison.Ordinal);
        return reason;
    }

    private static void AssertNoCanary(WorkerOutcome outcome) =>
        Assert.DoesNotContain(outcome.Results.SelectMany(r => r.Rules), r => r.StartsWith(YaraXCanary.Prefix, StringComparison.OrdinalIgnoreCase));

    // An entry for the EMBEDDED rules' key in `target`'s private cache that holds another ruleset: compiled here, stored
    // through the real cache (so the directory is owner-only and the entry well-formed), then re-keyed and bound again with
    // DPAPI (format v3) exactly as Store binds one. The worker runs as this same user, so its DPAPI vouches for it.
    private static void PlantRuleset(Profile target, params string[] sources)
    {
        using var rules = YaraX.Compile(sources);
        var cache = new YaraXRulesCache(target.CacheDirectory);
        Assert.True(cache.Store(rules), "the planted ruleset could not be stored");
        var stored = cache.EntryPath(rules.SourcesSha256)!;
        var key = YaraXRules.SourcesSha256Of(YaraRuleResources.ReadAll());
        var entry = YaraXRulesCacheEntryV3.Rebound(File.ReadAllBytes(stored),
            body => Convert.FromHexString(key).CopyTo(body, YaraXRulesCacheEntryV3.SourcesOffset));
        YaraXRulesCacheEntryV3.AssertVouched(entry, key);
        File.WriteAllBytes(cache.EntryPath(key)!, entry);
        File.Delete(stored);
    }

    private static Dictionary<string, string?> ModuleRecording(string record) => new()
    {
        ["DOTNET_STARTUP_HOOKS"] = HookDll,
        ["SILVERGUN_TEST_LOADED_MODULES_OUT"] = record,
    };

    private static ((string Name, string Location)[] Assemblies, (string Name, string Path)[] Modules) Record(string record)
    {
        Assert.True(File.Exists(record), $"the startup hook wrote no record at '{record}'");
        var lines = File.ReadAllLines(record).Select(l => l.Split('|')).Where(p => p.Length == 3).ToArray();
        return (lines.Where(p => p[0] == "A").Select(p => (p[1], p[2])).ToArray(), lines.Where(p => p[0] == "M").Select(p => (p[1], p[2])).ToArray());
    }

    private static string[] Modules(string record) => Record(record).Modules.Select(m => m.Name).ToArray();

    // scan-package with the JSON report written to a file (`--output`), which makes the CLI log to the console instead of
    // to a file only, so the run's own log lines (its warnings: why YARA is unavailable) can be read from stdout/stderr.
    private (WorkerRun Run, JsonElement Report, string Log) ScanPackageToFile(string nupkg, string records, Dictionary<string, string?> env, string workingDirectory, string? cliExe = null)
    {
        var report = Path.Combine(records, "report.json");
        var run = Run(["scan-package", nupkg, "--json", "--output", report, "--no-vulns", "--no-resolve"], [], env, workingDirectory: workingDirectory, cliExe: cliExe);
        Assert.True(File.Exists(report), $"scan-package wrote no report (exit {run.Exit})\n{run.Stdout}\n{run.Stderr}");
        using var json = JsonDocument.Parse(File.ReadAllText(report));
        return (run, json.RootElement.Clone(), run.Stdout + "\n" + run.Stderr);
    }

    // The module records under `records` written by processes other than `pid` (its children).
    private static string[] ChildRecords(string records, int pid) =>
        Directory.GetFiles(records, "*.txt")
            .Where(f => int.TryParse(Path.GetFileNameWithoutExtension(f), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var p) && p != pid)
            .ToArray();

    // The startup hook's SILVERGUN_TEST_PID_OUT records, in start order: one `<pid>|<process name>` per .NET process.
    private static (int Pid, string Name)[] PidRecords(string path)
    {
        Assert.True(File.Exists(path), $"the startup hook wrote no PID record at '{path}'");
        return File.ReadAllLines(path).Where(l => l.Length > 0).Select(l => l.Split('|'))
            .Select(p => (int.Parse(p[0], System.Globalization.CultureInfo.InvariantCulture), p[1])).ToArray();
    }

    private static byte[] Requests(params string[] paths) =>
        Utf8(string.Concat(paths.Select((p, i) => $"{{\"index\":{i},\"path\":{JsonSerializer.Serialize(p)}}}\n")));

    private static string Request(int index) => $"{{\"index\":{index},\"path\":\"file-{index}.bin\"}}";

    private static byte[] Utf8(string text) => new UTF8Encoding(false).GetBytes(text);

    private static string FatalReason(string line)
    {
        using var doc = JsonDocument.Parse(line);
        Assert.Equal("fatal", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal(2, doc.RootElement.EnumerateObject().Count());
        return doc.RootElement.GetProperty("reason").GetString()!;
    }

    // Every line \n-terminated, BOM-free UTF-8, no \r.
    private static string[] Lines(WorkerRun run)
    {
        Assert.False(run.StdoutBytes is [0xEF, 0xBB, 0xBF, ..], "stdout starts with a BOM");
        Assert.True(run.StdoutBytes.Length > 0 && run.StdoutBytes[^1] == (byte)'\n', "stdout does not end with a newline: " + run.Stderr);
        var text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(run.StdoutBytes);
        Assert.DoesNotContain('\r', text);
        return text[..^1].Split('\n');
    }

    // The worker's stdout through the parent's own strict reader, flattened for assertions.
    private static WorkerOutcome Outcome(WorkerRun run, int requests)
    {
        var outcome = new Yara.Worker.WorkerResponseReader(new MemoryStream(run.StdoutBytes), requests).ReadToEnd();
        return new(outcome.IsComplete, outcome.Results.Select(r => new WorkerFile(
            r.Status.ToString().ToLowerInvariant(), r.Reason, (r.Hits ?? []).Select(h => h.Rule).ToArray())).ToArray());
    }

    private WorkerRun Run(IReadOnlyList<string> args, byte[] stdin, Dictionary<string, string?>? env = null, string? profileRoot = null, string? workingDirectory = null, string? cliExe = null)
    {
        cliExe ??= CliExe;
        Assert.True(File.Exists(cliExe), $"the net10.0-windows CLI apphost is not at '{cliExe}'.");
        var psi = new ProcessStartInfo(cliExe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = workingDirectory ?? profile.Root,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment["USERPROFILE"] = profileRoot ?? profile.Root;
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");
        psi.Environment.Remove("SILVERGUN_YARA_ENGINE");
        foreach (var (key, value) in env ?? [])
            if (value is null)
                psi.Environment.Remove(key);
            else
                psi.Environment[key] = value;

        using var process = Process.Start(psi)!;
        var stdout = new MemoryStream();
        var readOut = process.StandardOutput.BaseStream.CopyToAsync(stdout);
        var readErr = process.StandardError.ReadToEndAsync();
        var write = Task.Run(() =>
        {
            try
            {
                process.StandardInput.BaseStream.Write(stdin);
                process.StandardInput.BaseStream.Flush();
                process.StandardInput.Close();
            }
            catch (IOException) { /* the worker stopped reading (fatal) and exited: expected for oversized input */ }
        });

        if (!process.WaitForExit(120_000))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail("the CLI did not exit within 120 s and was killed");
        }
        process.WaitForExit();
        readOut.GetAwaiter().GetResult();
        write.GetAwaiter().GetResult();
        return new WorkerRun(process.ExitCode, stdout.ToArray(), readErr.GetAwaiter().GetResult(), process.Id);
    }
    #endregion

    #region Nested types
    /// <summary>A private USERPROFILE (so a private rules cache) for the CLI children of one test class.</summary>
    public sealed class Profile : IDisposable
    {
        public Profile()
        {
            dir = new YaraXTempDir("profile");
            Root = dir.Root;
        }

        public string Root { get; }

        public string CacheDirectory => Path.Combine(Root, "AppData", "Local", "Silvergun", "yara-x-rules");

        public void Dispose() => dir.Dispose();

        private readonly YaraXTempDir dir;
    }

    private sealed record WorkerRun(int Exit, byte[] StdoutBytes, string Stderr, int Pid)
    {
        public string Stdout => Encoding.UTF8.GetString(StdoutBytes);
    }

    private sealed record WorkerFile(string Status, string? Reason, string[] Rules);

    private sealed record WorkerOutcome(bool Done, WorkerFile[] Results);
    #endregion

    #region Fields
    private static readonly string[] WorkerArgs = ["__worker", "yara", "--protocol", "1"];

    private static readonly string CliExe = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.exe");

    private static readonly string HookDll = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.LoadedAssembliesHook.dll");

    private static readonly Regex ReadyPattern = new(
        "^\\{\"type\":\"ready\",\"protocol\":1,\"engine\":\"yara-x\",\"engineVersion\":\"1\\.22\\.0\",\"ruleCount\":(?<count>[0-9]+),\"rulesSha256\":\"(?<sha>[0-9a-f]{64})\",\"canary\":\"passed\",\"ruleSourceErrors\":0\\}$");

    // Every app-local assembly the windows worker loads (measured 2026-10-22): the CLI, its argument parser, the runtime and
    // its stderr logger, and the protocol and engine types (Silvergun.PackageAnalysis.NuGet; no analysis code runs).
    private static readonly string[] AllowedWorkerAssemblies =
    [
        "Silvergun.CLI", "System.CommandLine", "Silvergun.Runtime", "Silvergun.PackageAnalysis.NuGet",
        "Serilog", "Serilog.Sinks.Console", "Serilog.Extensions.Logging", "Microsoft.Extensions.Logging.Abstractions",
    ];
    #endregion
}
#endif
