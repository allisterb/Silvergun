#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;
using Xunit.Abstractions;

using static FakeWorkerScript;

/// <summary>
/// The parent backend, <c>YaraXWorkerScanner</c> (ADR 0033 task T4), hosted in a fresh child process (the YaraXProbe's
/// parent-host modes) for what the xunit host cannot observe or must not do:
/// <list type="bullet">
/// <item>the worker's stderr relayed at Debug, prefixed, escaped and capped at 64 KiB, without ever blocking the worker;</item>
/// <item>a parent that dies by <c>Environment.FailFast</c> mid-scan leaves no worker (the kill-on-close Job Object);</item>
/// <item>the PRODUCTION constructor end to end: the CLI apphost resolved by amendment (o), the real engine, the real rules,
/// real files named <c>NUL</c>, <c>CON</c>, <c>nul.txt</c> and <c>aux\...</c> scanned as files, with a private rules cache;</item>
/// <item><c>YaraScannerFactory</c>'s once-per-process choice from <c>SILVERGUN_YARA_ENGINE</c> (the YARA-X worker by default
/// since T6b, <c>libyara</c> only when asked for), and a default whose worker cannot run staying unavailable;</item>
/// <item>worker resolution under a <c>PATH</c> that does hold a <c>Silvergun.CLI.exe</c> (it must not be used).</item>
/// </list>
/// </summary>
public sealed class YaraXWorkerScannerProcessTests(ITestOutputHelper output)
{
    #region Methods: the stderr relay
    [Fact]
    public void TheWorkersStderr_IsRelayedAtDebug_PrefixedEscapedAndCappedAt64KiB()
    {
        var forged = "evil\n[ERR] forged" + (char)0x202E + "bidi" + (char)0x1B + "[31mred";
        using var script = new FakeWorkerScript("relay").GenuineProbe().Otherwise(
            "out " + Ready(), "err plain diagnostic", @"err evil\n[ERR] forged\u202Ebidi\e[31mred", "errflood 200000", "answer", "done").Save();
        using var tree = new ScanTree("relay");
        tree.Write("a.bin");

        var run = Probe([], "parent", FakeYaraBinary.ProbePath, script.ScriptPath, tree.Root, "30", "20000", "5000", "5000");

        Assert.Equal("True", run["available"]);
        Assert.Equal("complete", run["result"]);   // a stderr flood never blocks the worker or costs the scan
        var relayed = run.Logs.Where(l => l.Message.StartsWith("[yara-worker] ", StringComparison.Ordinal)).ToArray();
        Assert.All(relayed, l => Assert.Equal("Debug", l.Level));
        Assert.Contains(relayed, l => l.Message == "[yara-worker] plain diagnostic");
        Assert.Contains(relayed, l => l.Message == "[yara-worker] evil");
        Assert.Contains(relayed, l => l.Message == "[yara-worker] [ERR] forged\\u202ebidi\\x1b[31mred");
        Assert.All(relayed, l => Assert.DoesNotContain(l.Message, c => c < ' ' || c is (char)0x7F or (char)0x202E));

        var total = Encoding.UTF8.GetByteCount("plain diagnostic\n" + forged + "\n") + 200000;
        Assert.Contains(relayed, l => l.Message == $"[yara-worker] (stderr exceeded 65536 bytes; {total - 65536} more byte(s) discarded)");
        var floodLines = relayed.Count(l => l.Message.StartsWith("[yara-worker] eeee", StringComparison.Ordinal));
        var keptFlood = 65536 - Encoding.UTF8.GetByteCount("plain diagnostic\n" + forged + "\n");
        Assert.InRange(floodLines, keptFlood / 128, keptFlood / 128 + 1);   // exactly the first 64 KiB, no more
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: the Job Object outlives nothing
    // The parent fails fast mid-scan: no finally, no Dispose, no exit handler runs in it. The worker (hung, so it would
    // otherwise live forever) must die with it, because the OS closes the parent's job handle and the job is
    // kill-on-close.
    [Fact]
    public void AParentThatFailsFast_LeavesNoWorkerRunning()
    {
        using var script = new FakeWorkerScript("failfast").GenuineProbe().Otherwise("out " + Ready(), "answer 1", "hang").Save();
        using var tree = new ScanTree("failfast");
        tree.Write("a.bin");
        tree.Write("b.bin");

        var run = Probe([], "failfast", FakeYaraBinary.ProbePath, script.ScriptPath, tree.Root, script.PidFile);

        Assert.Equal("True", run["available"]);
        Assert.NotEqual(0, run.Exit);
        Assert.NotEqual(3, run.Exit);   // 3: the worker never started, so nothing was proven
        var worker = int.Parse(run["worker"]!);
        Assert.Equal(worker, script.Pids[1]);
        WorkerProcesses.AssertGone([worker], WorkerProcesses.FakeWorkerName, TimeSpan.FromSeconds(15));
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: the production constructor, end to end with the real worker
    // The YaraXProbe is not the CLI, so amendment (o) step 2 picks the CLI apphost in its application directory (the test
    // bin). The real worker compiles the real rules into a cache under a private USERPROFILE (never the user's), and real
    // files whose names a plain path would turn into devices are scanned as files: the synthetic HermeticWiper positive is
    // found in each, the benign file is clean, the canary is never a finding, and the scan completes.
    [Fact]
    [Trait("Category", "Slow")]
    public void TheProductionConstructor_RunsTheRealWorker_AndFindsThePositiveInDeviceNamedFiles()
    {
        using var profile = new YaraXTempDir("profile");
        using var tree = new ScanTree("production");
        string[] positives = ["nul.txt", "NUL", "CON", @"aux\inside.bin", @"foo.\inside.bin"];
        foreach (var name in positives)
            tree.Write(name, HermeticWiperSample.Bytes);
        tree.Write("benign.txt", Encoding.ASCII.GetBytes("nothing to see here"));
        var pids = profile.Combine("pids.txt");

        // The startup hook (inherited by the worker through the environment) records every .NET process's PID, so the
        // real workers, whose PIDs the parent does not expose, can be checked by PID afterwards.
        var run = Probe(new()
        {
            ["USERPROFILE"] = profile.Root,
            ["DOTNET_STARTUP_HOOKS"] = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.LoadedAssembliesHook.dll"),
            ["SILVERGUN_TEST_PID_OUT"] = pids,
        }, "production", tree.Root);

        Assert.Equal(Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.exe"), run["worker"], ignoreCase: true);
        Assert.Equal("True", run["available"]);
        Assert.True(run["result"] == "complete", $"the scan was {run["result"]}: {run.Message}");
        var hits = run.All("hit").Select(h => h.Split('|')).ToArray();
        Assert.Equal(positives.Select(p => Path.Combine(tree.Root, p)).Order(StringComparer.OrdinalIgnoreCase),
            hits.Where(h => h[1] == HermeticWiperSample.RuleName).Select(h => h[0]).Order(StringComparer.OrdinalIgnoreCase));
        Assert.DoesNotContain(hits, h => h[0].EndsWith("benign.txt", StringComparison.Ordinal));
        Assert.DoesNotContain(hits, h => h[1].StartsWith(YaraXCanary.Prefix, StringComparison.OrdinalIgnoreCase));
        Assert.True(Directory.Exists(Path.Combine(profile.Root, "AppData", "Local", "Silvergun", "yara-x-rules")),
            "the worker's rules cache was not under the private USERPROFILE");
        var workers = File.ReadAllLines(pids).Select(l => l.Split('|')).Where(p => p[1] == WorkerProcesses.CliName).Select(p => int.Parse(p[0])).ToArray();
        Assert.Equal(2, workers.Length);   // the probe run and the scan run
        WorkerProcesses.AssertGone(workers, WorkerProcesses.CliName);
    }
    #endregion

    #region Methods: the factory (SILVERGUN_YARA_ENGINE, read once per process)
    // T6b: the YARA-X worker is the default on this build (unset or empty), `yarax` names it, and `libyara` (any case) is
    // the one explicit way to the in-process engine. None of these is worth a warning.
    [Theory]
    [InlineData(null, "YaraXWorkerScanner")]
    [InlineData("", "YaraXWorkerScanner")]
    [InlineData("yarax", "YaraXWorkerScanner")]
    [InlineData("YaraX", "YaraXWorkerScanner")]
    [InlineData("YARAX", "YaraXWorkerScanner")]
    [InlineData("libyara", "LibYaraScanner")]
    [InlineData("LIBYARA", "LibYaraScanner")]
    [InlineData("LibYara", "LibYaraScanner")]
    public void Factory_SelectsTheBackend_WithoutAWarningForARecognisedOrEmptyValue(string? value, string expected)
    {
        var env = new Dictionary<string, string?> { ["SILVERGUN_YARA_ENGINE"] = value };

        var run = Probe(env, "factory");

        Assert.Equal(expected, run["type"]);
        Assert.DoesNotContain(run.Logs, l => l.Level == "Warning" && l.Message.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal));
    }

    // An unrecognised value is said out loud, once, escaped and bounded (it is environment text), and the default (the
    // YARA-X worker) is kept. The match is exact apart from case: no trimming, so a padded `libyara` is not libyara either.
    [Theory]
    [InlineData("yara-x")]
    [InlineData(" yarax")]
    [InlineData("libyara ")]
    [InlineData("lib-yara")]
    [InlineData("hostile")]
    public void Factory_AnUnrecognisedValue_WarnsOnceEscapedAndBounded_AndKeepsTheDefault(string value)
    {
        var raw = value == "hostile" ? "x\n[ERR] forged" + (char)0x202E + new string('z', 200) : value;

        var run = Probe(new() { ["SILVERGUN_YARA_ENGINE"] = raw }, "factory");

        Assert.Equal("YaraXWorkerScanner", run["type"]);
        var warning = Assert.Single(run.Logs, l => l.Level == "Warning" && l.Message.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal)).Message;
        Assert.Contains("is not recognised (the recognised values are 'yarax' and 'libyara'); using the default YARA backend.", warning, StringComparison.Ordinal);
        var quoted = warning[(warning.IndexOf('\'') + 1)..warning.IndexOf("' is not recognised", StringComparison.Ordinal)];
        Assert.True(quoted.Length <= 64, $"the value is quoted at {quoted.Length} chars");
        Assert.DoesNotContain(warning, c => c < ' ' || c == (char)0x202E);
        if (value == "hostile")
            Assert.StartsWith("x\\n[ERR] forged\\u202e", quoted, StringComparison.Ordinal);
        else
            Assert.Equal(value, quoted);
    }

    // The public names of the two recognised values, and the factory's own constants they must agree with.
    [Fact]
    public void TheEngineValues_AreYaraxAndLibyara_AndAgreeWithTheFactory()
    {
        Assert.Equal("SILVERGUN_YARA_ENGINE", YaraXWorkerScanner.EngineVar);
        Assert.Equal("yarax", YaraXWorkerScanner.EngineValue);
        Assert.Equal("libyara", YaraXWorkerScanner.LibYaraEngineValue);
        Assert.Equal(YaraScannerFactory.EngineVar, YaraXWorkerScanner.EngineVar);
        Assert.Equal(YaraScannerFactory.YaraXEngineValue, YaraXWorkerScanner.EngineValue);
        Assert.Equal(YaraScannerFactory.LibYaraEngineValue, YaraXWorkerScanner.LibYaraEngineValue);
    }

    // T6b, ADR 0027 decision 4: the DEFAULT backend with no worker it can run stays unavailable, says why, and never falls
    // back to libyara. The probe runs from a copy of this test output WITHOUT Silvergun.CLI.exe, so amendment (o) resolves
    // no worker (the probe is not the CLI, and its application directory holds no CLI apphost). The factory still picks the
    // worker backend, the package's YARA status is Unavailable with zero findings, the warning names the real cause, and
    // neither engine's code is ever loaded: no libyara.NET assembly, no yara_x_capi.dll, no libyara module.
    [Fact]
    public void TheDefaultBackend_WithNoWorkerExecutable_StaysUnavailable_SaysWhy_AndNeverFallsBackToLibYara()
    {
        using var copy = CopyOfTestOutputWithout("Silvergun.CLI.exe");
        using var profile = new YaraXTempDir("profile");
        using var dir = new YaraXTempDir("default-noworker");
        var nupkg = YaraXWorkerScannerProtocolTests.Nupkg(dir, "SilvergunDefaultNoWorker");

        var run = ProbeAt(Path.Combine(copy.Root, Path.GetFileName(ProbeExe)), new() { ["USERPROFILE"] = profile.Root }, "factory-scan", nupkg);

        Assert.Equal(0, run.Exit);
        Assert.Equal("YaraXWorkerScanner", run["type"]);
        Assert.Equal("False", run["available"]);
        Assert.Equal("Unavailable", run["status"]);
        Assert.Equal("0", run["findings"]);
        Assert.Equal("False", run["libyara"]);
        Assert.Empty(run.All("module"));
        var warnings = run.Logs.Where(l => l.Level == "Warning").Select(l => l.Message).ToArray();
        Assert.Contains(warnings, w => w.StartsWith("YARA-X worker scanning UNAVAILABLE: there is no worker executable", StringComparison.Ordinal));
        Assert.Contains(warnings, w => w.StartsWith("YARA scanning UNAVAILABLE for SilvergunDefaultNoWorker", StringComparison.Ordinal));
        Assert.DoesNotContain(run.Logs, l => l.Message.Contains("in-process YARA engine", StringComparison.OrdinalIgnoreCase)
            || l.Message.Contains("libyara", StringComparison.OrdinalIgnoreCase));   // a libyara load failure names it (red-proof 2)
        Assert.False(Directory.Exists(Path.Combine(profile.Root, "AppData", "Local", "Silvergun", "yara-x-rules")), "a rules cache was written although no worker could run");
    }
    #endregion

    #region Methods: SILVERGUN_YARA_RULES_CACHE is gone (ADR 0033 amendment of 2026-10-22)
    // The variable once moved the rules cache, and the parent's YaraXWorkerScanner(YaraOptions?) constructor validated it
    // and warned about an ignored value. Both are gone (user decision, option A). With it set, the constructor (reached
    // through the factory, in a fresh process) logs no warning at all and creates nothing in the named directory: set to
    // a directory only the user controls (which the old code would have used), or to a missing one (which it warned about).
    // The worker-engine layer is guarded in YaraXRulesCacheNoOverrideTests, the real worker in YaraWorkerVerbWindowsTests.
    [Theory]
    [InlineData("a directory only the user controls")]
    [InlineData("a missing directory")]
    public void TheParent_WithTheRemovedRulesCacheVariableSet_LogsNoWarning_AndCreatesNothing(string kind)
    {
        using var dir = new ControlledTempDir("no-override-parent");
        var value = kind == "a missing directory" ? dir.Combine("missing") : dir.Root;

        var run = Probe(new() { ["SILVERGUN_YARA_RULES_CACHE"] = value }, "factory");

        Assert.Equal(0, run.Exit);
        Assert.Equal("YaraXWorkerScanner", run["type"]);
        Assert.DoesNotContain(run.Logs, l => l.Level == "Warning");
        Assert.Empty(Directory.EnumerateFileSystemEntries(dir.Root));
    }
    #endregion

    #region Methods: resolution never consults PATH
    [Fact]
    public void Resolve_IgnoresAPathThatHoldsTheCliApphost()
    {
        using var onPath = new YaraXTempDir("on-path");
        File.WriteAllBytes(onPath.Combine("Silvergun.CLI.exe"), []);
        using var empty = new YaraXTempDir("no-cli");
        var env = new Dictionary<string, string?> { ["PATH"] = onPath.Root + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH") };

        foreach (var processPath in new[] { "Silvergun.CLI.exe", @"C:\Program Files\dotnet\testhost.exe", @"C:\Program Files\dotnet\dotnet.exe" })
        {
            var run = Probe(env, "resolve", processPath, empty.Root);

            Assert.Equal("<null>", run["path"]);
            Assert.StartsWith("there is no worker executable", run["problem"], StringComparison.Ordinal);
        }
    }
    #endregion

    #region Methods: helpers
    private ProbeRun Probe(Dictionary<string, string?> env, params string[] args) => ProbeAt(ProbeExe, env, args);

    // A copy of this test output (no .pdb) without the named files, as YaraXEngineTests copies it without the DLL.
    internal static YaraXTempDir CopyOfTestOutputWithout(params string[] omitted)
    {
        var copy = new YaraXTempDir("bincopy");
        foreach (var file in Directory.EnumerateFiles(AppContext.BaseDirectory, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(AppContext.BaseDirectory, file);
            if (omitted.Contains(relative, StringComparer.OrdinalIgnoreCase) || relative.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)
                || relative.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
                continue;
            Directory.CreateDirectory(Path.GetDirectoryName(copy.Combine(relative))!);
            File.Copy(file, copy.Combine(relative));
        }
        foreach (var name in omitted)
            Assert.False(File.Exists(copy.Combine(name)), $"the copy still holds {name}");
        return copy;
    }

    private ProbeRun ProbeAt(string exe, Dictionary<string, string?> env, params string[] args)
    {
        Assert.True(File.Exists(exe), $"the YARA-X probe was not found at '{exe}'.");
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(exe)!,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment.Remove("SILVERGUN_YARA_ENGINE");
        foreach (var (key, value) in env)
            if (value is null)
                psi.Environment.Remove(key);
            else
                psi.Environment[key] = value;

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(180_000))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail("the YARA-X probe did not exit within 180 s");
        }
        process.WaitForExit();
        var run = new ProbeRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
        output.WriteLine(run.Report);
        return run;
    }
    #endregion

    #region Nested types
    private sealed record ProbeRun(int Exit, string Stdout, string Stderr)
    {
        public string? this[string key] => All(key).FirstOrDefault();

        public string[] All(string key) =>
            Stdout.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.StartsWith(key + "=", StringComparison.Ordinal)).Select(l => l[(key.Length + 1)..]).ToArray();

        public (string Level, string Message)[] Logs =>
            All("log").Select(l => l.Split('|', 2)).Select(p => (p[0], Encoding.UTF8.GetString(Convert.FromBase64String(p[1])))).ToArray();

        public string Message => this["message"] is { } m ? Encoding.UTF8.GetString(Convert.FromBase64String(m)) : "";

        public string Report => $"exit={Exit}\nstdout:\n{(Stdout.Length > 20000 ? Stdout[..20000] + "..." : Stdout)}\nstderr:\n{Stderr}";
    }
    #endregion

    #region Fields
    private static readonly string ProbeExe = Path.Combine(AppContext.BaseDirectory, "Silvergun.PackageAnalysis.NuGet.Tests.YaraXProbe.exe");
    #endregion
}
#endif
