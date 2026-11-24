#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;
using Xunit.Abstractions;

using static LinuxYaraX;

/// <summary>
/// The hidden <c>__worker yara --protocol 1</c> verb of the REAL net10.0 CLI on Linux, against the pinned
/// <c>libyara_x_capi.so</c> and the real embedded rules (<c>docs/agent/tasks/yarax-worker-linux.md</c>, Phase 1; the
/// Windows twin is <c>YaraWorkerVerbWindowsTests</c>). The CLI apphost is NOT in this test output (that must hold none;
/// the Linux-only ProjectReference only builds the CLI): it is launched from the CLI's own output directory,
/// <c>src/Silvergun.CLI/bin/&lt;configuration&gt;/net10.0/</c> (<see cref="LinuxYaraX.CliDirectory"/>), with its
/// <c>libyara_x_capi.so</c> beside it. There is no rules cache on Linux in Phase 1 (L6), so every run compiles.
///
/// <para>The positive is <see cref="HermeticWiperSample"/>: inert bytes derived at run time from the embedded rule.</para>
/// </summary>
public sealed class YaraWorkerVerbLinuxTests(ITestOutputHelper output)
{
    #region Methods: ready
    // G1 on Linux: the parent's own hash of its embedded rules, a real rule count, the canary passed, no source in error.
    // The rules were compiled (no cache on Linux, L6), and the per-file timeout is the product default.
    [LinuxYaraXFact]
    public void Ready_IsGenuine_WithTheCanaryPassed_AndNoSourceErrors()
    {
        var run = Run(WorkerArgs, []);

        Assert.Equal(0, run.Exit);
        var lines = Lines(run);
        Assert.Equal(2, lines.Length);
        var ready = ReadyPattern.Match(lines[0]);
        Assert.True(ready.Success, $"the ready line is not the genuine shape: {lines[0]}\n{run.Stderr}");
        Assert.Equal(YaraXRules.SourcesSha256Of(YaraRuleResources.ReadAll()), ready.Groups["sha"].Value);
        Assert.Equal(YaraXWorkerScanner.ExpectedRulesSha256, ready.Groups["sha"].Value);
        Assert.True(int.Parse(ready.Groups["count"].Value) > 300, $"only {ready.Groups["count"].Value} rules");
        Assert.Equal("{\"type\":\"done\",\"count\":0}", lines[1]);
        Assert.Contains(" rules (compiled)", run.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("from the rules cache", run.Stderr, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: files
    [LinuxYaraXFact]
    public void ThePositiveControl_IsScanned_AndHits()
    {
        using var tree = new LinuxScanTree("verb-linux-positive");
        var positive = tree.Write("positive.bin", HermeticWiperSample.Bytes);

        var run = Run(WorkerArgs, Requests(positive));

        Assert.Equal(0, run.Exit);
        var outcome = Outcome(run, 1);
        Assert.True(outcome.Done, run.Stdout + run.Stderr);
        Assert.Equal("scanned", outcome.Results[0].Status);
        Assert.Contains(HermeticWiperSample.RuleName, outcome.Results[0].Rules);
        AssertNoCanary(outcome.Results[0].Rules);
    }

    // Benign content is scanned (a genuine result, not skipped or an error) and matches nothing; so does an empty file.
    [LinuxYaraXFact]
    public void ABenignFile_IsScannedClean()
    {
        using var tree = new LinuxScanTree("verb-linux-benign");
        var text = tree.Write("readme.txt", Encoding.UTF8.GetBytes("Hello from a perfectly ordinary package.\n"));
        var empty = tree.Write("empty.bin", []);

        var run = Run(WorkerArgs, Requests(text, empty));

        Assert.Equal(0, run.Exit);
        var outcome = Outcome(run, 2);
        Assert.True(outcome.Done, run.Stdout + run.Stderr);
        Assert.All(outcome.Results, r => Assert.Equal(("scanned", 0), (r.Status, r.Rules.Length)));
    }

    // L3: a backslash is a file-name character on Linux, never a separator. A file NAMED `dir\positive.bin` (there is no
    // directory `dir`) is opened exactly as named and scanned; treating `\` as a separator would open a missing file.
    [LinuxYaraXFact]
    public void ABackslashInAFileName_IsOpenedAsNamed_AndScanned()
    {
        using var tree = new LinuxScanTree("verb-linux-backslash");
        var named = tree.Write(@"dir\positive.bin", HermeticWiperSample.Bytes);
        Assert.False(Directory.Exists(Path.Combine(tree.Root, "dir")));

        var run = Run(WorkerArgs, Requests(named));

        var outcome = Outcome(run, 1);
        Assert.True(outcome.Done, run.Stdout + run.Stderr);
        Assert.Equal("scanned", outcome.Results[0].Status);
        Assert.Contains(HermeticWiperSample.RuleName, outcome.Results[0].Rules);
    }

    // G2, worker side, on Linux: every path out of the form is refused by the worker too, even when it names a real file
    // (each case below resolves to the positive), so the refusal is the form's, never a failed open.
    [LinuxYaraXTheory]
    [InlineData("relative")]
    [InlineData("a dot segment")]
    [InlineData("a dot-dot segment")]
    [InlineData("an empty segment")]
    [InlineData("a trailing slash")]
    [InlineData("a Windows drive path")]
    public void ARequestPathOutOfForm_IsAnError_InvalidPathForm(string what)
    {
        using var tree = new LinuxScanTree("verb-linux-form");
        tree.Write("positive.bin", HermeticWiperSample.Bytes);
        var path = what switch
        {
            "relative" => "positive.bin",
            "a dot segment" => tree.Root + "/./positive.bin",
            "a dot-dot segment" => tree.Root + "/../root/positive.bin",
            "an empty segment" => tree.Root + "//positive.bin",
            "a trailing slash" => tree.Root + "/",
            "a Windows drive path" => @"C:\positive.bin",
            _ => throw new ArgumentOutOfRangeException(nameof(what)),
        };

        var run = Run(WorkerArgs, Requests(path), workingDirectory: tree.Root);

        var outcome = Outcome(run, 1);
        Assert.True(outcome.Done, run.Stdout + run.Stderr);
        Assert.Equal(("error", "invalid path form"), (outcome.Results[0].Status, outcome.Results[0].Reason));
    }

    [LinuxYaraXFact]
    public void AMissingFile_IsAnError_AndTheNextFileIsStillScanned()
    {
        using var tree = new LinuxScanTree("verb-linux-missing");
        var next = tree.Write("next.bin", HermeticWiperSample.Bytes);

        var run = Run(WorkerArgs, Requests(Path.Combine(tree.Root, "not-there.bin"), next));

        var outcome = Outcome(run, 2);
        Assert.True(outcome.Done, run.Stdout);
        Assert.Equal("error", outcome.Results[0].Status);
        Assert.StartsWith("could not open the file: FileNotFoundException", outcome.Results[0].Reason, StringComparison.Ordinal);
        Assert.Equal("scanned", outcome.Results[1].Status);
        Assert.Contains(HermeticWiperSample.RuleName, outcome.Results[1].Rules);
    }
    #endregion

    #region Methods: containment (L4)
    // The parent dies, the worker does not linger: a helper shell starts a real worker (its stdin is a pipe THIS test
    // holds open, so the worker is blocked reading requests and has no other reason to exit), the worker reports ready,
    // and the shell is SIGKILLed. WorkerParentWatch sees the parent pid change and exits the worker within ~2 s (a 1 s
    // poll), saying why on stderr, which this test still holds.
    [LinuxYaraXFact]
    [Trait("Category", "Slow")]
    public void WhenTheParentIsKilled_TheWorkerExits_WithinAboutTwoSeconds()
    {
        // The worker's stdin is the shell's (fd 3), not the /dev/null an asynchronous list would otherwise get.
        var psi = new ProcessStartInfo("/bin/sh")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            ArgumentList = { "-c", "exec 3<&0; \"$0\" __worker yara --protocol 1 <&3 3<&- & echo \"pid $!\"; wait", CliPath },
        };
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");

        using var shell = Process.Start(psi)!;
        var stderr = shell.StandardError.ReadToEndAsync();
        int? worker = null;
        try
        {
            string? ready = null;
            var readLines = Task.Run(() =>
            {
                for (string? line; ready is null && (line = shell.StandardOutput.ReadLine()) is not null;)
                    if (line.StartsWith("pid ", StringComparison.Ordinal))
                        worker = int.Parse(line[4..], System.Globalization.CultureInfo.InvariantCulture);
                    else if (line.StartsWith("{\"type\":\"ready\"", StringComparison.Ordinal))
                        ready = line;
            });
            Assert.True(readLines.Wait(TimeSpan.FromSeconds(60)), "the worker sent no ready within 60 s");
            Assert.NotNull(worker);
            Assert.Matches(ReadyPattern, ready!);
            Assert.Equal(shell.Id, Stat(worker.Value)!.Value.ParentPid);

            // Control: a worker whose parent lives stays blocked on its open stdin.
            Thread.Sleep(1500);
            Assert.True(IsAlive(worker.Value, WorkerComm), "the worker exited while its parent was alive");

            shell.Kill();
            var clock = Stopwatch.StartNew();
            while (IsAlive(worker.Value, WorkerComm) && clock.Elapsed < TimeSpan.FromSeconds(10))
                Thread.Sleep(25);
            clock.Stop();
            output.WriteLine($"the orphaned worker was gone {clock.Elapsed.TotalMilliseconds:0} ms after its parent was killed");

            Assert.False(IsAlive(worker.Value, WorkerComm), "the orphaned worker is still running 10 s after its parent was killed");
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(3), $"the orphaned worker took {clock.Elapsed} to exit (expected ~2 s)");
            Assert.True(stderr.Wait(TimeSpan.FromSeconds(10)), "stderr did not close after the worker exited");
            Assert.Contains($"the parent process (pid {shell.Id}) is gone; exiting.", stderr.Result, StringComparison.Ordinal);
        }
        finally
        {
            if (worker is { } pid && IsAlive(pid, WorkerComm))
                try { Process.GetProcessById(pid).Kill(); } catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { }
            try { shell.Kill(); } catch (InvalidOperationException) { }
        }
    }
    #endregion

    #region Methods: what loads where (ADR 0033 decision 5; the Linux twins of YaraWorkerVerbWindowsTests' pins)
    // The worker DOES map libyara_x_capi.so (that is its job), from its own application directory; it still loads none of
    // the analysis code: the app-local assemblies are exactly the verb's.
    [LinuxYaraXFact]
    public void WorkerMode_MapsTheYaraXLibraryFromTheAppDirectory_AndLoadsNoAnalysisCode()
    {
        using var tree = new LinuxScanTree("verb-linux-modules");
        var record = Path.Combine(tree.Base, "modules.txt");
        var file = tree.Write("a.bin", [1, 2, 3]);

        var run = Run(WorkerArgs, Requests(file), env: ModuleRecording(record));

        Assert.Equal(0, run.Exit);
        var (assemblies, modules) = Record(record);
        Assert.Contains(assemblies, a => a.Name == "Silvergun.CLI");   // the hook really observed the worker
        Assert.Contains(modules, m => m.Path == Path.Combine(CliDirectory!, "libyara_x_capi.so"));
        var appLocal = assemblies.Where(a => a.Location.StartsWith(CliDirectory!, StringComparison.Ordinal)).Select(a => a.Name).ToArray();
        Assert.NotEmpty(appLocal);
        Assert.Empty(appLocal.Except(AllowedWorkerAssemblies, StringComparer.Ordinal));
        Assert.DoesNotContain(assemblies, a => a.Name is "Silvergun.CodeAnalysis.IL" or "Silvergun.Intel" or "libyara.NET" or "Spectre.Console" or "Serilog.Sinks.File"
            || a.Name.StartsWith("NuGet.", StringComparison.Ordinal) || a.Name.Contains("Cci", StringComparison.OrdinalIgnoreCase));
    }

    // A NORMAL CLI run never maps libyara_x_capi.so in its own process. By default (Phase 1: no worker on Linux) and with
    // --no-yara under SILVERGUN_YARA_ENGINE=yarax, no YARA scan runs and no worker is started at all. With yarax and a scan,
    // the scan really runs on the worker (Completed), and only the worker children (the probe and the scan) map it.
    [LinuxYaraXTheory]
    [InlineData(null, false)]
    [InlineData("yarax", false)]
    [InlineData("yarax", true)]
    public void ScanPackage_NeverMapsTheYaraXLibrary_InItsOwnProcess(string? engine, bool scansWithYara)
    {
        using var tree = new LinuxScanTree("verb-linux-scan");
        var records = Path.Combine(tree.Base, "records");
        Directory.CreateDirectory(records);
        var pids = Path.Combine(records, "pids.txt");
        var nupkg = Path.Combine(tree.Base, "SilvergunNeverMapsYaraX.nupkg");
        NupkgBuilder.WriteNupkg(nupkg,
        [
            ("SilvergunNeverMapsYaraX.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml("SilvergunNeverMapsYaraX", "1.0.0", "Silvergun Tests", "worker test package", "net8.0", []))),
            ("content/a.bin", [1, 2, 3]),
        ]);
        var env = ModuleRecording(Path.Combine(records, "{pid}.txt"));
        env["SILVERGUN_TEST_PID_OUT"] = pids;
        env["SILVERGUN_YARA_ENGINE"] = engine;
        string[] args = ["scan-package", nupkg, "--json", "--no-vulns", "--no-resolve", .. (engine is not null && !scansWithYara ? new[] { "--no-yara" } : [])];

        var run = Run(args, [], tree.Base, env);

        var own = Path.Combine(records, $"{run.Pid}.txt");
        Assert.True(File.Exists(own), $"the scan-package process wrote no module record (exit {run.Exit})\n{run.Stderr}");
        var (assemblies, modules) = Record(own);
        Assert.Contains(assemblies, a => a.Name == "Silvergun.PackageAnalysis.NuGet");   // the scan path really ran in it
        Assert.NotEmpty(modules);   // the hook does see native modules here
        Assert.DoesNotContain(modules, m => m.Name.Contains("yara_x_capi", StringComparison.Ordinal));
        var children = File.ReadAllLines(pids).Where(l => l.Length > 0).Select(l => int.Parse(l.Split('|')[0], System.Globalization.CultureInfo.InvariantCulture))
            .Where(p => p != run.Pid).ToArray();
        if (scansWithYara)
        {
            using var json = System.Text.Json.JsonDocument.Parse(run.Stdout);
            Assert.Equal("Completed", json.RootElement.GetProperty("YaraScanStatus").GetString());
            Assert.Equal(2, children.Length);   // the probe and the scan
            Assert.All(children, c => Assert.Contains(Record(Path.Combine(records, $"{c}.txt")).Modules, m => m.Name == "libyara_x_capi.so"));
        }
        else
        {
            Assert.Empty(children);   // no worker, not even a probe
        }
    }
    #endregion

    #region Methods: helpers
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
    #endregion

    #region Fields
    private static readonly string HookDll = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.LoadedAssembliesHook.dll");

    // Every app-local assembly the Linux worker may load: the CLI, its argument parser, the runtime and its stderr logger,
    // and the protocol and engine types (Silvergun.PackageAnalysis.NuGet; no analysis code runs). The Windows list.
    private static readonly string[] AllowedWorkerAssemblies =
    [
        "Silvergun.CLI", "System.CommandLine", "Silvergun.Runtime", "Silvergun.PackageAnalysis.NuGet",
        "Serilog", "Serilog.Sinks.Console", "Serilog.Extensions.Logging", "Microsoft.Extensions.Logging.Abstractions",
    ];

    private static readonly Regex ReadyPattern = new(
        "^\\{\"type\":\"ready\",\"protocol\":1,\"engine\":\"yara-x\",\"engineVersion\":\"1\\.22\\.0\",\"ruleCount\":(?<count>[0-9]+),\"rulesSha256\":\"(?<sha>[0-9a-f]{64})\",\"canary\":\"passed\",\"ruleSourceErrors\":0\\}$");
    #endregion
}
#endif
