namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using Xunit;

/// <summary>
/// The hidden <c>__worker yara --protocol 1</c> verb of the real CLI as THIS project builds it: <b>net10.0</b> (ADR 0033
/// FINAL FORM; worker protocol v1 in <c>docs/agent/tasks/yarax-worker.md</c>), driven as a child process exactly as a parent
/// would drive it: argument array, redirected stdin/stdout/stderr, requests written on their own task.
///
/// <para><b>Amendment (m).</b> On Windows the YARA-X engine is in the net10.0-windows TFM only, so the net10.0 CLI this
/// project builds answers every valid invocation there with exactly one <c>fatal</c> "engine unavailable on this platform"
/// and exit 3 (T3: never the T1 stub); those tests are <see cref="NoYaraXEngineFactAttribute"/>. On Linux the net10.0 CLI
/// HAS the engine (<c>docs/agent/tasks/yarax-worker-linux.md</c>), so they are a visible skip there. The argument checks
/// still come first and are pinned here on every OS. The real-engine verb tests launch the CLI from
/// <c>Silvergun.PackageAnalysis.NuGet.Tests</c>: the net10.0-windows CLI (<c>YaraWorkerVerbWindowsTests</c>) and, on Linux,
/// the net10.0 CLI (<c>YaraWorkerVerbLinuxTests</c>).</para>
///
/// <para>Records are pinned <b>byte for byte</b> (no BOM, <c>\n</c> only, one record per line), because the parent's reader is
/// strict. Worker mode must load no analysis code (ADR 0033 decision 5), observed from outside the process with a startup
/// hook (<c>Silvergun.CLI.Tests.LoadedAssembliesHook</c>) that lists the child's loaded assemblies and native modules at
/// exit.</para>
/// </summary>
public sealed class YaraWorkerVerbCliTests
{
    #region Methods: help
    [Fact]
    public void Help_DoesNotListTheHiddenWorkerVerb()
    {
        var run = Run(["--help"], []);

        Assert.Equal(0, run.Exit);
        Assert.Contains("scan-package", run.Stdout, StringComparison.Ordinal);   // the listing really was printed
        Assert.DoesNotContain("__worker", run.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("__worker", run.Stderr, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: this build has no engine
    // Formerly the T1 stub's ready/skipped/done, byte for byte. This build has no YARA-X engine, so whatever stdin holds,
    // stdout is exactly one fatal record and the exit code is 3: no ready (a parent must never see an engine here), no
    // result, no done.
    [NoYaraXEngineTheory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(20)]
    public void Worker_OnThisBuild_SendsOnlyFatalEngineUnavailable_AndExitsThree(int requests)
    {
        var stdin = string.Concat(Enumerable.Range(0, requests).Select(i => Request(i) + "\n"));

        var run = Run(WorkerArgs, Utf8(stdin));

        Assert.Equal(3, run.Exit);
        Assert.Equal(Utf8(EngineUnavailable + "\n"), run.StdoutBytes);
    }

    // The same with a valid --timeout: the timeout is accepted (checked first), then the engine is unavailable.
    [NoYaraXEngineTheory]
    [InlineData("2")]
    [InlineData("30")]
    [InlineData("3600")]
    public void Worker_WithAValidTimeout_GetsPastTheArgumentChecks_ToEngineUnavailable(string timeout)
    {
        var run = Run([.. WorkerArgs, "--timeout", timeout], Utf8(Request(0) + "\n"));

        Assert.Equal(3, run.Exit);
        Assert.Equal(Utf8(EngineUnavailable + "\n"), run.StdoutBytes);
    }

    // Malformed stdin cannot change that: the request stream is never read on this build.
    [NoYaraXEngineFact]
    public void Worker_OnThisBuild_IgnoresEvenAMalformedRequestStream()
    {
        var run = Run(WorkerArgs, Utf8("{\"index\":0,\"path\":\"a.bin\",\"extra\":1}\n" + new string('x', 70_000)));

        Assert.Equal(3, run.Exit);
        Assert.Equal(Utf8(EngineUnavailable + "\n"), run.StdoutBytes);
    }

    // stdout carries protocol records only (ADR 0033 decision 5): the fatal is logged, and the log goes to stderr.
    [NoYaraXEngineFact]
    public void Worker_LogsToStderrOnly_NeverToStdout()
    {
        var run = Run(WorkerArgs, []);

        Assert.Contains("[ERR] yara worker: fatal: engine unavailable on this platform", run.Stderr, StringComparison.Ordinal);
        Assert.All(Lines(run), line => Assert.StartsWith("{\"type\":", line, StringComparison.Ordinal));
    }

    // W2: worker mode replaces Console.Out with TextWriter.Null, so nothing written through Console.Out (here by the
    // startup hook, at process exit, after the verb has finished) ever reaches stdout.
    [NoYaraXEngineFact]
    public void Worker_AConsoleOutWrite_NeverReachesStdout()
    {
        var run = Run(WorkerArgs, [], new Dictionary<string, string>
        {
            ["DOTNET_STARTUP_HOOKS"] = HookDll,
            ["SILVERGUN_TEST_CONSOLE_OUT_AT_EXIT"] = "LEAKED-THROUGH-CONSOLE-OUT\n",
        });

        Assert.Equal(3, run.Exit);
        Assert.Equal(Utf8(EngineUnavailable + "\n"), run.StdoutBytes);
    }

    // The control for the test above: the hook's exit write DOES reach stdout in a normal run, so its absence in worker
    // mode is W2's doing, not the hook's.
    [Fact]
    public void Control_TheHooksConsoleOutWrite_ReachesStdoutOutsideWorkerMode()
    {
        var run = Run(["--help"], [], new Dictionary<string, string>
        {
            ["DOTNET_STARTUP_HOOKS"] = HookDll,
            ["SILVERGUN_TEST_CONSOLE_OUT_AT_EXIT"] = "LEAKED-THROUGH-CONSOLE-OUT\n",
        });

        Assert.Contains("LEAKED-THROUGH-CONSOLE-OUT", run.Stdout, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: fatal + exit 3 for bad arguments (checked before any engine)
    [Fact]
    public void Worker_WithProtocol2_SendsOnlyFatal_AndExitsThree()
    {
        var run = Run(["__worker", "yara", "--protocol", "2"], Utf8(Request(0) + "\n"));

        Assert.Equal(3, run.Exit);
        var fatal = Assert.Single(Lines(run));
        Assert.Equal("unsupported protocol '2'; this build speaks 1", FatalReason(fatal));
    }

    [Fact]
    public void Worker_WithoutAProtocol_SendsOnlyFatal_AndExitsThree()
    {
        var run = Run(["__worker", "yara"], []);

        Assert.Equal(3, run.Exit);
        var fatal = Assert.Single(Lines(run));
        Assert.Equal("missing --protocol; this build speaks 1", FatalReason(fatal));
    }

    // A protocol value that tries to forge a second record (a newline and a done line) and to hide itself (a bidi
    // override, a BEL): it is escaped and bounded inside the fatal reason, so stdout is still exactly one line.
    [Fact]
    public void Worker_WithAHostileProtocolValue_EscapesItInTheFatalReason()
    {
        var hostile = "1\n{\"type\":\"done\",\"count\":0}" + (char)0x202E + (char)0x07 + new string('x', 100);

        var run = Run(["__worker", "yara", "--protocol", hostile], []);

        Assert.Equal(3, run.Exit);
        Assert.Equal(1, run.StdoutBytes.Count(b => b == (byte)'\n'));
        var reason = FatalReason(Assert.Single(Lines(run)));
        Assert.StartsWith("unsupported protocol '1\\n{", reason, StringComparison.Ordinal);
        Assert.True(reason.Length <= 512, $"reason is {reason.Length} chars");
        Assert.DoesNotContain(new string('x', 40), reason, StringComparison.Ordinal);   // the value itself is cut short
        AssertNoRawControlOrBidi(reason);
        AssertNoRawControlOrBidi(run.Stderr.Replace("\r", "").Replace("\n", ""));
    }

    // G3, (k), W-D: --timeout is whole seconds in [2, 3600]. Anything else (out of range, signed, padded, not a number, a
    // bare `--timeout` with no value, an overflow) is a protocol fatal and exit 3, before any engine would load.
    [Theory]
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("3601")]
    [InlineData("-1")]
    [InlineData("abc")]
    [InlineData("+5")]
    [InlineData(" 5")]
    [InlineData("99999999999")]
    [InlineData("2.5")]
    public void Worker_WithAnInvalidTimeout_SendsOnlyFatal_AndExitsThree(string timeout)
    {
        var run = Run([.. WorkerArgs, "--timeout", timeout], Utf8(Request(0) + "\n"));

        Assert.Equal(3, run.Exit);
        Assert.Equal($"invalid --timeout '{timeout}'; expected whole seconds from 2 to 3600", FatalReason(Assert.Single(Lines(run))));
    }

    [Fact]
    public void Worker_WithABareTimeoutOption_SendsOnlyFatal_AndExitsThree()
    {
        var run = Run([.. WorkerArgs, "--timeout"], []);

        Assert.Equal(3, run.Exit);
        Assert.Equal("invalid --timeout ''; expected whole seconds from 2 to 3600", FatalReason(Assert.Single(Lines(run))));
    }

    [Fact]
    public void Worker_WithAHostileTimeoutValue_EscapesAndBoundsIt()
    {
        var run = Run([.. WorkerArgs, "--timeout", "5\n{\"type\":\"done\",\"count\":0}" + (char)0x202E + new string('9', 200)], []);

        Assert.Equal(3, run.Exit);
        var reason = FatalReason(Assert.Single(Lines(run)));
        Assert.StartsWith("invalid --timeout '5\\n{", reason, StringComparison.Ordinal);
        Assert.DoesNotContain(new string('9', 40), reason, StringComparison.Ordinal);
        AssertNoRawControlOrBidi(reason);
    }
    #endregion

    #region Methods: a worker command line that does not parse (FR2.3)
    // (what, the arguments). Before FR2, System.CommandLine answered these with help (or its error) on STDOUT and exit 1,
    // which a parent's strict reader would meet where a protocol record belongs. Now anything under `__worker` that does
    // not resolve to the yara worker's own action is exactly one `fatal` record on stdout and exit 3.
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
        var run = Run(args, Utf8(Request(0) + "\n"));

        Assert.True(run.Exit == 3, $"{what}: exit {run.Exit}");
        var reason = FatalReason(Assert.Single(Lines(run)));
        Assert.Matches(@"^the worker's arguments (did not parse \([0-9]+ error\(s\)\)|asked for something other than a worker session); expected __worker yara --protocol 1 \[--timeout <seconds>\]$", reason);
        Assert.DoesNotContain("Usage", run.Stdout, StringComparison.Ordinal);
        Assert.Contains("[ERR] yara worker: fatal: the worker's arguments", run.Stderr, StringComparison.Ordinal);
    }

    // The parser's own messages quote the offending token, so the fatal reason is fixed text: a hostile unknown token (a
    // forged record after a newline, a bidi override) reaches neither stdout nor the log.
    [Fact]
    public void Worker_AHostileUnknownToken_IsNotEchoed()
    {
        const string forged = "{\"type\":\"done\",\"count\":0}";
        var run = Run(["__worker", "yara", "--protocol", "1", "--x\n" + forged + (char)0x202E], []);

        Assert.Equal(3, run.Exit);
        Assert.Equal(1, run.StdoutBytes.Count(b => b == (byte)'\n'));
        FatalReason(Assert.Single(Lines(run)));
        Assert.DoesNotContain("done", run.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("done", run.Stderr, StringComparison.Ordinal);
        AssertNoRawControlOrBidi(run.Stderr.Replace("\r", "").Replace("\n", ""));
    }

    // Outside worker mode nothing changed: root --help prints help on stdout and exits 0 (and still hides __worker, see
    // Help_DoesNotListTheHiddenWorkerVerb); a parse error in a normal verb, or at the root, prints its error on stderr
    // and help on stdout, and exits 1.
    public static TheoryData<string[]> NormalModeParseErrors() => new()
    {
        { ["scan-package", "x.nupkg", "--bogus"] },
        { ["analyze", "x.dll", "--timeout", "5"] },   // --timeout is only the worker's
        { ["--bogus"] },
    };

    [Theory]
    [MemberData(nameof(NormalModeParseErrors))]
    public void NormalMode_AParseError_StillPrintsHelpToStdout_AndExitsOne(string[] args)
    {
        var run = Run(args, []);

        Assert.Equal(1, run.Exit);
        Assert.Contains("Usage:", run.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("\"type\":\"fatal\"", run.Stdout, StringComparison.Ordinal);
        Assert.Contains("Unrecognized command or argument", run.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("yara worker", run.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    public void NormalMode_RootHelp_StillPrintsHelpToStdout_AndExitsZero()
    {
        var run = Run(["--help"], []);

        Assert.Equal(0, run.Exit);
        Assert.Contains("Usage:", run.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("\"type\":\"fatal\"", run.Stdout, StringComparison.Ordinal);
        Assert.Empty(run.Stderr);
    }
    #endregion

    #region Methods: worker mode loads no analysis code
    // ADR 0033 decision 5 / T1: "It must not touch libyara.NET, CCI, NuGet or OSV code paths", and on this build there is
    // no YARA-X engine to load either. The allow-list is every app-local assembly the worker needs; anything else from the
    // CLI's own directory loading in worker mode is a regression (a static initialiser or a type reference in the verb's
    // path pulling analysis code in). The explicit deny-list repeats the ones the ADR names, for a readable red.
    [NoYaraXEngineFact]
    public void Worker_LoadsOnlyTheRuntimeLoggingAndProtocolAssemblies_AndNoEngine()
    {
        var record = Path.Combine(Path.GetTempPath(), $"silvergun-yara-worker-modules-{Guid.NewGuid():N}.txt");
        try
        {
            var run = Run(WorkerArgs, Utf8(Request(0) + "\n" + Request(1) + "\n"), new Dictionary<string, string>
            {
                ["DOTNET_STARTUP_HOOKS"] = HookDll,
                ["SILVERGUN_TEST_LOADED_MODULES_OUT"] = record,
            });

            Assert.Equal(3, run.Exit);
            Assert.True(File.Exists(record), "the startup hook wrote no record; is DOTNET_STARTUP_HOOKS honoured by the CLI?\n" + run.Stderr);
            var lines = File.ReadAllLines(record).Select(l => l.Split('|')).Where(p => p.Length == 3).ToArray();
            var assemblies = lines.Where(p => p[0] == "A").Select(p => (Name: p[1], Location: p[2])).ToArray();
            var modules = lines.Where(p => p[0] == "M").Select(p => p[1]).ToArray();

            Assert.Contains(assemblies, a => a.Name == "Silvergun.CLI");   // the hook really observed the worker
            var appLocal = assemblies
                .Where(a => a.Location.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase))
                .Select(a => a.Name)
                .Where(n => n != "Silvergun.CLI.Tests.LoadedAssembliesHook")
                .ToArray();
            Assert.Empty(appLocal.Except(AllowedWorkerAssemblies, StringComparer.Ordinal));

            string[] denied = ["Silvergun.CodeAnalysis.IL", "Silvergun.Intel", "libyara.NET", "Spectre.Console", "Serilog.Sinks.File"];
            Assert.DoesNotContain(assemblies, a => denied.Contains(a.Name, StringComparer.Ordinal)
                || a.Name.StartsWith("NuGet.", StringComparison.Ordinal)
                || a.Name.Contains("Cci", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(modules, m => m.StartsWith("yara_x_capi", StringComparison.OrdinalIgnoreCase)
                || m.StartsWith("libyara", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            File.Delete(record);
        }
    }

    // Worker-mode logging has no file sink: no log file named for the worker appears next to the CLI or in the working
    // directory. (The assembly test above also pins that Serilog's file sink never loads.)
    [Fact]
    public void Worker_CreatesNoLogFile()
    {
        var cwd = Path.Combine(Path.GetTempPath(), $"silvergun-yara-worker-cwd-{Guid.NewGuid():N}");
        Directory.CreateDirectory(cwd);
        try
        {
            var run = Run(["__worker", "yara", "--protocol", "2"], [], workingDirectory: cwd);

            Assert.Equal(3, run.Exit);
            Assert.NotEmpty(run.Stderr);   // it did log
            Assert.Empty(Directory.EnumerateFileSystemEntries(cwd));
            Assert.DoesNotContain(Directory.EnumerateFiles(AppContext.BaseDirectory, "*worker*", SearchOption.TopDirectoryOnly),
                f => f.EndsWith(".log", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(cwd, recursive: true);
        }
    }
    #endregion

    #region Methods: helpers
    private static string FatalReason(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        Assert.Equal("fatal", root.GetProperty("type").GetString());
        Assert.Equal(2, root.EnumerateObject().Count());
        return root.GetProperty("reason").GetString()!;
    }

    // Every line must be \n-terminated, BOM-free UTF-8; the last byte is always the final record's \n.
    private static string[] Lines(WorkerRun run)
    {
        Assert.False(run.StdoutBytes.Length >= 3 && run.StdoutBytes[0] == 0xEF && run.StdoutBytes[1] == 0xBB && run.StdoutBytes[2] == 0xBF, "stdout starts with a BOM");
        Assert.True(run.StdoutBytes.Length > 0 && run.StdoutBytes[^1] == (byte)'\n', "stdout does not end with a newline");
        var text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(run.StdoutBytes);
        Assert.DoesNotContain('\r', text);
        return text[..^1].Split('\n');
    }

    private static void AssertNoRawControlOrBidi(string text)
    {
        var offender = text.FirstOrDefault(c => c < ' ' || c is >= (char)0x7F and <= (char)0x9F or >= (char)0x202A and <= (char)0x202E or >= (char)0x2066 and <= (char)0x2069);
        Assert.True(offender == '\0', $"raw control or bidi character U+{(int)offender:X4} in '{text}'");
    }

    private static byte[] Utf8(string text) => new UTF8Encoding(false).GetBytes(text);

    private static string Request(int index) => $"{{\"index\":{index},\"path\":\"file-{index}.bin\"}}";

    // One child run. stdin is written on its own task and closed (amendment (a): a parent that writes and reads on one
    // thread can deadlock on full pipes); a worker that stops reading early makes that write fail, which is expected.
    private static WorkerRun Run(IReadOnlyList<string> args, byte[] stdin, IReadOnlyDictionary<string, string>? env = null, string? workingDirectory = null)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = workingDirectory ?? AppContext.BaseDirectory,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");
        foreach (var (key, value) in env ?? new Dictionary<string, string>())
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
            catch (IOException) { /* the worker stopped reading (fatal) and exited: expected */ }
        });

        if (!process.WaitForExit(TimeoutMs))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail($"the worker did not exit within {TimeoutMs} ms and was killed");
        }
        process.WaitForExit();
        readOut.GetAwaiter().GetResult();
        write.GetAwaiter().GetResult();
        return new WorkerRun(process.ExitCode, stdout.ToArray(), readErr.GetAwaiter().GetResult());
    }
    #endregion

    #region Nested types
    private sealed record WorkerRun(int Exit, byte[] StdoutBytes, string Stderr)
    {
        public string Stdout => Encoding.UTF8.GetString(StdoutBytes);
    }
    #endregion

    #region Fields
    // The one record this build's worker ever sends for a valid invocation where it has no engine
    // (UnavailableYaraWorkerEngine.Reason). The writer's encoder writes the text as is: it holds no character it escapes.
    private const string EngineUnavailable =
        "{\"type\":\"fatal\",\"reason\":\"engine unavailable on this platform: the YARA-X worker engine runs on Windows and Linux only\"}";

    private const int TimeoutMs = 60_000;

    private static readonly string[] WorkerArgs = ["__worker", "yara", "--protocol", "1"];

    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    private static readonly string HookDll = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.LoadedAssembliesHook.dll");

    // Every app-local assembly this build's worker loads: the CLI, its argument parser, the runtime and its stderr logger,
    // and the protocol types (which live in Silvergun.PackageAnalysis.NuGet; loading the assembly runs none of its analysis).
    private static readonly string[] AllowedWorkerAssemblies =
    [
        "Silvergun.CLI", "System.CommandLine", "Silvergun.Runtime", "Silvergun.PackageAnalysis.NuGet",
        "Serilog", "Serilog.Sinks.Console", "Serilog.Extensions.Logging", "Microsoft.Extensions.Logging.Abstractions",
    ];
    #endregion
}

/// <summary>
/// A <see cref="FactAttribute"/> for the net10.0 CLI's no-engine behaviour, which holds everywhere but Linux: there the
/// net10.0 worker runs the YARA-X engine (<c>docs/agent/tasks/yarax-worker-linux.md</c>), so it is a visible skip.
/// </summary>
public sealed class NoYaraXEngineFactAttribute : FactAttribute
{
    #region Constructors
    public NoYaraXEngineFactAttribute() => Skip = NoYaraXEngine.SkipReason;
    #endregion
}

/// <summary>The <see cref="TheoryAttribute"/> twin of <see cref="NoYaraXEngineFactAttribute"/>.</summary>
public sealed class NoYaraXEngineTheoryAttribute : TheoryAttribute
{
    #region Constructors
    public NoYaraXEngineTheoryAttribute() => Skip = NoYaraXEngine.SkipReason;
    #endregion
}

internal static class NoYaraXEngine
{
    #region Properties
    internal static string? SkipReason => OperatingSystem.IsLinux()
        ? "On Linux the net10.0 CLI's __worker yara runs the YARA-X engine (docs/agent/tasks/yarax-worker-linux.md); its "
          + "real-engine verb tests are YaraWorkerVerbLinuxTests in Silvergun.PackageAnalysis.NuGet.Tests."
        : null;
    #endregion
}
