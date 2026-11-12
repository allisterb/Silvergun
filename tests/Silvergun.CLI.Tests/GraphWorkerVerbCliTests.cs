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
/// The hidden <c>__worker graph --protocol 2</c> verb of the real CLI as THIS project builds it, <b>net10.0</b>
/// (<c>docs/agent/tasks/graph-worker.md</c> G2, G5): the cross-platform build the corpus harness launches. An empty
/// session is <c>ready</c> and <c>done</c> byte for byte, and every command line that does not parse is one graph-protocol
/// <c>fatal</c> on stdout and exit 3 (never help text). The real analysis through this verb is pinned in
/// <c>Silvergun.PackageAnalysis.NuGet.Tests</c> (<c>GraphWorkerCliTests</c>).
/// </summary>
public sealed class GraphWorkerVerbCliTests
{
    #region Methods
    /// <summary>A request with no folders, stdin held open as the parent holds it: <c>ready</c>, <c>done</c>, exit 0.</summary>
    [Fact]
    public void Worker_AnEmptyRequest_IsReadyAndDone_AndExitZero()
    {
        var run = Run(WorkerArgs, Utf8("{\"protocol\":2,\"budget\":{\"maxNodes\":10,\"maxEdges\":10,\"maxDispatchWork\":10},\"folders\":[]}\n"), closeStdin: false);

        Assert.Equal(0, run.Exit);
        Assert.Equal(Utf8("{\"type\":\"ready\",\"protocol\":2,\"folders\":0}\n{\"type\":\"done\",\"count\":0}\n"), run.StdoutBytes);
    }

    /// <summary>
    /// Protocol v2 (<c>ssa-facts-s4.md</c> §4): a request with valid <c>ssa</c> bounds and no folders is the same
    /// <c>ready</c> and <c>done</c>; one with a bound that is not positive is refused with one <c>fatal</c> and exit 3.
    /// </summary>
    [Theory]
    [InlineData(1, 0, "{\"type\":\"ready\",\"protocol\":2,\"folders\":0}\n{\"type\":\"done\",\"count\":0}\n")]
    [InlineData(0, 3, "{\"type\":\"fatal\",\"reason\":\"the request is out of contract: an SSA fact bound is not positive\"}\n")]
    public void Worker_ARequestWithSsaBounds_IsServedOrRefused_ByItsBounds(int maxSites, int exit, string stdout)
    {
        var ssa = $"{{\"maxSites\":{maxSites},\"maxArguments\":8,\"maxAlternatives\":4,\"maxPhiDepth\":16,\"maxPhiInputs\":1024,\"maxTextChars\":256,"
            + "\"maxFactTextChars\":1000000,\"maxLiftedMethods\":50000,\"folderTimeMilliseconds\":60000,\"maxCandidates\":64}";

        var run = Run(WorkerArgs, Utf8("{\"protocol\":2,\"budget\":{\"maxNodes\":10,\"maxEdges\":10,\"maxDispatchWork\":10},\"folders\":[],\"ssa\":" + ssa + "}\n"), closeStdin: false);

        Assert.Equal(exit, run.Exit);
        Assert.Equal(Utf8(stdout), run.StdoutBytes);
    }

    [Fact]
    public void Worker_NoRequest_IsOneFatal_AndExitThree()
    {
        var run = Run(WorkerArgs, [], closeStdin: true);

        Assert.Equal(3, run.Exit);
        Assert.Equal(Utf8("{\"type\":\"fatal\",\"reason\":\"no request line (Eof)\"}\n"), run.StdoutBytes);
    }

    public static TheoryData<string, string[], string> CommandLinesThatDoNotParse() => new()
    {
        { "--help", ["__worker", "graph", "--help"], ParseError },
        { "-? after valid arguments", ["__worker", "graph", "--protocol", "2", "-?"], ParseError },
        { "a repeated --protocol", ["__worker", "graph", "--protocol", "2", "--protocol", "2"], ParseError },
        { "the yara worker's --timeout", ["__worker", "graph", "--protocol", "2", "--timeout", "5"], ParseError },
        { "an unknown token", ["__worker", "graph", "--protocol", "2", "extra"], ParseError },
        { "--protocol without its value", ["__worker", "graph", "--protocol"], ParseError },
        { "protocol 1 (v1, retired)", ["__worker", "graph", "--protocol", "1"], "^unsupported protocol '1'; this build speaks 2$" },
        { "no protocol", ["__worker", "graph"], "^missing --protocol; this build speaks 2$" },
    };

    [Theory]
    [MemberData(nameof(CommandLinesThatDoNotParse))]
    public void Worker_ACommandLineThatDoesNotParse_IsOneGraphFatal_AndExitThree(string what, string[] args, string reason)
    {
        var run = Run(args, Utf8("{\"protocol\":2}\n"), closeStdin: true);

        Assert.True(run.Exit == 3, $"{what}: exit {run.Exit}");
        Assert.Equal(1, run.StdoutBytes.Count(b => b == (byte)'\n'));
        using var doc = JsonDocument.Parse(run.StdoutBytes);
        Assert.Equal("fatal", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal(2, doc.RootElement.EnumerateObject().Count());
        Assert.Matches(reason, doc.RootElement.GetProperty("reason").GetString()!);
        Assert.DoesNotContain("Usage", run.Stdout, StringComparison.Ordinal);
    }

    // One child run. With closeStdin false, stdin stays open until stdout ends (the parent's posture: closing it is the
    // "parent gone" signal, exit 4).
    private static WorkerRun Run(IReadOnlyList<string> args, byte[] stdin, bool closeStdin)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");

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
                if (closeStdin)
                    process.StandardInput.Close();
            }
            catch (IOException) { /* the worker stopped reading (fatal) and exited */ }
        });

        if (!process.WaitForExit(TimeoutMs))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail($"the worker did not exit within {TimeoutMs} ms and was killed");
        }
        process.WaitForExit();
        readOut.GetAwaiter().GetResult();
        write.GetAwaiter().GetResult();
        if (!closeStdin)
            try { process.StandardInput.Close(); } catch (IOException) { }
        return new WorkerRun(process.ExitCode, stdout.ToArray(), readErr.GetAwaiter().GetResult());
    }

    private static byte[] Utf8(string text) => new UTF8Encoding(false).GetBytes(text);
    #endregion

    #region Nested types
    private sealed record WorkerRun(int Exit, byte[] StdoutBytes, string Stderr)
    {
        public string Stdout => Encoding.UTF8.GetString(StdoutBytes);
    }
    #endregion

    #region Fields
    private const string ParseError = @"^the worker's arguments (did not parse \([0-9]+ error\(s\)\)|asked for something other than a worker session); expected __worker graph --protocol 2$";

    private const int TimeoutMs = 60_000;

    private static readonly string[] WorkerArgs = ["__worker", "graph", "--protocol", "2"];

    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");
    #endregion
}
