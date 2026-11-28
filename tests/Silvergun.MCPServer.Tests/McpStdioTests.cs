namespace Silvergun.MCPServer.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

/// <summary>
/// Task S0 and D9, observed on the raw process: the CLI apphost started with redirected stdin/stdout/stderr, a hand-written
/// newline-delimited JSON-RPC session (<see cref="McpScript"/>), then stdin closed. Each test has its own child and temp
/// directories; <see cref="McpChildProcess"/> bounds every wait and kills the child on dispose.
/// </summary>
public sealed class McpStdioTests
{
    #region Methods
    [Fact]
    public async Task EveryStdoutLine_IsAJsonRpcMessage()
    {
        using var dirs = new TestDirs();
        using var child = McpChildProcess.Start(McpCli.Args(dirs, "--debug"), dirs.Root);

        await McpScript.RunAsync(child);
        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        McpAssert.StdoutIsJsonRpcOnly(child, 4, exit.Stderr);
    }

    [Fact]
    public async Task ClosingStdin_ExitsZeroWithin5Seconds()
    {
        using var dirs = new TestDirs();
        using var child = McpChildProcess.Start(McpCli.Args(dirs), dirs.Root);
        await McpScript.RunAsync(child);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"did not exit within {McpCli.Timeout} of stdin closing\n{exit.Stderr}");
        Assert.True(exit.Elapsed <= TimeSpan.FromSeconds(5), $"exited {exit.Elapsed.TotalMilliseconds:F0} ms after stdin closed (limit 5 s, D4a)");
        Assert.True(exit.ExitCode == 0, $"exit code {exit.ExitCode}\n{exit.Stderr}");
    }

    [Fact]
    public async Task DebugLog_ReachesStderrAndFile_ButNeverToolResults()
    {
        using var dirs = new TestDirs();
        using var child = McpChildProcess.Start(McpCli.Args(dirs, "--debug"), dirs.Root);
        var instanceId = McpScript.InstanceId(await McpScript.RunAsync(child));

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        Assert.Matches("^[0-9a-f]{16}$", instanceId);

        var logFile = Assert.Single(Directory.GetFiles(dirs.Logs, "Silvergun-MCP*.log"));
        Assert.Matches(@"^Silvergun-MCP\d{8}(_\d{3})?\.log$", Path.GetFileName(logFile));
        var log = McpAssert.SingleLogFile(dirs.Logs);
        Assert.False(string.IsNullOrWhiteSpace(log), "the file log is empty");
        Assert.False(string.IsNullOrWhiteSpace(exit.Stderr), "stderr is empty");
        Assert.True(HasDebugLine(log), $"no debug-level line in the file log under --debug:\n{log}");
        Assert.True(HasDebugLine(exit.Stderr), $"no debug-level line on stderr under --debug:\n{exit.Stderr}");

        // A JSON-RPC body in either sink would carry the tool result, and with it the instance id (S0 acceptance).
        Assert.DoesNotContain(instanceId, log);
        Assert.DoesNotContain(instanceId, exit.Stderr);
        Assert.DoesNotContain("\"jsonrpc\"", log);
        Assert.DoesNotContain("\"jsonrpc\"", exit.Stderr);
    }

    /// <summary>The control for the test above: without <c>--debug</c> the same session logs nothing below Information.</summary>
    [Fact]
    public async Task WithoutDebug_LogHasNoDebugLines()
    {
        using var dirs = new TestDirs();
        using var child = McpChildProcess.Start(McpCli.Args(dirs), dirs.Root);
        await McpScript.RunAsync(child);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        var log = McpAssert.SingleLogFile(dirs.Logs);
        Assert.False(string.IsNullOrWhiteSpace(log), "the file log is empty");
        Assert.False(HasDebugLine(log), $"a debug-level line without --debug:\n{log}");
        Assert.False(HasDebugLine(exit.Stderr), $"a debug-level line on stderr without --debug:\n{exit.Stderr}");
    }

    /// <summary>Every log record in the shared file names the process that wrote it, so several servers can share one directory.</summary>
    [Fact]
    public async Task LogFile_EveryRecordNamesTheChildsPid()
    {
        using var dirs = new TestDirs();
        using var child = McpChildProcess.Start(McpCli.Args(dirs, "--debug"), dirs.Root);
        var pid = child.Id;
        await McpScript.RunAsync(child);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        var records = McpAssert.SingleLogFile(dirs.Logs).Split('\n').Select(l => l.TrimEnd((char)13)).Where(l => recordStart.IsMatch(l)).ToArray();
        Assert.True(records.Length >= 3, $"only {records.Length} log records");
        Assert.All(records, r => Assert.Matches(@"^\S+ \S+ \S+ \[[A-Z]{3}\] \(" + pid + @"\) ", r));
    }

    /// <summary>
    /// D9 "log shape, not content": text the agent chooses (client info, a method name, a tool name, a resource URI), each
    /// carrying a newline and a forged record, never forges a line in either sink, and no raw bidi control lands in either.
    /// Without <c>--debug</c> none of it appears at all; with it, it appears only escaped.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SdkLog_AgentChosenText_NeverReachesLogsRaw(bool debug)
    {
        using var dirs = new TestDirs();
        using var child = McpChildProcess.Start(debug ? McpCli.Args(dirs, "--debug") : McpCli.Args(dirs), dirs.Root);
        var nl = ((char)10).ToString();
        var rlo = (char)0x202E;

        child.Send(Message(1, "initialize", new JsonObject
        {
            ["protocolVersion"] = "2025-11-25",
            ["capabilities"] = new JsonObject(),
            ["clientInfo"] = new JsonObject { ["name"] = "c" + nl + "[ERR] FORGED-CLIENT" + rlo, ["version"] = "0" + rlo }
        }));
        await child.WaitForResponseAsync(1);
        child.Send(new JsonObject { ["jsonrpc"] = "2.0", ["method"] = "notifications/initialized" }.ToJsonString());
        child.Send(Message(2, "bogus/method" + nl + "[ERR] FORGED-METHOD" + rlo, null));
        child.Send(Message(3, "tools/call", new JsonObject { ["name"] = "nosuch" + nl + "[ERR] FORGED-TOOL" + rlo, ["arguments"] = new JsonObject() }));
        child.Send(Message(4, "resources/read", new JsonObject { ["uri"] = "silvergun://guide" + nl + "[ERR] FORGED-URI" + rlo }));
        foreach (var id in new[] { 2, 3, 4 })
            await child.WaitForResponseAsync(id);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        var log = McpAssert.SingleLogFile(dirs.Logs);
        Assert.False(string.IsNullOrWhiteSpace(log), "the file log is empty");
        foreach (var (sink, text) in new[] { ("file log", log), ("stderr", exit.Stderr) })
        {
            var forged = text.Split('\n').Where(l => l.TrimStart().StartsWith("[ERR] FORGED", StringComparison.Ordinal)).ToArray();
            Assert.True(forged.Length == 0, $"{sink}: forged line(s): {string.Join(" | ", forged)}");
            Assert.False(text.Contains(rlo), $"{sink}: a raw U+202E");
            if (!debug)
                Assert.False(text.Contains("FORGED", StringComparison.Ordinal), $"{sink}: agent text without --debug:\n{text}");
        }
        // The positive side, so the checks above are not vacuous. Without --debug, the allow-listed protocol names still
        // render verbatim end to end (so redaction is the allow-list, not a blanket drop); under --debug the agent's text
        // does reach the log, escaped.
        if (!debug)
            Assert.True(log.Contains("'tools/call'", StringComparison.Ordinal) || log.Contains("'initialize'", StringComparison.Ordinal),
                $"file log: no verbatim 'tools/call' or 'initialize' without --debug:\n{log}");
        if (debug)
            foreach (var marker in new[] { "FORGED-METHOD", "FORGED-TOOL", "FORGED-URI" })
                Assert.True(log.Contains(Backslash + "n[ERR] " + marker, StringComparison.Ordinal), $"file log: no escaped {marker} under --debug:\n{log}");
    }

    /// <summary>An unusable log directory is refused before logging starts: the file log is the record (D9).</summary>
    [Theory]
    [InlineData("an existing file")]
    [InlineData("a path under a file")]
    public async Task UnwritableLogDir_ExitsOneWithNothingOnStdout(string what)
    {
        using var dirs = new TestDirs();
        var file = Path.Combine(dirs.Base, "not-a-dir");
        File.WriteAllText(file, "x");
        var logDir = what == "an existing file" ? file : Path.Combine(file, "logs");
        using var child = McpChildProcess.Start(["mcp", "--root", dirs.Root, "--cache-dir", dirs.Cache, "--log-dir", logDir, "--no-network"], dirs.Root);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"--log-dir {what}: did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        Assert.True(exit.ExitCode == 1, $"--log-dir {what}: exit {exit.ExitCode}\n{exit.Stderr}");
        Assert.True(child.RawStdout.Length == 0, $"--log-dir {what}: {child.RawStdout.Length} bytes on stdout");
        Assert.Contains("--log-dir", exit.Stderr);
    }

    /// <summary>
    /// <c>mcp</c> reached through a response file (<c>Silvergun.CLI @file</c>, the first argument is not <c>mcp</c>) gets the
    /// same stdout discipline: a full session writes only JSON-RPC and exits 0.
    /// </summary>
    [Fact]
    public async Task ResponseFile_McpSession_KeepsStdoutJsonRpcOnly()
    {
        using var dirs = new TestDirs();
        var rsp = WriteResponseFile(dirs, McpCli.Args(dirs, "--debug"));
        using var child = McpChildProcess.Start(["@" + rsp], dirs.Root);

        await McpScript.RunAsync(child);
        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        Assert.True(exit.ExitCode == 0, $"exit {exit.ExitCode}\n{exit.Stderr}");
        McpAssert.StdoutIsJsonRpcOnly(child, 4, exit.Stderr);
    }

    [Fact]
    public async Task ResponseFile_McpHelp_WritesNothingToStdout()
    {
        using var dirs = new TestDirs();
        var rsp = WriteResponseFile(dirs, ["mcp", "--help"]);
        using var child = McpChildProcess.Start(["@" + rsp], dirs.Root);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        Assert.True(child.RawStdout.Length == 0, $"{child.RawStdout.Length} bytes on stdout: {Encoding.UTF8.GetString(child.RawStdout)}");
        Assert.True(exit.ExitCode == 0, $"exit {exit.ExitCode}\n{exit.Stderr}");
        Assert.False(string.IsNullOrWhiteSpace(exit.Stderr), "no help on stderr");
    }
    #endregion

    #region Methods: helpers
    // Serilog's level tag, in both the file and the stderr templates.
    private static bool HasDebugLine(string log) => log.Contains("[DBG]", StringComparison.Ordinal) || log.Contains("[VRB]", StringComparison.Ordinal);

    private static string Message(int id, string method, JsonObject? parameters)
    {
        var message = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = method };
        if (parameters is not null)
            message["params"] = parameters;
        return message.ToJsonString();   // escapes the newline and the bidi char: the server decodes them
    }

    // One token per line.
    private static string WriteResponseFile(TestDirs dirs, string[] tokens)
    {
        var path = Path.Combine(dirs.Base, "args.rsp");
        File.WriteAllText(path, string.Join((char)10, tokens) + (char)10, new UTF8Encoding(false));
        return path;
    }
    #endregion

    #region Fields
    private const string Backslash = @"\";

    // A log record's first line starts with its timestamp; anything else is a continuation (an exception's lines).
    private static readonly Regex recordStart = new(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} ", RegexOptions.CultureInvariant);
    #endregion
}

/// <summary>
/// D9's parser layer: help, version and parse errors of the <c>mcp</c> verb, and its own argument checks, write nothing to
/// stdout. Each case gets the isolated directories too, so a case that wrongly starts the server pollutes nothing; stdin is
/// closed at once, so such a server would exit 0 and fail the exit-code check.
/// </summary>
public sealed class McpParserOutputTests
{
    #region Methods
    public static TheoryData<string, string[], bool> Cases() => new()
    {
        { "--help", ["--help"], true },
        { "--version", ["--version"], false },
        { "--bogus", ["--bogus"], false },
        { "--max-jobs 9", ["--max-jobs", "9"], false },
        { "--root <nonexistent>", ["--root", NonexistentMarker], false },
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ParserOutput_NeverReachesStdout(string what, string[] extra, bool succeeds)
    {
        using var dirs = new TestDirs();
        var args = extra.Select(a => a == NonexistentMarker ? Path.Combine(dirs.Base, "no-such-root") : a).ToArray();
        using var child = McpChildProcess.Start(["mcp", .. args, "--cache-dir", dirs.Cache, "--log-dir", dirs.Logs, "--no-network"], dirs.Root);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"mcp {what}: did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        var stdout = child.RawStdout;
        Assert.True(stdout.Length == 0, $"mcp {what}: {stdout.Length} bytes on stdout: {Encoding.UTF8.GetString(stdout)}");
        Assert.False(string.IsNullOrWhiteSpace(exit.Stderr), $"mcp {what}: nothing on stderr");
        if (succeeds)
            Assert.True(exit.ExitCode == 0, $"mcp {what}: exit {exit.ExitCode}\n{exit.Stderr}");
        else
            Assert.True(exit.ExitCode != 0, $"mcp {what}: exit 0\n{exit.Stderr}");
    }
    #endregion

    #region Fields
    private const string NonexistentMarker = "<nonexistent>";
    #endregion
}
