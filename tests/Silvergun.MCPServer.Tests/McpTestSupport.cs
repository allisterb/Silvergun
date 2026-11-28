namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

/// <summary>
/// The platform file name of a <c>dotnet build</c> apphost (replicated from <c>Silvergun.CLI.Tests</c>, which this project
/// does not reference): <c>.exe</c> only on Windows.
/// </summary>
internal static class ApphostPath
{
    #region Methods
    public static string Resolve(string baseDirectory, string assemblyName) =>
        Path.Combine(baseDirectory, OperatingSystem.IsWindows() ? $"{assemblyName}.exe" : assemblyName);
    #endregion
}

/// <summary>The CLI apphost copied into this test output by the project reference, and the shared child-process limits.</summary>
internal static class McpCli
{
    #region Methods
    /// <summary>
    /// <c>mcp</c> with this run's isolated root, cache and log directories and <c>--no-network</c> (the network is on by
    /// default since S5, and no test may reach a real host), then <paramref name="extra"/>.
    /// </summary>
    public static string[] Args(TestDirs dirs, params string[] extra) =>
        ["mcp", "--root", dirs.Root, "--cache-dir", dirs.Cache, "--log-dir", dirs.Logs, "--no-network", .. extra];
    #endregion

    #region Fields
    public static readonly string Exe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    /// <summary>The bound on every wait for a child: generous for a cold start on a slow machine.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    #endregion
}

/// <summary>A fresh temp root, cache and log directory for one child process; deleted on dispose.</summary>
internal sealed class TestDirs : IDisposable
{
    #region Constructors
    public TestDirs()
    {
        var id = Guid.NewGuid().ToString("N");
        Base = Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", id);
        Root = Directory.CreateDirectory(Path.Combine(Base, "sg-root-" + id[..8])).FullName;
        Cache = Directory.CreateDirectory(Path.Combine(Base, "cache")).FullName;
        Logs = Directory.CreateDirectory(Path.Combine(Base, "logs")).FullName;
    }
    #endregion

    #region Properties
    public string Base { get; }

    public string Root { get; }

    public string Cache { get; }

    public string Logs { get; }
    #endregion

    #region Methods
    /// <summary>Another existing directory under <see cref="Base"/>, for a second root.</summary>
    public string NewDir(string name) => Directory.CreateDirectory(Path.Combine(Base, name)).FullName;

    public void Dispose()
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                if (Directory.Exists(Base))
                    Directory.Delete(Base, recursive: true);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                System.Threading.Thread.Sleep(200);   // a just-exited child may still hold the log file for a moment
            }
        }
    }
    #endregion
}

/// <summary>
/// The CLI started directly with redirected stdin/stdout/stderr, speaking newline-delimited JSON-RPC by hand. stdout is
/// captured as raw bytes (so "0 bytes" and "every line" are exact) and split on <c>\n</c>. Killed on dispose if still alive.
/// </summary>
internal sealed class McpChildProcess : IDisposable
{
    #region Constructors
    private McpChildProcess(Process process)
    {
        this.process = process;
        stdoutPump = Task.Run(PumpStdoutAsync);
        stderrRead = process.StandardError.ReadToEndAsync();
    }
    #endregion

    #region Properties
    /// <summary>Complete stdout lines so far (without the <c>\n</c>), decoded as UTF-8.</summary>
    public IReadOnlyList<string> Lines
    {
        get { lock (gate) return [.. lines]; }
    }

    /// <summary>Every stdout byte so far.</summary>
    public byte[] RawStdout
    {
        get { lock (gate) return raw.ToArray(); }
    }

    /// <summary>Bytes after the last <c>\n</c>: a message not newline-terminated.</summary>
    public int TrailingBytes
    {
        get { lock (gate) return pending.Count; }
    }

    public int Id => process.Id;

    public bool HasExited => process.HasExited;

    public int ExitCode => process.ExitCode;
    #endregion

    #region Methods
    public static McpChildProcess Start(IReadOnlyList<string> args, string workingDirectory)
    {
        var psi = new ProcessStartInfo(McpCli.Exe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = workingDirectory,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");
        return new McpChildProcess(Process.Start(psi)!);
    }

    /// <summary>Writes one JSON-RPC message and a bare <c>\n</c>.</summary>
    public void Send(string json)
    {
        process.StandardInput.Write(json);
        process.StandardInput.Write('\n');
        process.StandardInput.Flush();
    }

    /// <summary>The response whose numeric <c>id</c> is <paramref name="id"/>; throws with stderr when none arrives in time.</summary>
    public async Task<JsonElement> WaitForResponseAsync(int id)
    {
        var clock = Stopwatch.StartNew();
        while (true)
        {
            if (Lines.Select(l => TryResponse(l, id)).FirstOrDefault(r => r is not null) is { } found)
                return found;
            if (clock.Elapsed > McpCli.Timeout || stdoutPump.IsCompleted)
                throw new TimeoutException($"no response with id {id} (exited: {process.HasExited}); stdout lines: {Lines.Count}\nstderr:\n{await StderrSoFarAsync()}");
            await Task.Delay(20);
        }
    }

    /// <summary>
    /// Closes stdin and waits up to <see cref="McpCli.Timeout"/> for exit, timing from the close; kills the tree on timeout.
    /// Then drains stdout and stderr.
    /// </summary>
    public async Task<ExitObservation> CloseStdinAndWaitForExitAsync()
    {
        try { process.StandardInput.Close(); } catch (IOException) { /* already gone */ }
        var clock = Stopwatch.StartNew();
        var exited = process.WaitForExit(McpCli.Timeout);
        var elapsed = clock.Elapsed;
        if (!exited)
            Kill();
        process.WaitForExit();
        await Task.WhenAny(Task.WhenAll(stdoutPump, stderrRead), Task.Delay(TimeSpan.FromSeconds(10)));
        return new ExitObservation(exited, elapsed, exited ? process.ExitCode : null, stderrRead.IsCompletedSuccessfully ? stderrRead.Result : "<stderr not drained>");
    }

    /// <summary>Terminates the server process alone (TerminateProcess / SIGKILL), not its tree: no handler of its own runs.</summary>
    public void KillServerOnly()
    {
        process.Kill(entireProcessTree: false);
        process.WaitForExit(10_000);
    }

    public void Dispose()
    {
        if (!process.HasExited)
            Kill();
        process.Dispose();
    }

    private void Kill()
    {
        try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { /* exited meanwhile */ }
        process.WaitForExit(10_000);
    }

    private async Task<string> StderrSoFarAsync()
    {
        if (!process.HasExited)
            return "<still running>";
        await Task.WhenAny(stderrRead, Task.Delay(2_000));
        return stderrRead.IsCompletedSuccessfully ? stderrRead.Result : "<stderr not drained>";
    }

    private static JsonElement? TryResponse(string line, int id)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            return doc.RootElement is { ValueKind: JsonValueKind.Object } root
                && root.TryGetProperty("id", out var rid) && rid.ValueKind == JsonValueKind.Number && rid.GetInt32() == id
                ? root.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private async Task PumpStdoutAsync()
    {
        var stream = process.StandardOutput.BaseStream;
        var buffer = new byte[8192];
        int n;
        while ((n = await stream.ReadAsync(buffer)) > 0)
        {
            lock (gate)
            {
                raw.Write(buffer, 0, n);
                foreach (var b in buffer.AsSpan(0, n))
                {
                    if (b == (byte)'\n')
                    {
                        lines.Add(Encoding.UTF8.GetString([.. pending]));
                        pending.Clear();
                    }
                    else
                        pending.Add(b);
                }
            }
        }
    }
    #endregion

    #region Nested types
    /// <summary><paramref name="Elapsed"/> runs from closing stdin to exit (or to the timeout).</summary>
    public sealed record ExitObservation(bool Exited, TimeSpan Elapsed, int? ExitCode, string Stderr);
    #endregion

    #region Fields
    private readonly Process process;
    private readonly Task stdoutPump;
    private readonly Task<string> stderrRead;
    private readonly object gate = new();
    private readonly MemoryStream raw = new();
    private readonly List<string> lines = [];
    private readonly List<byte> pending = [];
    #endregion
}

/// <summary>Assertions over what a child wrote: stdout lines as JSON-RPC, and the file log.</summary>
internal static class McpAssert
{
    #region Methods
    /// <summary>
    /// Every complete stdout line is a JSON object with jsonrpc "2.0" that is a request/notification (method) or a response
    /// (id with exactly one of result/error), at least <paramref name="minLines"/> of them, and nothing after the last newline.
    /// </summary>
    public static void StdoutIsJsonRpcOnly(McpChildProcess child, int minLines, string stderr)
    {
        var lines = child.Lines;
        Assert.True(lines.Count >= minLines, $"only {lines.Count} stdout lines\n{stderr}");
        Assert.True(child.TrailingBytes == 0, $"{child.TrailingBytes} stdout bytes after the last newline");
        for (var i = 0; i < lines.Count; i++)
            JsonRpcMessage(i, lines[i]);
    }

    /// <summary>The one log file a child wrote to <paramref name="logDir"/>, read shared (the server opens it shared).</summary>
    public static string SingleLogFile(string logDir)
    {
        var path = Assert.Single(Directory.GetFiles(logDir, "Silvergun-MCP*.log"));
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static void JsonRpcMessage(int index, string line)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(line);
        }
        catch (JsonException ex)
        {
            Assert.Fail($"stdout line {index} is not JSON ({ex.Message}): {Shorten(line)}");
            return;
        }
        using (doc)
        {
            var root = doc.RootElement;
            Assert.True(root.ValueKind == JsonValueKind.Object, $"stdout line {index} is not a JSON object: {Shorten(line)}");
            Assert.True(root.TryGetProperty("jsonrpc", out var v) && v.ValueKind == JsonValueKind.String && v.GetString() == "2.0",
                $"stdout line {index} has no jsonrpc \"2.0\": {Shorten(line)}");
            var isRequestOrNotification = root.TryGetProperty("method", out var m) && m.ValueKind == JsonValueKind.String;
            var isResponse = root.TryGetProperty("id", out _) && (root.TryGetProperty("result", out _) ^ root.TryGetProperty("error", out _));
            Assert.True(isRequestOrNotification ^ isResponse, $"stdout line {index} is neither a request/notification nor a response: {Shorten(line)}");
        }
    }

    private static string Shorten(string s) => s.Length <= 300 ? s : s[..300] + "...";
    #endregion
}

/// <summary>The scripted S0 session, written by hand as newline-delimited JSON-RPC.</summary>
internal static class McpScript
{
    #region Methods
    /// <summary>
    /// initialize (protocol 2025-11-25), then notifications/initialized, tools/list, resources/read of the guide and
    /// tools/call get_server_info, waiting for each response. Returns the get_server_info response. stdin stays open.
    /// </summary>
    public static async Task<JsonElement> RunAsync(McpChildProcess child)
    {
        child.Send("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"silvergun-mcp-tests","version":"1.0.0"}}}""");
        var init = await child.WaitForResponseAsync(1);
        Assert.True(init.TryGetProperty("result", out _), $"initialize failed: {init}");

        child.Send("""{"jsonrpc":"2.0","method":"notifications/initialized"}""");
        child.Send("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""");
        child.Send("""{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"silvergun://guide"}}""");
        child.Send("""{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_server_info","arguments":{}}}""");
        foreach (var id in new[] { 2, 3 })
        {
            var response = await child.WaitForResponseAsync(id);
            Assert.True(response.TryGetProperty("result", out _), $"request {id} failed: {response}");
        }
        var info = await child.WaitForResponseAsync(4);
        Assert.True(info.TryGetProperty("result", out _), $"get_server_info failed: {info}");
        return info;
    }

    /// <summary>The <c>instanceId</c> in a get_server_info response's structuredContent.</summary>
    public static string InstanceId(JsonElement infoResponse) =>
        infoResponse.GetProperty("result").GetProperty("structuredContent").GetProperty("instanceId").GetString()!;
    #endregion
}
