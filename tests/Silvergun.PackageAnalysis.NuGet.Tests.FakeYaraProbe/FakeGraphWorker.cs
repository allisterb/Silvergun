namespace Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe;

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using Silvergun.PackageAnalysis.NuGet.Graph;

/// <summary>
/// <b>Role 5 - a scripted fake of <c>silvergun __worker graph</c> (<c>--fake-graph-worker &lt;script&gt;</c>).</b> The parent,
/// <c>GraphWorkerProcess</c> / <c>PackageReachability</c>, takes its launch as configuration (an internal
/// <c>GraphWorkerLaunch</c>), so the graph-worker tests point it at this role to replay what a hostile, broken, slow or
/// genuine worker would do (graph worker protocol v1, <c>docs/agent/tasks/graph-worker.md</c> G2). A genuine answer
/// (<c>build</c>) is the real <see cref="GraphWorker"/> run in this process over a one-folder request, re-indexed; everything
/// else is whatever the script says.
///
/// <para><b>Runs.</b> As <see cref="FakeWorker"/>: each start increments <c>&lt;script&gt;.runs</c> and executes section
/// <c>@run N</c>, or <c>@run *</c> when there is none. One command per line; <c>#</c> starts a comment.</para>
///
/// <list type="table">
/// <item><term><c>pid &lt;file&gt;</c></term><description>append this process's id to <c>file</c> (start counts, orphan checks).</description></item>
/// <item><term><c>requests &lt;file&gt;</c> / <c>answered &lt;file&gt;</c></term><description>append the request line, and each folder
/// answered by <c>build</c> / <c>empty</c> / <c>answer</c>, to <c>file</c>.</description></item>
/// <item><term><c>request</c> / <c>wait</c></term><description>read the request line (parsed); read and discard one stdin line.</description></item>
/// <item><term><c>ready [n]</c></term><description><c>ready</c> announcing <c>n</c> folders, or the request's count.</description></item>
/// <item><term><c>build [k]</c> / <c>empty [k]</c></term><description>answer the next <c>k</c> folders (all when absent) for real, or
/// as "nothing loaded" (every assembly a load failure, no report).</description></item>
/// <item><term><c>answer &lt;build|empty&gt; &lt;mod&gt;</c></term><description>answer the next folder, then break it: <c>index</c>
/// (+1), <c>folder</c> (renamed), <c>drop</c> / <c>dup</c> / <c>extra</c> (an assembly missing, twice, or not requested),
/// <c>noreport</c> (report removed), <c>reportnothing</c> (every assembly moved to the failures, report kept), <c>negative</c>
/// (nodes -1), <c>none</c>.</description></item>
/// <item><term><c>skip [k]</c></term><description>count the next <c>k</c> folders answered without writing anything.</description></item>
/// <item><term><c>done [n]</c></term><description><c>done</c> with <c>n</c>, or the request's count.</description></item>
/// <item><term><c>out &lt;text&gt;</c> / <c>raw &lt;text&gt;</c> / <c>outbig &lt;bytes&gt;</c></term><description>stdout: a line, text
/// without a <c>\n</c>, or one line of that many <c>x</c>.</description></item>
/// <item><term><c>err &lt;text&gt;</c></term><description>one stderr line.</description></item>
/// <item><term><c>sleep &lt;ms&gt;</c> / <c>hang</c> / <c>flood</c> / <c>exit &lt;code&gt;</c></term><description>wait; wait forever;
/// write to stdout forever; exit now. A script that runs out exits 0.</description></item>
/// <item><term><c>stackoverflow</c> / <c>failfast</c> / <c>debugfail</c></term><description>die by unbounded recursion,
/// <see cref="Environment.FailFast(string)"/>, or <see cref="Debug.Fail(string)"/> (CCI's path, ADR 0021).</description></item>
/// <item><term><c>alloc &lt;managed|native&gt; &lt;MiB&gt;</c></term><description>commit and touch that much memory, 16 MiB at a
/// time; an allocation failure is unhandled. <c>tryalloc</c> catches it and prints <c>alloc-ok</c> or <c>alloc-failed</c>.</description></item>
/// <item><term><c>floodlines &lt;bytes&gt;</c></term><description>stdout: lines of that many <c>x</c>, forever.</description></item>
/// <item><term><c>relay</c></term><description>become the real worker: <see cref="GraphWorker.Run"/> over this process's own stdin and
/// stdout (with the CLI's exit-4 watchdog), and exit with its code. Must be the first command that touches stdin.</description></item>
/// <item><term><c>answer build null&lt;list&gt;</c></term><description>the modifiers <c>nullassembly</c>, <c>nullfailure</c>,
/// <c>nullreach</c>, <c>nullprofile</c>, <c>nullclass</c>, <c>nullreason</c>, <c>nullignored</c>, <c>nullexample</c> and
/// <c>nullhop</c> append a JSON null to that list of the record or its report.</description></item>
/// <item><term><c>spawn &lt;script&gt;</c></term><description>start a grandchild fake graph worker on <c>script</c>, inheriting
/// this process's standard handles (the orphan checks).</description></item>
/// </list>
/// </summary>
internal static class FakeGraphWorker
{
    #region Methods
    internal static int Run(string script)
    {
        var run = FakeWorker.NextRun(script);
        var session = new Session();
        foreach (var command in FakeWorker.Section(File.ReadAllLines(script), run))
        {
            var (verb, rest) = FakeWorker.Split(command);
            switch (verb)
            {
                case "pid": File.AppendAllText(rest, Environment.ProcessId + "\n"); break;
                case "requests": session.RequestLog = rest; break;
                case "answered": session.AnsweredLog = rest; break;
                case "request": session.ReadRequest(); break;
                case "wait": session.Stdin.ReadLine(); break;
                case "ready": session.Out($"{{\"type\":\"ready\",\"protocol\":1,\"folders\":{(rest.Length == 0 ? session.Folders.Count : int.Parse(rest))}}}\n"); break;
                case "build": session.Answer(FakeWorker.Count(rest), real: true, "none"); break;
                case "empty": session.Answer(FakeWorker.Count(rest), real: false, "none"); break;
                case "answer": session.Answer(1, real: rest.StartsWith("build", StringComparison.Ordinal), rest.Split(' ')[1]); break;
                case "skip": session.Next += FakeWorker.Count(rest); break;
                case "done": session.Out($"{{\"type\":\"done\",\"count\":{(rest.Length == 0 ? session.Folders.Count : int.Parse(rest))}}}\n"); break;
                case "out": session.Out(rest + "\n"); break;
                case "raw": session.Out(rest); break;
                case "outbig": session.OutBig(int.Parse(rest)); break;
                case "floodlines": session.FloodLines(int.Parse(rest)); break;
                case "relay": return Relay(session.RequestLog);
                case "err": session.Err(rest + "\n"); break;
                case "sleep": Thread.Sleep(int.Parse(rest)); break;
                case "hang": Thread.Sleep(Timeout.Infinite); break;
                case "flood": session.Flood(); break;
                case "exit": return int.Parse(rest);
                case "stackoverflow": return Recurse(0);
                case "failfast": Environment.FailFast("fake graph worker: FailFast on request"); break;
                case "debugfail": Debug.Fail("fake graph worker: Debug.Fail on request"); break;
                case "alloc": Allocate(rest, handled: false); break;
                case "tryalloc": session.Out(Allocate(rest, handled: true) ? "alloc-ok\n" : "alloc-failed\n"); break;
                case "spawn": Spawn(rest); break;
                default: throw new InvalidOperationException($"fake graph worker: unknown command '{verb}'");
            }
        }
        return 0;
    }

    // The real worker loop on this process's stdin and stdout, with the CLI's exit-4 watchdog. The request line is read here
    // first, byte by byte so nothing past it is consumed, and logged like the scripted `request` step logs it; the loop then
    // reads that line, and after it the live stdin its watchdog needs.
    private static int Relay(string? requestLog)
    {
        var stdin = Console.OpenStandardInput();
        var line = new MemoryStream();
        for (var b = stdin.ReadByte(); b >= 0; b = stdin.ReadByte())
        {
            line.WriteByte((byte)b);
            if (b == '\n')
                break;
        }
        if (requestLog is not null && line.Length > 0)
            File.AppendAllText(requestLog, Encoding.UTF8.GetString(line.ToArray()).TrimEnd('\n') + "\n");
        line.Position = 0;
        return GraphWorker.Run("1", new ThenStream(line, stdin), Console.OpenStandardOutput(), () => Environment.Exit(4));
    }

    // Unbounded recursion, not a tail call: a real stack overflow (uncatchable, ADR 0021).
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Recurse(int depth) => Recurse(depth + 1) + depth;

    // Commits and touches `<kind> <MiB>` of memory in 16 MiB chunks and keeps it; false when an allocation failed and
    // `handled`, else an allocation failure propagates (an unhandled OutOfMemoryException).
    private static bool Allocate(string rest, bool handled)
    {
        var parts = rest.Split(' ');
        var native = parts[0] == "native";
        var chunks = int.Parse(parts[1]) / 16;
        try
        {
            for (var i = 0; i < chunks; i++)
            {
                if (native)
                {
                    var block = Marshal.AllocHGlobal(Chunk);
                    for (var offset = 0; offset < Chunk; offset += 4096)
                        Marshal.WriteByte(block, offset, 1);
                    kept.Add(block);
                }
                else
                {
                    var block = new byte[Chunk];
                    for (var offset = 0; offset < Chunk; offset += 4096)
                        block[offset] = 1;
                    keptManaged.Add(block);
                }
            }
            return true;
        }
        catch (OutOfMemoryException) when (handled)
        {
            return false;
        }
    }

    private static void Spawn(string script)
    {
        var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
        info.ArgumentList.Add("--fake-graph-worker");
        info.ArgumentList.Add(script);
        Process.Start(info)!.Dispose();
    }
    #endregion

    #region Fields
    private const int Chunk = 16 * 1024 * 1024;

    private static readonly List<nint> kept = [];
    private static readonly List<byte[]> keptManaged = [];
    #endregion

    #region Nested types
    // Reads `first` to its end, then `then`: the request line already taken off stdin, followed by stdin itself.
    private sealed class ThenStream(Stream first, Stream then) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count) =>
            first.Position < first.Length ? first.Read(buffer, offset, count) : then.Read(buffer, offset, count);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class Session
    {
        public string? RequestLog { get; set; }

        public string? AnsweredLog { get; set; }

        public StreamReader Stdin { get; } = new(Console.OpenStandardInput(), new UTF8Encoding(false));

        public JsonArray Folders { get; private set; } = [];

        public int Next { get; set; }

        public void ReadRequest()
        {
            var line = Stdin.ReadLine() ?? throw new InvalidOperationException("fake graph worker: no request line");
            if (RequestLog is not null)
                File.AppendAllText(RequestLog, line + "\n");
            request = JsonNode.Parse(line)!.AsObject();
            Folders = request["folders"]!.AsArray();
        }

        // Answers up to `count` more folders, each for real or as nothing loaded, then breaks it as `mod` says.
        public void Answer(int count, bool real, string mod)
        {
            for (var k = 0; k < count && Next < Folders.Count; k++, Next++)
            {
                var folder = Folders[Next]!.AsObject();
                var record = real ? Built(folder) : Empty(folder);
                record["index"] = Next;
                Break(record, mod);
                if (AnsweredLog is not null)
                    File.AppendAllText(AnsweredLog, folder["folder"]!.GetValue<string>() + "\n");
                Out(record.ToJsonString() + "\n");
            }
        }

        // The real worker's record for this one folder: GraphWorker.Run over a one-folder request, in memory.
        private JsonObject Built(JsonObject folder)
        {
            var one = new JsonObject
            {
                ["protocol"] = 1,
                ["budget"] = request!["budget"]!.DeepClone(),
                ["folders"] = new JsonArray(folder.DeepClone()),
            };
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(one.ToJsonString() + "\n"));
            using var output = new MemoryStream();
            var exit = GraphWorker.Run("1", input, output);
            var lines = Encoding.UTF8.GetString(output.ToArray()).Split('\n');
            if (exit != 0 || lines.Length < 3)
                throw new InvalidOperationException($"fake graph worker: the real worker exited {exit}: {lines[0]}");
            return JsonNode.Parse(lines[1])!.AsObject();
        }

        private static JsonObject Empty(JsonObject folder) => new()
        {
            ["type"] = "folder",
            ["index"] = 0,
            ["folder"] = folder["folder"]!.GetValue<string>(),
            ["assemblies"] = new JsonArray(),
            ["loadFailures"] = new JsonArray([.. folder["assemblies"]!.AsArray().Select(a => (JsonNode)new JsonObject
            {
                ["relativePath"] = a!["relativePath"]!.GetValue<string>(),
                ["reason"] = "fake: not loaded",
            })]),
            ["report"] = null,
            ["nodes"] = 0,
            ["edges"] = 0,
        };

        private static void Break(JsonObject record, string mod)
        {
            var assemblies = record["assemblies"]!.AsArray();
            var failures = record["loadFailures"]!.AsArray();
            var list = assemblies.Count > 0 ? assemblies : failures;
            switch (mod)
            {
                case "none": break;
                case "index": record["index"] = record["index"]!.GetValue<int>() + 1; break;
                case "folder": record["folder"] = record["folder"]!.GetValue<string>() + "-other"; break;
                case "drop": list.RemoveAt(0); break;
                case "dup": list.Add(list[0]!.DeepClone()); break;
                case "extra": list.Add(list == assemblies ? (JsonNode)"not/requested.dll" : new JsonObject { ["relativePath"] = "not/requested.dll", ["reason"] = "fake" }); break;
                case "noreport": record["report"] = null; break;
                case "negative": record["nodes"] = -1; break;
                case "nullassembly": assemblies.Add(null); break;
                case "nullfailure": failures.Add(null); break;
                case "nullreach": Report(record)["reaches"]!.AsArray().Add(null); break;
                case "nullprofile": Report(record)["profiles"]!.AsArray().Add(null); break;
                case "nullclass": Report(record)["classes"]!.AsArray().Add(null); break;
                case "nullreason": Report(record)["classes"]!.AsArray()[0]!["reasons"]!.AsArray().Add(null); break;
                case "nullignored": Report(record)["ignoredEdges"]!.AsArray().Add(null); break;
                case "nullexample": Report(record)["reaches"]!.AsArray()[0]!["examples"]!.AsArray().Add(null); break;
                case "nullhop":
                    Report(record)["reaches"]!.AsArray().Select(r => r!["examples"]!.AsArray()).First(e => e.Count > 0)[0]!["hops"]!.AsArray().Add(null);
                    break;
                case "reportnothing":
                    foreach (var name in assemblies.Select(a => a!.GetValue<string>()).ToArray())
                        failures.Add(new JsonObject { ["relativePath"] = name, ["reason"] = "fake: moved" });
                    assemblies.Clear();
                    break;
                default: throw new InvalidOperationException($"fake graph worker: unknown modifier '{mod}'");
            }
        }

        private static JsonObject Report(JsonObject record) =>
            record["report"] as JsonObject ?? throw new InvalidOperationException("fake graph worker: this modifier needs a real report (answer build ...)");

        // Lines of `bytes` x's (each within the protocol's 16 MiB record limit when bytes is), forever: a flood of
        // records the parent must not read.
        public void FloodLines(int bytes)
        {
            var line = new byte[bytes + 1];
            Array.Fill(line, (byte)'x');
            line[^1] = (byte)'\n';
            while (true)
            {
                stdout.Write(line);
                stdout.Flush();
            }
        }

        public void OutBig(int bytes)
        {
            var chunk = Encoding.ASCII.GetBytes(new string('x', 64 * 1024));
            for (var written = 0; written < bytes; written += chunk.Length)
                stdout.Write(chunk, 0, Math.Min(chunk.Length, bytes - written));
            stdout.Write("\n"u8);
            stdout.Flush();
        }

        public void Out(string text)
        {
            stdout.Write(Encoding.UTF8.GetBytes(text));
            stdout.Flush();
        }

        public void Err(string text)
        {
            stderr.Write(Encoding.UTF8.GetBytes(text));
            stderr.Flush();
        }

        public void Flood()
        {
            var chunk = Encoding.ASCII.GetBytes(new string('x', 64 * 1024));
            while (true)
                stdout.Write(chunk);
        }

        private readonly Stream stdout = Console.OpenStandardOutput();
        private readonly Stream stderr = Console.OpenStandardError();
        private JsonObject? request;
    }
    #endregion
}
