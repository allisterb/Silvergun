namespace Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe;

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using Silvergun.PackageAnalysis.NuGet.Graph;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>
/// <b>Role 5 - a scripted fake of <c>silvergun __worker graph</c> (<c>--fake-graph-worker &lt;script&gt;</c>).</b> The parent,
/// <c>GraphWorkerProcess</c> / <c>PackageReachability</c>, takes its launch as configuration (an internal
/// <c>GraphWorkerLaunch</c>), so the graph-worker tests point it at this role to replay what a hostile, broken, slow or
/// genuine worker would do (graph worker protocol v2, <c>docs/agent/tasks/graph-worker.md</c> G2 and
/// <c>ssa-facts-s4.md</c> §4). A genuine answer (<c>build</c>) is the real <see cref="GraphWorker"/> run in this process over
/// a one-folder request (with the request's <c>ssa</c> bounds, when it has them), re-indexed; everything else is whatever
/// the script says.
///
/// <para><b>Runs.</b> As <see cref="FakeWorker"/>: each start increments <c>&lt;script&gt;.runs</c> and executes section
/// <c>@run N</c>, or <c>@run *</c> when there is none. One command per line; <c>#</c> starts a comment.</para>
///
/// <para><b>The SSA phase.</b> When the request carries <c>ssa</c> bounds, <c>build</c>, <c>empty</c> and <c>answer</c> follow
/// each folder record with its <c>ssa</c> record, as the real worker does: the real worker's for <c>build</c>, and for
/// <c>empty</c> a NotRun one (no graph, so no sink sites). <c>graph</c> writes only the folder record and leaves its
/// <c>ssa</c> record pending, so the script can die, hang, send <c>fatal</c> or allocate in the SSA phase, or send the
/// pending record (broken or not) with <c>ssa</c>. Without <c>ssa</c> bounds no <c>ssa</c> record is ever written but by
/// <c>out</c>.</para>
///
/// <list type="table">
/// <item><term><c>pid &lt;file&gt;</c></term><description>append this process's id to <c>file</c> (start counts, orphan checks).</description></item>
/// <item><term><c>requests &lt;file&gt;</c> / <c>answered &lt;file&gt;</c></term><description>append the request line, and each folder
/// answered by <c>build</c> / <c>empty</c> / <c>answer</c> / <c>graph</c>, to <c>file</c>.</description></item>
/// <item><term><c>request</c> / <c>wait</c></term><description>read the request line (parsed); read and discard one stdin line.</description></item>
/// <item><term><c>ready [n]</c></term><description><c>ready</c> for this build's protocol announcing <c>n</c> folders, or the request's count.</description></item>
/// <item><term><c>build [k]</c> / <c>empty [k]</c></term><description>answer the next <c>k</c> folders (all when absent) for real, or
/// as "nothing loaded" (every assembly a load failure, no report); each followed by its <c>ssa</c> record when SSA is on.</description></item>
/// <item><term><c>answer &lt;build|empty&gt; &lt;mod&gt;</c></term><description>answer the next folder, then break it: <c>index</c>
/// (+1), <c>folder</c> (renamed), <c>drop</c> / <c>dup</c> / <c>extra</c> (an assembly missing, twice, or not requested),
/// <c>noreport</c> (report removed), <c>reportnothing</c> (every assembly moved to the failures, report kept), <c>negative</c>
/// (nodes -1), <c>none</c>.</description></item>
/// <item><term><c>graph &lt;build|empty&gt;</c></term><description>answer the next folder's <c>folder</c> record only, keeping its
/// <c>ssa</c> record (as <c>build</c> or <c>empty</c> would write it) pending.</description></item>
/// <item><term><c>ssa &lt;mod&gt;</c></term><description>write the pending <c>ssa</c> record, broken by <c>mod</c>: <c>none</c>;
/// <c>index</c> (+1); <c>timedout</c> (TimedOut, which only the parent decides); <c>crashed</c> / <c>notrun</c> (that outcome
/// with a reason, no facts: valid); <c>notrun &lt;reason&gt;</c> (NotRun with that reason); <c>pad &lt;n&gt;</c> (NotRun with a
/// reason of <c>n</c> <c>p</c>s); <c>crashedfacts</c> (Crashed, facts kept); <c>analyzednofacts</c> (Analyzed, no facts);
/// <c>reasonandfacts</c> (Analyzed with a reason too); <c>noreason</c> (NotRun, no reason); <c>analyzed</c> (Analyzed with empty
/// facts); <c>nullsite</c>, <c>nullunknown</c>, <c>nullargument</c>, <c>nullconstant</c>, <c>nullcandidate</c> (a JSON null in
/// that list; the last two need a site with an argument, or set a target on the first site); <c>oversites</c> (the first
/// site twice more, counts kept consistent); <c>inconsistent</c> (sitesTotal below the sites); <c>truncatedlie</c>
/// (truncated flipped); <c>overargs</c> / <c>overcandidates</c> (the first site gets one argument, or one candidate, past
/// the request's bound); <c>negative</c> / <c>negativelost</c> (methodsLifted or assembliesLost -1). Value contracts, on
/// the first argument of the first Analyzed site that has one: <c>constempty</c> (Constant, no constant), <c>oneofone</c>
/// (OneOf, one constant), <c>dynnoorigin</c> (Dynamic, no origin), <c>paramneg</c> (Parameter -5), <c>hugeconst</c> (a
/// 100,000-char constant), <c>controlconst</c> (a raw control char in a constant), <c>textconst &lt;hex&gt;</c> /
/// <c>typeconst &lt;hex&gt;</c> (a String or Type constant of exactly that text, UTF-16 code units in hex, 4 digits
/// each). Site contracts: <c>argcountneg</c>
/// (argumentCount -7), <c>analyzedreason</c> (an Analyzed site with a reason), <c>unknownnokind</c> /
/// <c>unknownnoreason</c> (MethodUnknown without its failure kind, or its reason), <c>unknownwithargs</c> (MethodUnknown
/// keeping its values), <c>notrunsite</c> (a NotRun site with no budget flag), <c>longname</c> (a node id past its bound),
/// <c>targetmember</c> (a Type target with a member), <c>candidatestotal</c> (more candidates than candidatesTotal).
/// Folder contracts: <c>unknownneg</c> (a failure count of -9), <c>unknowndup</c> (one failure kind twice),
/// <c>lostanalyzed</c> (assembliesLost 1 with Analyzed sites), <c>unknowntimedout</c> (one TimedOut failure count),
/// <c>sitetimedout</c> (the first site MethodUnknown with kind TimedOut and a reason). Valid controls: <c>unknownok</c> (the first site
/// MethodUnknown with kind and reason), <c>notrunok</c> (the first site NotRun, methodBudget set). Every <c>null*</c>,
/// count, value and site modifier needs facts with a site (<c>graph build</c> over a folder with sink sites).</description></item>
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
        // First, mirroring the CLI's `Main`, which opts out for every `__worker` command line: a fake that dies
        // (stackoverflow, failfast, debugfail) is gone at once, so the parent sees the pipe end and reads Crashed, never TimedOut while WER builds a report (13-43 s).
        WorkerErrorReporting.OptOut();
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
                case "ready": session.Out($"{{\"type\":\"ready\",\"protocol\":{GraphWorkerProtocol.Version},\"folders\":{(rest.Length == 0 ? session.Folders.Count : int.Parse(rest))}}}\n"); break;
                case "build": session.Answer(FakeWorker.Count(rest), real: true, "none", ssaNow: true); break;
                case "empty": session.Answer(FakeWorker.Count(rest), real: false, "none", ssaNow: true); break;
                case "answer": session.Answer(1, real: rest.StartsWith("build", StringComparison.Ordinal), rest.Split(' ')[1], ssaNow: true); break;
                case "graph": session.Answer(1, real: rest == "build", "none", ssaNow: false); break;
                case "ssa": session.WriteSsa(rest); break;
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
        return GraphWorker.Run(Protocol, new ThenStream(line, stdin), Console.OpenStandardOutput(), () => Environment.Exit(4));
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

    // This build's --protocol value, as the CLI passes it.
    private static readonly string Protocol = GraphWorkerProtocol.Version.ToString(System.Globalization.CultureInfo.InvariantCulture);

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

        // Answers up to `count` more folders, each for real or as nothing loaded, then breaks it as `mod` says. With SSA on,
        // each folder's ssa record follows it (`ssaNow`), or is kept pending for an `ssa` command.
        public void Answer(int count, bool real, string mod, bool ssaNow)
        {
            for (var k = 0; k < count && Next < Folders.Count; k++, Next++)
            {
                var folder = Folders[Next]!.AsObject();
                var (record, ssa) = real ? Built(folder) : (Empty(folder), SsaOn ? EmptySsa() : null);
                record["index"] = Next;
                Break(record, mod);
                if (AnsweredLog is not null)
                    File.AppendAllText(AnsweredLog, folder["folder"]!.GetValue<string>() + "\n");
                Out(record.ToJsonString() + "\n");
                if (ssa is null)
                    continue;
                ssa["index"] = Next;
                if (ssaNow)
                    Out(ssa.ToJsonString() + "\n");
                else
                    pendingSsa = ssa;
            }
        }

        // Writes the pending ssa record (from `graph`), broken as `mod` says.
        public void WriteSsa(string mod)
        {
            var record = pendingSsa ?? throw new InvalidOperationException("fake graph worker: no ssa record is pending (graph first, with SSA on)");
            pendingSsa = null;
            BreakSsa(record, mod);
            Out(record.ToJsonString() + "\n");
        }

        // Whether the request asks for SSA facts.
        private bool SsaOn => request?["ssa"] is JsonObject;

        // The real worker's records for this one folder: GraphWorker.Run over a one-folder request (with the request's SSA
        // bounds), in memory. The ssa record is null when the request has no SSA bounds.
        private (JsonObject Record, JsonObject? Ssa) Built(JsonObject folder)
        {
            var one = new JsonObject
            {
                ["protocol"] = GraphWorkerProtocol.Version,
                ["budget"] = request!["budget"]!.DeepClone(),
                ["folders"] = new JsonArray(folder.DeepClone()),
            };
            if (SsaOn)
                one["ssa"] = request!["ssa"]!.DeepClone();
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(one.ToJsonString() + "\n"));
            using var output = new MemoryStream();
            var exit = GraphWorker.Run(Protocol, input, output);
            var lines = Encoding.UTF8.GetString(output.ToArray()).Split('\n');
            if (exit != 0 || lines.Length < (SsaOn ? 4 : 3))
                throw new InvalidOperationException($"fake graph worker: the real worker exited {exit}: {lines[^1]}");
            return (JsonNode.Parse(lines[1])!.AsObject(), SsaOn ? JsonNode.Parse(lines[2])!.AsObject() : null);
        }

        // The ssa record the real worker sends for a folder with no graph.
        private static JsonObject EmptySsa() => new()
        {
            ["type"] = "ssa",
            ["index"] = 0,
            ["outcome"] = "NotRun",
            ["facts"] = null,
            ["reason"] = "the folder's graph was not built, so it has no sink sites",
        };

        private static JsonObject EmptyFacts() => new()
        {
            ["sites"] = new JsonArray(),
            ["sitesTotal"] = 0,
            ["truncated"] = false,
            ["methodsLifted"] = 0,
            ["unknown"] = new JsonArray(),
            ["methodBudget"] = false,
            ["timeBudget"] = false,
            ["textBudget"] = false,
            ["assembliesLost"] = 0,
        };

        private static JsonObject Dynamic() => new() { ["kind"] = "Dynamic", ["constants"] = new JsonArray(), ["parameter"] = null, ["origin"] = "Other" };

        private static JsonObject Value(string kind, JsonNode[] constants, int? parameter, string? origin) => new()
        {
            ["kind"] = kind,
            ["constants"] = new JsonArray(constants),
            ["parameter"] = parameter,
            ["origin"] = origin,
        };

        private static JsonObject Constant(string text) => new() { ["kind"] = "String", ["text"] = text, ["cut"] = false };

        // Text from UTF-16 code units in hex, 4 digits each ("005c0071" is a backslash and q).
        private static string Utf16(string hex) =>
            new([.. Enumerable.Range(0, hex.Length / 4).Select(i => (char)Convert.ToUInt16(hex.Substring(i * 4, 4), 16))]);

        private static JsonObject Failure(string kind, int methods) => new() { ["kind"] = kind, ["methods"] = methods };

        // A site made non-Analyzed: `status`, its failure kind and reason, and no values.
        private static void Unanalyzed(JsonObject site, string status, string? kind, string? reason)
        {
            site["status"] = status;
            site["failureKind"] = kind;
            site["reason"] = reason;
            site["receiver"] = null;
            site["arguments"] = new JsonArray();
            site["argumentCount"] = 0;
            site["merged"] = false;
            site["target"] = null;
        }

        private static JsonObject Target(JsonArray candidates, JsonObject? member = null) => new()
        {
            ["kind"] = "Type",
            ["assembly"] = null,
            ["type"] = Dynamic(),
            ["member"] = member,
            ["match"] = "ByName",
            ["candidates"] = candidates,
            ["candidatesTotal"] = candidates.Count,
            ["candidatesGap"] = null,
        };

        private void BreakSsa(JsonObject record, string mod)
        {
            var (verb, argument) = FakeWorker.Split(mod);
            var facts = record["facts"] as JsonObject;
            var bounds = request!["ssa"]!.AsObject();
            JsonArray Sites() => (facts ?? throw new InvalidOperationException($"fake graph worker: ssa {verb} needs facts")) ["sites"]!.AsArray();
            JsonObject First() => Sites().Count > 0 ? Sites()[0]!.AsObject() : throw new InvalidOperationException($"fake graph worker: ssa {verb} needs a site");
            void Failed(string outcome, string? reason, bool keepFacts = false)
            {
                record["outcome"] = outcome;
                if (!keepFacts)
                    record["facts"] = null;
                record["reason"] = reason;
            }
            JsonObject Analyzed() =>
                Sites().Select(s => s!.AsObject()).FirstOrDefault(s => s["status"]!.GetValue<string>() == "Analyzed")
                    ?? throw new InvalidOperationException($"fake graph worker: ssa {verb} needs an Analyzed site");
            JsonObject WithArgument() =>
                Sites().Select(s => s!.AsObject()).FirstOrDefault(s => s["status"]!.GetValue<string>() == "Analyzed" && s["arguments"]!.AsArray().Count > 0)
                    ?? throw new InvalidOperationException($"fake graph worker: ssa {verb} needs an Analyzed site with an argument");
            void FirstArgument(JsonObject value) => WithArgument()["arguments"]!.AsArray()[0] = value;
            void Consistent(int total)
            {
                facts!["sitesTotal"] = Math.Max(total, Sites().Count);
                facts["truncated"] = facts["sitesTotal"]!.GetValue<int>() > Sites().Count;
            }
            switch (verb)
            {
                case "none": break;
                case "index": record["index"] = record["index"]!.GetValue<int>() + 1; break;
                case "timedout": Failed("TimedOut", "fake: timed out"); break;
                case "crashed": Failed("Crashed", "fake: crashed"); break;
                case "notrun": Failed("NotRun", argument.Length > 0 ? argument : "fake: not run"); break;
                case "pad": Failed("NotRun", new string('p', int.Parse(argument))); break;
                case "crashedfacts": _ = Sites(); Failed("Crashed", "fake: crashed", keepFacts: true); break;
                case "analyzednofacts": Failed("Analyzed", "fake: no facts"); break;
                case "reasonandfacts": _ = Sites(); record["reason"] = "fake: a reason too"; break;
                case "noreason": Failed("NotRun", null); break;
                case "analyzed": record["outcome"] = "Analyzed"; record["facts"] = EmptyFacts(); record["reason"] = null; break;
                case "nullsite": Sites().Add(null); break;
                case "nullunknown": _ = Sites(); facts!["unknown"]!.AsArray().Add(null); break;
                case "nullargument": First()["arguments"]!.AsArray().Add(null); break;
                case "nullconstant":
                    var withArgument = Sites().Select(s => s!["arguments"]!.AsArray()).FirstOrDefault(a => a.Count > 0 && a[0] is JsonObject)
                        ?? throw new InvalidOperationException("fake graph worker: ssa nullconstant needs a site with an argument");
                    withArgument[0]!["constants"]!.AsArray().Add(null);
                    break;
                case "nullcandidate": First()["target"] = Target(new JsonArray("Own.Type", null)); break;
                case "oversites":
                    First();
                    Sites().Add(Sites()[0]!.DeepClone());
                    Sites().Add(Sites()[0]!.DeepClone());
                    Consistent(facts!["sitesTotal"]!.GetValue<int>());
                    break;
                case "inconsistent": First(); facts!["sitesTotal"] = Sites().Count - 1; break;
                case "truncatedlie": _ = Sites(); facts!["truncated"] = !facts["truncated"]!.GetValue<bool>(); break;
                case "overargs":
                    var arguments = First()["arguments"]!.AsArray();
                    while (arguments.Count <= bounds["maxArguments"]!.GetValue<int>())
                        arguments.Add(Dynamic());
                    First()["argumentCount"] = arguments.Count;
                    break;
                case "overcandidates":
                    First()["target"] = Target(new JsonArray([.. Enumerable.Range(0, bounds["maxCandidates"]!.GetValue<int>() + 1).Select(i => (JsonNode)$"Own.Type{i}")]));
                    break;
                case "negative": _ = Sites(); facts!["methodsLifted"] = -1; break;
                case "negativelost": _ = Sites(); facts!["assembliesLost"] = -1; break;
                // Review round 1 (W3): one value, site or folder contract broken at a time.
                case "constempty": FirstArgument(Value("Constant", [], null, null)); break;
                case "oneofone": FirstArgument(Value("OneOf", [Constant("a")], null, null)); break;
                case "dynnoorigin": FirstArgument(Value("Dynamic", [], null, null)); break;
                case "paramneg": FirstArgument(Value("Parameter", [], -5, null)); break;
                case "hugeconst": FirstArgument(Value("Constant", [Constant(new string('x', 100_000))], null, null)); break;
                case "controlconst": FirstArgument(Value("Constant", [Constant("a" + (char)1 + "b")], null, null)); break;
                // Review round 2 (N1): a String or Type constant of exactly this text, given as UTF-16 code units in hex (4
                // digits each), so backslashes, quotes and lone surrogates cross the script verbatim.
                case "textconst": FirstArgument(Value("Constant", [Constant(Utf16(argument))], null, null)); break;
                case "typeconst":
                    var typeName = Constant(Utf16(argument));
                    typeName["kind"] = "Type";
                    FirstArgument(Value("Constant", [typeName], null, null));
                    break;
                case "argcountneg": Analyzed()["argumentCount"] = -7; break;
                case "analyzedreason": Analyzed()["reason"] = "fake: a reason on an Analyzed site"; break;
                case "unknownok": Unanalyzed(First(), "MethodUnknown", "Import", "fake: did not import"); break;
                case "unknownnokind": Unanalyzed(First(), "MethodUnknown", null, "fake: did not import"); break;
                case "unknownnoreason": Unanalyzed(First(), "MethodUnknown", "Import", null); break;
                case "unknownwithargs":
                    var withArgs = WithArgument();
                    withArgs["status"] = "MethodUnknown";
                    withArgs["failureKind"] = "Import";
                    withArgs["reason"] = "fake: did not import";
                    break;
                case "notrunok": Unanalyzed(First(), "NotRun", null, "fake: not run"); facts!["methodBudget"] = true; break;
                case "notrunsite": Unanalyzed(First(), "NotRun", null, "fake: not run"); facts!["methodBudget"] = false; facts["timeBudget"] = false; break;
                case "unknownneg": _ = Sites(); facts!["unknown"] = new JsonArray(Failure("Import", -9)); break;
                case "unknowndup": _ = Sites(); facts!["unknown"] = new JsonArray(Failure("Import", 1), Failure("Import", 2)); break;
                case "lostanalyzed": Analyzed(); facts!["assembliesLost"] = 1; break;
                // In-lift deadline, review round 1: a TimedOut lift never reaches a fact, as a count or as a site's kind.
                case "unknowntimedout": _ = Sites(); facts!["unknown"] = new JsonArray(Failure("TimedOut", 1)); break;
                case "sitetimedout": Unanalyzed(First(), "MethodUnknown", "TimedOut", "fake: timed out"); break;
                case "longname": First()["site"]!["nodeId"] = new string('n', Silvergun.CodeAnalysis.IL.Reachability.MaxNameChars + 49); break;
                case "targetmember": Analyzed()["target"] = Target(new JsonArray(), member: Dynamic()); break;
                case "candidatestotal":
                    var target = Target(new JsonArray("Own.Type"));
                    target["candidatesTotal"] = 0;
                    Analyzed()["target"] = target;
                    break;
                default: throw new InvalidOperationException($"fake graph worker: unknown ssa modifier '{verb}'");
            }
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
        private JsonObject? pendingSsa;
    }
    #endregion
}
