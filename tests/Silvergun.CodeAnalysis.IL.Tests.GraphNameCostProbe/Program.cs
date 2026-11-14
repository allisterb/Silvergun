namespace Silvergun.CodeAnalysis.IL.Tests.GraphNameCostProbe;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Text;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

/// <summary>
/// <c>&lt;k&gt; &lt;n&gt; [&lt;tsv-out&gt;]</c>: writes the TypeSpec DAG fixture of docs/agent/tasks/graph-names-hostile-types.md
/// step 1 at depth <c>k</c> with <c>n</c> references, then runs the graph and SSA pipeline over it phase by phase, printing
/// one TSV line per phase (flushed, and appended to <c>tsv-out</c> if given) so a guard kill keeps what came before. One
/// size per process: the peaks are cumulative for the process. Measurement only; asserts nothing.
/// <para>Fixture (<c>GraphNameCost.dll</c>): <c>Dag.Pair`2</c>; TypeSpecs T_0 = <c>Pair&lt;int32,int32&gt;</c> ..
/// T_k = <c>Pair&lt;T_(k-1),T_(k-1)&gt;</c>; in <c>Dag.Holder</c>: <c>Take(T_k)</c> and <c>Take2(T_k, T_k)</c> (each
/// parameter inline as <c>Pair&lt;T_(k-1),T_(k-1)&gt;</c>), <c>CallsTake</c> (n calls of <c>Take(null)</c>),
/// <c>ManyTokens</c> (n <c>ldtoken T_k</c>), each of those two ending in <c>Activator.CreateInstance(typeof(T_k))</c>, and
/// <c>Sink</c> (that sink alone). With <c>--no-signature</c>, only <c>ManyTokens</c>: no T_k in any signature, so model
/// load can be told apart from the signature and namer costs.</para>
/// Exit 0 on DONE, 1 on a managed exception, 2 on bad usage.
/// </summary>
public static class Program
{
    #region Methods
    public static int Main(string[] args)
    {
        var noSignature = args.Contains(NoSignatureFlag);
        args = [.. args.Where(a => a != NoSignatureFlag)];
        if (args.Length is < 2 or > 3
            || !int.TryParse(args[0], NumberStyles.None, CultureInfo.InvariantCulture, out var k) || k is < 1 or > 16
            || !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n is < 1 or > 100_000)
        {
            Console.Error.WriteLine($"USAGE: <k 1..16> <n 1..100000> [tsv-out] [{NoSignatureFlag}]");
            return 2;
        }
        using var file = args.Length == 3 ? new StreamWriter(args[2], append: true) { AutoFlush = true } : null;
        void Emit(string line)
        {
            Console.Out.WriteLine(line);
            Console.Out.Flush();
            file?.WriteLine(line);
        }

        var directory = Path.Combine(Path.GetTempPath(), "silvergun-graphnamecost-" + Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
        Directory.CreateDirectory(directory);
        try
        {
            Emit("k\tn\tphase\twall_ms\talloc_mb\tretained_mb\tpeak_ws_mb\tpeak_private_mb\tprivate_mb\tdetail");
            new Pipeline(new Meter(k, n, Emit), directory, k, n, noSignature).Run();
            Emit("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("UNHANDLED " + Escape(ex.ToString(), 4_000));
            return 1;
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private static string GraphDetail(MethodGraph graph)
    {
        var longest = graph.Nodes.MaxBy(x => x.NodeId.Length)!;
        return $"nodes={graph.Nodes.Count} edges={graph.Edges.Count} opacities={graph.Opacities.Count} "
            + Lengths("node_ids", graph.Nodes.Select(x => x.NodeId)) + " "
            + Lengths("keys", graph.Nodes.Select(x => x.ClassificationKey)) + " "
            + Lengths("edge_ends", graph.Edges.SelectMany(e => new[] { e.From, e.To })) + " "
            + $"long_edge_ends={LongEnds(graph).Count()} long_edge_end_instances={LongEnds(graph).Distinct(ReferenceEqualityComparer.Instance).Count()} "
            + $"longest_node={Short(longest.NodeId)}({longest.Kind})";
    }

    // Edge ends of 1,000 chars or more: the copies of a huge name the graph holds, by reference.
    private static IEnumerable<string> LongEnds(MethodGraph graph) =>
        graph.Edges.SelectMany(e => new[] { e.From, e.To }).Where(id => id.Length >= 1_000);

    // "<label>_max=..  <label>_sum=..": lengths only, never the (exponential) text.
    private static string Lengths(string label, IEnumerable<string> texts)
    {
        var lengths = texts.Select(t => (long)t.Length).ToArray();
        return $"{label}_max={(lengths.Length == 0 ? 0 : lengths.Max())} {label}_sum={lengths.Sum()}";
    }

    // The first 40 chars of a name, escaped, and its length.
    private static string Short(string text) => Escape(text, 40) + (text.Length > 40 ? $"...[{text.Length}]" : "");

    // Printable ASCII only, cut at max chars: anything else, and space and backslash, as \uXXXX.
    private static string Escape(string text, int max)
    {
        var builder = new StringBuilder();
        foreach (var c in text.Take(max))
        {
            if (c is > ' ' and < (char)0x7F and not '\\')
                builder.Append(c);
            else
                builder.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:X4}");
        }
        return builder.ToString();
    }

    private static string Write(string directory, int k, int n, bool noSignature)
    {
        var raw = new RawAssembly("GraphNameCost");
        var type = raw.TypeRef(raw.Runtime, "System", "Type");
        var handle = raw.TypeRef(raw.Runtime, "System", "RuntimeTypeHandle");
        var activator = raw.TypeRef(raw.Runtime, "System", "Activator");
        var getTypeFromHandle = raw.MemberRef(type, "GetTypeFromHandle",
            RawAssembly.MethodSig(false, r => r.Type().Type(type, isValueType: false), p => p.Type(handle, isValueType: true)));
        var createInstance = raw.MemberRef(activator, "CreateInstance",
            RawAssembly.MethodSig(false, r => r.Type().Object(), p => p.Type(type, isValueType: false)));

        var pair = raw.Type("Dag", "Pair`2", raw.Object);
        raw.GenericParameter(pair, "A", 0);
        raw.GenericParameter(pair, "B", 1);
        var specs = Chain(raw, pair, k);

        void CreateInstanceOf(InstructionEncoder il)
        {
            il.OpCode(ILOpCode.Ldtoken);
            il.Token(specs[k]);
            il.Call(getTypeFromHandle);
            il.Call(createInstance);
            il.OpCode(ILOpCode.Pop);
        }
        // T_k written inline as Pair<T_(k-1), T_(k-1)>.
        void Inline(SignatureTypeEncoder encoder)
        {
            var arguments = encoder.GenericInstantiation(pair, 2, isValueType: false);
            ClassOf(arguments.AddArgument(), specs[k - 1]);
            ClassOf(arguments.AddArgument(), specs[k - 1]);
        }
        var none = RawAssembly.MethodSig(false, r => r.Void());

        raw.Type("Dag", "Holder", raw.Object, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        if (!noSignature)
        {
            var take = raw.Static("Take", RawAssembly.MethodSig(false, r => r.Void(), Inline), il => il.OpCode(ILOpCode.Ret));
            raw.Static("Take2", RawAssembly.MethodSig(false, r => r.Void(), Inline, Inline), il => il.OpCode(ILOpCode.Ret));
            raw.Static("CallsTake", none, il =>
            {
                for (var i = 0; i < n; i++)
                {
                    il.OpCode(ILOpCode.Ldnull);
                    il.Call(take);
                }
                CreateInstanceOf(il);
                il.OpCode(ILOpCode.Ret);
            });
        }
        raw.Static("ManyTokens", none, il =>
        {
            for (var i = 0; i < n; i++)
            {
                il.OpCode(ILOpCode.Ldtoken);
                il.Token(specs[k]);
                il.Call(getTypeFromHandle);
                il.OpCode(ILOpCode.Pop);
            }
            CreateInstanceOf(il);
            il.OpCode(ILOpCode.Ret);
        });
        if (!noSignature)
            raw.Static("Sink", none, il =>
            {
                CreateInstanceOf(il);
                il.OpCode(ILOpCode.Ret);
            });
        return raw.Save(directory);
    }

    // As SsaTypeNameDagFixture.Chain: TypeSpec rows T_0 .. T_depth, each argument the row before by TypeSpec handle.
    private static List<TypeSpecificationHandle> Chain(RawAssembly raw, TypeDefinitionHandle pair, int depth)
    {
        var specs = new List<TypeSpecificationHandle>
        {
            raw.TypeSpec(s =>
            {
                var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
                arguments.AddArgument().Int32();
                arguments.AddArgument().Int32();
            }),
        };
        for (var level = 1; level <= depth; level++)
        {
            var previous = specs[^1];
            specs.Add(raw.TypeSpec(s =>
            {
                var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
                ClassOf(arguments.AddArgument(), previous);
                ClassOf(arguments.AddArgument(), previous);
            }));
        }
        return specs;
    }

    // CLASS and the spec's TypeDefOrRefOrSpec coded index, by hand (SignatureTypeEncoder.Type takes no TypeSpec).
    private static void ClassOf(SignatureTypeEncoder encoder, TypeSpecificationHandle spec)
    {
        encoder.Builder.WriteByte((byte)SignatureTypeKind.Class);
        encoder.Builder.WriteCompressedInteger(CodedIndex.TypeDefOrRefOrSpec(spec));
    }
    #endregion

    #region Fields
    private const string NoSignatureFlag = "--no-signature";
    #endregion

    #region Child types
    // The phases, each in its own non-inlined method, their results kept in fields, so a dropped field is really unreachable:
    // a method with exception handling reports its stack temporaries live for its whole body, which kept every phase's
    // result alive when the phases ran in Main.
    private sealed class Pipeline(Meter meter, string directory, int k, int n, bool noSignature)
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public void Run()
        {
            Emit();
            Load();
            Index();
            Graph();
            Sites();
            Members();
            DropModel();
            Open();
            Extract();
            DropSession();
            DropGraph();
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void Emit() => path = meter.Phase("1-emit", () => Write(directory, k, n, noSignature),
            p => $"bytes={new FileInfo(p).Length} variant={(noSignature ? "no-signature" : "full")}");

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void Load()
        {
            model = meter.Phase("2-model-load", () => ModelAssemblies.Load(path!), _ => "");
            weak.Add(("model", new(model)));
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void Index()
        {
            index = meter.Phase("3-member-index", () => model!.Index(),
                i => $"methods={i.Methods.Count} {Lengths("method_ids", i.Methods.Select(m => m.NodeId))}");
            weak.Add(("index", new(index)));
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void Graph()
        {
            graph = meter.Phase("4-method-graph", () => MethodGraph.Build(index!), GraphDetail);
            weak.Add(("graph", new(graph)));
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void Sites() => sites = meter.Phase("5-sink-sites", () => SinkSites.Of(graph!),
            s => $"sites={s.Count} {Lengths("site_node_ids", s.Select(x => x.NodeId))}");

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void Members() => members = meter.Phase("5b-own-members", () => OwnMembers.Of(graph!), _ => "");

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void DropModel() => meter.Phase("5c-drop-model", () =>
        {
            model!.Dispose();
            model = null;
            index = null;
            // As the graph worker does before its SSA phase: Analysis.Net's statics otherwise root the last host's model.
            AssemblyDisassembler.ReleaseStatics();
            return 0;
        }, _ => "model disposed, model and index dropped, ReleaseStatics " + Alive());

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void Open()
        {
            session = meter.Phase("6a-ssa-open", () => SsaSession.Open([path!]), _ => "");
            weak.Add(("session", new(session)));
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void Extract() => facts = meter.Phase("6b-ssa-extract", () => SsaSinkFacts.Extract(session!, sites!, members: members),
            f => $"lifted={f.MethodsLifted} unknown=[{string.Join(",", f.Unknown.Select(u => u.Kind + ":" + u.Methods))}] "
                + string.Join(" ", f.Sites.Select(s => $"{Short(s.Site.NodeId)}@{s.Site.Offset}={s.Status}{(s.FailureKind is { } fk ? "/" + fk : "")}")));

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void DropSession() => meter.Phase("7-drop-session", () => { session!.Dispose(); session = null; facts = null; return 0; },
            _ => "session disposed, session and facts dropped " + Alive());

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void DropGraph() => meter.Phase("8-drop-graph", () => { graph = null; sites = null; members = null; return 0; },
            _ => "graph, sites and members dropped " + Alive());

        private string Alive() => "alive=[" + string.Join(",", weak.Where(w => w.Ref.IsAlive).Select(w => w.Name)) + "]";

        private readonly List<(string Name, WeakReference Ref)> weak = [];
        private string? path;
        private ModelAssemblies? model;
        private MemberIndex? index;
        private MethodGraph? graph;
        private IReadOnlyList<SinkSite>? sites;
        private OwnMembers? members;
        private SsaSession? session;
        private SsaFolderFacts? facts;
    }

    // Times one phase and records its allocation, what it leaves live, and the process's peaks so far.
    private sealed class Meter(int k, int n, Action<string> emit)
    {
        public T Phase<T>(string name, Func<T> run, Func<T, string> detail)
        {
            var allocated = GC.GetTotalAllocatedBytes(true);
            var clock = Stopwatch.StartNew();
            var result = run();
            clock.Stop();
            var allocDelta = GC.GetTotalAllocatedBytes(true) - allocated;
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
            var retained = GC.GetTotalMemory(false);
            using var process = Process.GetCurrentProcess();
            process.Refresh();
            emit(string.Join('\t', k, n, name, clock.ElapsedMilliseconds, Mb(allocDelta), Mb(retained),
                Mb(process.PeakWorkingSet64), Mb(process.PeakPagedMemorySize64), Mb(process.PrivateMemorySize64), detail(result)));
            return result;
        }

        private static string Mb(long bytes) => (bytes / (1024.0 * 1024.0)).ToString("F1", CultureInfo.InvariantCulture);
    }
    #endregion
}
