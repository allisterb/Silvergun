namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

/// <summary>
/// The presence parity oracle of ADR 0037 decision 9, exactly as <c>Silvergun.CodeAnalysis.IL.Tests.PresenceParityTests</c>
/// computes it, so a corpus folder is judged by the rule the library's tests pin. Both sides are reduced to distinct
/// <c>(caller key, capability, callee key)</c> triples:
/// <list type="bullet">
/// <item><description><b>Scanner:</b> the <see cref="CapabilityAnalysis"/> findings of kinds Call, Construct,
/// MethodPointerLoad and NativeImport; caller <c>CallerType.CallerMethod</c>, callee <c>CalledApi</c>, both with generic
/// argument lists removed (<see cref="ScannerKey"/>); a NativeImport's callee is <see cref="NativeCallee"/>.</description></item>
/// <item><description><b>Graph:</b> every call-site edge (Call, CallVirt, NewObj, Ldftn, Ldvirtftn) from an own node to an
/// External node the default map classifies as a capability, by the two nodes' classification keys; plus every own node
/// whose facts say NativeImport.</description></item>
/// </list>
/// A scanner-only triple is <c>NameShadowed</c> only when the graph has a call-site edge from that caller to an own node
/// keyed as the callee (S3 review N1). Any other difference is unexplained. Duplicated here rather than shared because
/// the test is an xUnit class this console harness does not reference; <c>ReachabilityHarnessTests</c> pins the copy.
/// </summary>
public static class ReachabilityParity
{
    #region Methods
    /// <summary>Compares <paramref name="findings"/> (the scanner over the graph's assemblies) with <paramref name="graph"/>.</summary>
    public static ParityRecord Compare(IEnumerable<ApiCallFinding> findings, MethodGraph graph)
    {
        var scanner = ScannerTriples(findings);
        var graphSide = GraphTriples(graph);
        var ownCalls = OwnCallKeys(graph);

        var scannerOnly = scanner.Except(graphSide).Order().ToArray();
        var shadowed = scannerOnly.Where(t => t.Callee != NativeCallee && ownCalls.Contains((t.Caller, t.Callee))).ToArray();
        var unexplained = scannerOnly.Except(shadowed).ToArray();
        var graphOnly = graphSide.Except(scanner).Order().ToArray();

        return new ParityRecord(
            scanner.Intersect(graphSide).Count(),
            Cap(shadowed.Select(Render)),
            Cap(unexplained.Select(Render)),
            Cap(graphOnly.Select(Render)));
    }

    /// <summary>A rendered CCI name with its generic argument lists removed; a <c>&lt;</c> opening a name part is kept.</summary>
    public static string ScannerKey(string rendered)
    {
        var key = new StringBuilder(rendered.Length);
        var depth = 0;
        for (var i = 0; i < rendered.Length; i++)
        {
            var c = rendered[i];
            if (depth > 0)
                depth += c == '<' ? 1 : c == '>' ? -1 : 0;
            else if (c == '<' && i > 0 && rendered[i - 1] is not '.' and not '<')
                depth = 1;
            else
                key.Append(c);
        }
        return key.ToString();
    }

    private static CappedList Cap(IEnumerable<string> items)
    {
        var all = items.ToArray();
        return new CappedList(all.Length, [.. all.Take(ReachabilityChild.MaxListed)]);
    }

    private static string Render(Triple t) => $"{t.Caller} -[{t.Capability}]-> {t.Callee}";

    private static HashSet<(string Caller, string Callee)> OwnCallKeys(MethodGraph graph) =>
        graph.Edges
            .Where(e => callSiteKinds.Contains(e.Kind))
            .Select(e => (From: graph.Node(e.From), To: graph.Node(e.To)))
            .Where(e => e.From is { Kind: not MethodNodeKind.External } && e.To is { Kind: not MethodNodeKind.External })
            .Select(e => (e.From!.ClassificationKey, e.To!.ClassificationKey))
            .ToHashSet();

    private static HashSet<Triple> ScannerTriples(IEnumerable<ApiCallFinding> findings) =>
        findings
            .Where(f => comparedKinds.Contains(f.Kind))
            .Select(f => new Triple($"{ScannerKey(f.CallerType)}.{f.CallerMethod}", f.Capability, f.Kind == ApiCallKind.NativeImport ? NativeCallee : ScannerKey(f.CalledApi)))
            .ToHashSet();

    private static HashSet<Triple> GraphTriples(MethodGraph graph) =>
        SinkEdges(graph)
            .Select(e => new Triple(graph.Node(e.From)!.ClassificationKey, Classify(graph.Node(e.To)!)!.Value, graph.Node(e.To)!.ClassificationKey))
            .Concat(graph.Facts.Methods
                .Where(f => f.NativeImport && graph.Node(f.NodeId) is { Kind: not MethodNodeKind.External })
                .Select(f => new Triple(graph.Node(f.NodeId)!.ClassificationKey, Capability.NativeInterop, NativeCallee)))
            .ToHashSet();

    private static IEnumerable<MethodEdge> SinkEdges(MethodGraph graph) =>
        graph.Edges.Where(e => callSiteKinds.Contains(e.Kind)
            && graph.Node(e.From) is { Kind: not MethodNodeKind.External }
            && graph.Node(e.To) is { Kind: MethodNodeKind.External } to
            && Classify(to) is not null);

    private static Capability? Classify(MethodNode node) =>
        CapabilityMap.Default.Classify(node.ClassificationKey) is { Class: CapabilityClass.Capability, Capability: { } capability } ? capability : null;
    #endregion

    #region Fields
    /// <summary>The callee key of a NativeImport, on both sides.</summary>
    public const string NativeCallee = "<native import>";

    private static readonly ApiCallKind[] comparedKinds = [ApiCallKind.Call, ApiCallKind.Construct, ApiCallKind.MethodPointerLoad, ApiCallKind.NativeImport];

    private static readonly HashSet<MethodEdgeKind> callSiteKinds =
        [MethodEdgeKind.Call, MethodEdgeKind.CallVirt, MethodEdgeKind.NewObj, MethodEdgeKind.Ldftn, MethodEdgeKind.Ldvirtftn];
    #endregion

    #region Child types
    // One capability use: who, what capability, through which API. Ordered as PresenceParityTests orders its triples.
    private sealed record Triple(string Caller, Capability Capability, string Callee) : IComparable<Triple>
    {
        public int CompareTo(Triple? other) =>
            other is null ? 1
            : string.CompareOrdinal(Caller, other.Caller) is var a && a != 0 ? a
            : Capability.CompareTo(other.Capability) is var b && b != 0 ? b
            : string.CompareOrdinal(Callee, other.Callee);
    }
    #endregion
}
