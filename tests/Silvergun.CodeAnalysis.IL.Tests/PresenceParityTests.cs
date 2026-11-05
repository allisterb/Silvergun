namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The presence parity oracle (ADR 0037 decision 9; reachability R1, S3; acceptance criterion 6): the raw-CCI
/// <see cref="CapabilityAnalysis"/> and the graph's sinks must see the same capability uses. Both sides are reduced to
/// distinct <c>(caller key, capability, callee key)</c> triples, keyed as the scanner keys them:
/// <list type="bullet">
/// <item><description><b>Scanner:</b> the findings of kinds <see cref="ApiCallKind.Call"/>, <see cref="ApiCallKind.Construct"/>,
/// <see cref="ApiCallKind.MethodPointerLoad"/> and <see cref="ApiCallKind.NativeImport"/>. The caller key is
/// <c>CallerType.CallerMethod</c>; the callee key is <c>CalledApi</c> with its generic argument lists removed (the scanner
/// classifies by the declaring type's definition, so <c>Expression&lt;Func&lt;String&gt;&gt;.Compile</c> is classified as
/// <c>Expression.Compile</c>).</description></item>
/// <item><description><b>Graph:</b> every edge of the five call-site kinds (Call, CallVirt, NewObj, Ldftn, Ldvirtftn) from
/// an own node to an External node the map classifies as a capability, keyed by the two nodes' classification keys; plus
/// every own node whose facts say NativeImport.</description></item>
/// </list>
/// A NativeImport has no callee the graph can name (the scanner's is <c>module!entry</c>), so both sides key it
/// <see cref="NativeCallee"/>. Every difference is either fixed or a named, counted gap here (<c>Comparison.Gaps</c>), never
/// tolerated silently. The one expected gap is <c>NameShadowed</c>: a callee named like a platform API that the package
/// defines itself is classified by the scanner by name, and walked by the graph as own code.
/// </summary>
public sealed class PresenceParityTests : IClassFixture<MechanismFixtureFixture>, IClassFixture<ShadowMethodGraphFixture>
{
    #region Constructors
    public PresenceParityTests(MechanismFixtureFixture mechanism, ShadowMethodGraphFixture shadow)
    {
        this.mechanism = mechanism;
        this.shadow = shadow;
    }
    #endregion

    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // The mechanism fixture (all three assemblies, one graph)
    // ---------------------------------------------------------------------------------------------------

    // Measured: exact. No NameShadowed gap either, since the mechanism fixture defines no platform-named member.
    [Fact]
    public void Parity_OverTheMechanismFixture_IsExact_WithNoNamedGap()
    {
        var comparison = Compare(ScannerTriples(mechanism.Findings), MechanismGraphSource.Graph);

        AssertParity(comparison, new Dictionary<string, int>(StringComparer.Ordinal) { [NameShadowed] = 0 });
    }

    // The comparison is not vacuous: every scanner kind the oracle compares, and every capability the fixture's sinks
    // stand for, occurs on both sides.
    [Fact]
    public void Parity_OverTheMechanismFixture_ComparesEveryKind_AndEveryCapability()
    {
        var findings = mechanism.Findings.Where(f => comparedKinds.Contains(f.Kind)).ToArray();
        var graphTriples = GraphTriples(MechanismGraphSource.Graph);

        Assert.Equal(comparedKinds, comparedKinds.Where(k => findings.Any(f => f.Kind == k)));
        Assert.Equal(
            new[]
            {
                Capability.FileSystem, Capability.Network, Capability.ProcessExecution, Capability.EnvironmentProbe, Capability.NativeInterop,
                Capability.DynamicCodeLoading, Capability.ReflectionInvocation,
            }.Order(),
            graphTriples.Select(t => t.Capability).Distinct().Order());
        // The graph side draws on four edge kinds for its sink edges (no own Ldvirtftn of a capability in the fixture).
        Assert.Equal(
            [MethodEdgeKind.Call, MethodEdgeKind.CallVirt, MethodEdgeKind.NewObj, MethodEdgeKind.Ldftn],
            SinkEdges(MechanismGraphSource.Graph).Select(e => e.Kind).Distinct().Order());
    }

    // ADR 0037 decision 9 at the capability level: with every own method a root, the capabilities reached over all roots
    // are exactly the scanner's, for the compared kinds.
    [Fact]
    public void Parity_OverTheMechanismFixture_TheCapabilitiesReachedOverAllRoots_AreTheScanners()
    {
        var reached = Reachability.Analyze(MechanismGraphSource.Graph).Reaches.Select(r => r.Capability).OfType<Capability>().Distinct().Order();
        var scanned = mechanism.Findings.Where(f => comparedKinds.Contains(f.Kind)).Select(f => f.Capability).Distinct().Order();

        Assert.Equal(scanned, reached);
    }

    // ---------------------------------------------------------------------------------------------------
    // The shadow fixture: the NameShadowed gap, shown real
    // ---------------------------------------------------------------------------------------------------

    // ShadowFixture defines its own System.Environment.GetEnvironmentVariable. The scanner classifies the call to it as
    // EnvironmentProbe by name; the graph resolves it to the own method and walks its benign body. That is the one gap,
    // counted; the call to the real platform method is on both sides.
    [Fact]
    public void Parity_OverTheShadowFixture_DiffersExactlyByTheNameShadowedGap()
    {
        using var assembly = Load(ShadowFixtureAssembly.Path);
        var findings = Scan(assembly);

        var comparison = Compare(ScannerTriples(findings), shadow.Graph);

        AssertParity(comparison, new Dictionary<string, int>(StringComparer.Ordinal) { [NameShadowed] = 1 });
        Assert.Equal(
            [new Triple("ShadowFixture.Callers.ReadsShadowEnvironment", Capability.EnvironmentProbe, "System.Environment.GetEnvironmentVariable")],
            comparison.Gaps[NameShadowed]);
        Assert.Contains(new Triple("ShadowFixture.Callers.ReadsPlatformEnvironment", Capability.EnvironmentProbe, "System.Environment.GetEnvironmentVariable"), comparison.Matched);
        // The graph's own record of the collision, at the caller of the real platform method.
        Assert.Contains(shadow.Graph.Opacities, o => o.Kind == OpacityKind.NameShadowed && o.Site == "ShadowFixture.Callers.ReadsPlatformEnvironment()");
    }

    // S3 review N1: a scanner-only triple is NameShadowed only when the graph has a call-site edge from that caller to an
    // own node keyed as the callee. Another caller's call to the shadow does not explain it, and neither does an own node
    // of that name alone: App.Lone's triple stays unexplained.
    [Fact]
    public void NameShadowed_NeedsACallSiteEdgeFromThatCallerToTheOwnNamesake()
    {
        const string shadowId = "System.Environment.GetEnvironmentVariable(System.String)";
        const string shadowKey = "System.Environment.GetEnvironmentVariable";
        var graph = MethodGraph.FromParts(
            [
                new MethodNode("App.Calls()", "App.Calls", MethodNodeKind.OwnWithBody),
                new MethodNode("App.Lone()", "App.Lone", MethodNodeKind.OwnWithBody),
                new MethodNode("App.Token()", "App.Token", MethodNodeKind.OwnWithBody),
                new MethodNode(shadowId, shadowKey, MethodNodeKind.OwnWithBody),
            ],
            [new MethodEdge("App.Calls()", shadowId, MethodEdgeKind.Call, 1), new MethodEdge("App.Token()", shadowId, MethodEdgeKind.LoadToken, 2)],
            [], complete, GraphFacts.None);
        HashSet<Triple> scanner =
        [
            new("App.Calls", Capability.EnvironmentProbe, shadowKey),
            new("App.Lone", Capability.EnvironmentProbe, shadowKey),
            new("App.Token", Capability.EnvironmentProbe, shadowKey),
        ];

        var comparison = Compare(scanner, graph);

        Assert.Equal([new Triple("App.Calls", Capability.EnvironmentProbe, shadowKey)], comparison.Gaps[NameShadowed]);
        // A LoadToken edge is no call site, so it explains nothing either.
        Assert.Equal(
            [new Triple("App.Lone", Capability.EnvironmentProbe, shadowKey), new Triple("App.Token", Capability.EnvironmentProbe, shadowKey)],
            comparison.ScannerOnly);
        Assert.Empty(comparison.GraphOnly);
    }

    // ---------------------------------------------------------------------------------------------------
    // The keying, pinned
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("System.Environment.GetEnvironmentVariable", "System.Environment.GetEnvironmentVariable")]
    [InlineData("System.Linq.Expressions.Expression<System.Func<System.String>>.Compile", "System.Linq.Expressions.Expression.Compile")]
    [InlineData("System.Collections.Generic.Dictionary<System.String,System.Collections.Generic.List<System.Int32>>.Add", "System.Collections.Generic.Dictionary.Add")]
    [InlineData("System.IO.FileInfo..ctor", "System.IO.FileInfo..ctor")]
    [InlineData("MechanismFixture.Lambda.LinqCase.<>c.<CountsSetVariables>b__0_0", "MechanismFixture.Lambda.LinqCase.<>c.<CountsSetVariables>b__0_0")]
    [InlineData("A.<<Run>b__0_0>d.MoveNext", "A.<<Run>b__0_0>d.MoveNext")]
    [InlineData("A.Box<System.Int32>.<Wraps>b__0", "A.Box.<Wraps>b__0")]
    public void ScannerKey_DropsGenericArgumentLists_ButNotCompilerGeneratedNames(string rendered, string expected)
    {
        Assert.Equal(expected, ScannerKey(rendered));
    }

    // ---------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------

    private static void AssertParity(Comparison comparison, IReadOnlyDictionary<string, int> expectedGaps)
    {
        Assert.True(comparison.ScannerOnly.Count == 0 && comparison.GraphOnly.Count == 0,
            $"Scanner only:{Environment.NewLine}{string.Join(Environment.NewLine, comparison.ScannerOnly)}{Environment.NewLine}" +
            $"Graph only:{Environment.NewLine}{string.Join(Environment.NewLine, comparison.GraphOnly)}");
        Assert.Equal(expectedGaps.OrderBy(g => g.Key, StringComparer.Ordinal), comparison.Gaps.Select(g => KeyValuePair.Create(g.Key, g.Value.Count)).OrderBy(g => g.Key, StringComparer.Ordinal));
        Assert.NotEmpty(comparison.Matched);
    }

    // Matches the two sides, then sorts each difference into a named gap or leaves it unexplained.
    private static Comparison Compare(IReadOnlySet<Triple> scanner, MethodGraph graph)
    {
        var graphSide = GraphTriples(graph);
        var ownCalls = OwnCallKeys(graph);

        var scannerOnly = scanner.Except(graphSide).Order().ToArray();
        // NameShadowed: the graph resolved this very call to the package's own method of that name, so it has a call-site
        // edge from the caller to an own node keyed as the callee (S3 review N1: an own node of that name alone is not enough).
        var shadowed = scannerOnly.Where(t => t.Callee != NativeCallee && ownCalls.Contains((t.Caller, t.Callee))).ToArray();

        return new Comparison(
            [.. scanner.Intersect(graphSide).Order()],
            [.. scannerOnly.Except(shadowed)],
            [.. graphSide.Except(scanner).Order()],
            new Dictionary<string, IReadOnlyList<Triple>>(StringComparer.Ordinal) { [NameShadowed] = shadowed });
    }

    // (caller key, callee key) of every call-site edge from an own node to an own node.
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

    // The call-site edges from an own node to an External node the built-in map classifies as a capability.
    private static IEnumerable<MethodEdge> SinkEdges(MethodGraph graph) =>
        graph.Edges.Where(e => callSiteKinds.Contains(e.Kind)
            && graph.Node(e.From) is { Kind: not MethodNodeKind.External }
            && graph.Node(e.To) is { Kind: MethodNodeKind.External } to
            && Classify(to) is not null);

    private static Capability? Classify(MethodNode node) =>
        CapabilityMap.Default.Classify(node.ClassificationKey) is { Class: CapabilityClass.Capability, Capability: { } capability } ? capability : null;

    // A rendered CCI type or member name with its generic argument lists removed: a '<' that follows a name character
    // opens one; a '<' at the start of a name part (after '.' or another '<') is a compiler-generated name, kept.
    private static string ScannerKey(string rendered)
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

    private static AssemblyAnalyzer Load(string path)
    {
        var result = AssemblyAnalyzer.Load(path);
        return result.IsSuccess ? result.Value : throw new InvalidOperationException($"Failed to load '{path}': {result.Message}", result.Exception);
    }

    private static IReadOnlyList<ApiCallFinding> Scan(AssemblyAnalyzer assembly)
    {
        var result = new CapabilityAnalysis(assembly).Analyze();
        return result.IsSuccess && result.Value.MethodsSkipped == 0
            ? result.Value.Findings
            : throw new InvalidOperationException($"CapabilityAnalysis failed or skipped methods on '{assembly.AssemblyPath}': {result.Message}", result.Exception);
    }
    #endregion

    #region Fields
    /// <summary>The callee key of a NativeImport, on both sides.</summary>
    public const string NativeCallee = "<native import>";

    private const string NameShadowed = "NameShadowed";

    private static readonly GraphCoverage complete = new(new IndexCoverage(0, 0, 0), 0, 0, 0, 0, ResolutionCounts.None, 0, 0, 0, 0, 0, 0, 0, false, null);

    private static readonly ApiCallKind[] comparedKinds = [ApiCallKind.Call, ApiCallKind.Construct, ApiCallKind.MethodPointerLoad, ApiCallKind.NativeImport];

    private static readonly HashSet<MethodEdgeKind> callSiteKinds =
        [MethodEdgeKind.Call, MethodEdgeKind.CallVirt, MethodEdgeKind.NewObj, MethodEdgeKind.Ldftn, MethodEdgeKind.Ldvirtftn];

    private readonly MechanismFixtureFixture mechanism;
    private readonly ShadowMethodGraphFixture shadow;
    #endregion

    #region Child types
    /// <summary>One capability use: who, what capability, through which API.</summary>
    public sealed record Triple(string Caller, Capability Capability, string Callee) : IComparable<Triple>
    {
        public int CompareTo(Triple? other) =>
            other is null ? 1
            : string.CompareOrdinal(Caller, other.Caller) is var a && a != 0 ? a
            : Capability.CompareTo(other.Capability) is var b && b != 0 ? b
            : string.CompareOrdinal(Callee, other.Callee);

        public override string ToString() => $"{Caller} -[{Capability}]-> {Callee}";
    }

    /// <summary>The triples both sides have, those only one has, and the named gaps the scanner-only ones fall into.</summary>
    private sealed record Comparison(
        IReadOnlyList<Triple> Matched,
        IReadOnlyList<Triple> ScannerOnly,
        IReadOnlyList<Triple> GraphOnly,
        IReadOnlyDictionary<string, IReadOnlyList<Triple>> Gaps);
    #endregion
}
