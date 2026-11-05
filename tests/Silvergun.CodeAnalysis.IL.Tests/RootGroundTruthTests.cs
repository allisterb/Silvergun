namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <see cref="RootGroundTruth"/> (reachability R1, S3; acceptance criterion 5) asserted against
/// <see cref="Reachability.Analyze"/> over the real mechanism-fixture graph (<see cref="MechanismGraphSource.Graph"/>,
/// built-in map). Each row's root is analysed alone: every other own method's classes are cleared, so the report's rows
/// are that one root's, while every node, edge, opacity, liveness and NativeImport fact stays. The strongest tier is read
/// from the row's counts (Bound, then Instantiated, then ChaOnly) and checked against its one example path. Also pinned
/// here: the table's own consistency, and the premises the rows rest on (the host stubs stay external, the new fixture
/// methods carry the classes the S1.2 rules give them, the tier cases' types are live or dead as intended).
/// </summary>
public sealed class RootGroundTruthTests
{
    #region Methods
    public static TheoryData<string> RowIds()
    {
        var data = new TheoryData<string>();
        foreach (var row in RootGroundTruth.Rows)
            data.Add(row.Id);
        return data;
    }

    // ---------------------------------------------------------------------------------------------------
    // The rows
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(RowIds))]
    public void RootRow_HoldsInTheReachabilityReport(string id)
    {
        var row = RootGroundTruth.Rows.Single(r => r.Id == id);
        var graph = MechanismGraphSource.Graph;
        var root = Root(graph, row);
        Assert.True(root.Roots.HasFlag(row.Class), $"{row.Id}: {root.NodeId} is {root.Roots}, not {row.Class}. Note: {row.Note}");

        var report = Reachability.Analyze(Alone(graph, root.NodeId));
        var reaches = report.Reaches.Where(r => r.Class == row.Class).ToArray();
        var rendered = string.Join("; ", reaches.Select(r => $"{r.Capability?.ToString() ?? "Unseen"} {r.Roots}/{r.Instantiated}/{r.Bound}"));

        switch (row.Expect)
        {
            case Expectation.Present or Expectation.KnownImprecision:
            {
                var reach = reaches.SingleOrDefault(r => r.Capability == row.Capability);
                Assert.True(reach is not null, $"{row.Id}: {root.NodeId} does not reach {row.Capability} as {row.Class}. Reaches: [{rendered}]. Note: {row.Note}");
                Assert.Equal(1, reach.Roots);
                var strongest = reach.Bound > 0 ? ReachEvidence.Bound : reach.Instantiated > 0 ? ReachEvidence.Instantiated : ReachEvidence.ChaOnly;
                Assert.True(row.Strongest == strongest, $"{row.Id}: strongest tier {strongest}, expected {row.Strongest}. Note: {row.Note}");
                var path = Assert.Single(reach.Examples);
                Assert.Equal((root.NodeId, strongest), (path.Root, path.Evidence));
                Assert.Equal(row.Capability, SinkCapability(graph, path.Hops[^1].NodeId));
                break;
            }
            case Expectation.Absent:
                Assert.True(
                    !reaches.Any(r => r.Capability is { } c && (row.Capability is null || c == row.Capability)),
                    $"{row.Id}: expected {root.NodeId} to reach no {row.Capability?.ToString() ?? "capability"} as {row.Class}. Reaches: [{rendered}]. Note: {row.Note}");
                break;
            default:
                throw new InvalidOperationException($"{row.Id}: {row.Expect} is not a root-row expectation.");
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // The table itself
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Table_IdsAreUnique_AndEveryRowHasANote()
    {
        Assert.Equal(RootGroundTruth.Rows.Count, RootGroundTruth.Rows.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.All(RootGroundTruth.Rows, r => Assert.False(string.IsNullOrWhiteSpace(r.Note), r.Id));
    }

    // Absent has no tier; every other row a capability and a tier. Each row is about exactly one class.
    [Fact]
    public void Table_RowShapesMatchTheirExpectation()
    {
        Assert.All(RootGroundTruth.Rows, r =>
        {
            Assert.True(r.Class != RootClass.None && (r.Class & (r.Class - 1)) == 0, $"{r.Id}: {r.Class} is not a single class.");
            Assert.True(r.Expect is Expectation.Present or Expectation.Absent or Expectation.KnownImprecision, $"{r.Id}: {r.Expect}");
            if (r.Expect == Expectation.Absent)
                Assert.True(r.Strongest is null, $"{r.Id}: an Absent row has no tier.");
            else
                Assert.True(r.Capability is not null && r.Strongest is not null, $"{r.Id}: a reaching row names its capability and tier.");
        });
    }

    // Every interesting row has its Absent twin, of the same class; and every Absent row is someone's twin.
    [Fact]
    public void Table_EveryRowHasAnAbsentTwinOfTheSameClass()
    {
        var byId = RootGroundTruth.Rows.ToDictionary(r => r.Id, StringComparer.Ordinal);
        var interesting = RootGroundTruth.Rows.Where(r => r.Expect != Expectation.Absent).ToArray();

        Assert.All(interesting, r =>
        {
            Assert.True(byId.TryGetValue(r.Id + RootGroundTruth.TwinSuffix, out var twin), $"{r.Id} has no twin {r.Id}{RootGroundTruth.TwinSuffix}.");
            Assert.Equal((Expectation.Absent, r.Class), (twin!.Expect, twin.Class));
        });
        Assert.Equal(
            interesting.Select(r => r.Id + RootGroundTruth.TwinSuffix).Order(StringComparer.Ordinal),
            RootGroundTruth.Rows.Where(r => r.Expect == Expectation.Absent).Select(r => r.Id).Order(StringComparer.Ordinal));
    }

    // Coverage of the design space: a reaching row for every single root class and for every evidence tier.
    [Fact]
    public void Table_CoversEveryRootClassAndEveryEvidenceTier()
    {
        var reaching = RootGroundTruth.Rows.Where(r => r.Expect != Expectation.Absent).ToArray();

        Assert.Equal(allClasses, allClasses.Where(c => reaching.Any(r => r.Class == c)));
        Assert.Equal(Enum.GetValues<ReachEvidence>(), Enum.GetValues<ReachEvidence>().Where(e => reaching.Any(r => r.Strongest == e)));
    }

    // Each root regex names exactly one own node of the graph (never vacuous), and no two rows share a root.
    [Fact]
    public void Table_EveryRootRegexNamesExactlyOneOwnNode()
    {
        var graph = MechanismGraphSource.Graph;
        var problems = RootGroundTruth.Rows
            .Select(r => (r.Id, Matches: graph.Facts.Methods.Count(f => new Regex(r.RootRegex).IsMatch(f.NodeId))))
            .Where(m => m.Matches != 1)
            .Select(m => $"{m.Id}: {m.Matches} matches")
            .ToArray();

        Assert.True(problems.Length == 0, string.Join(Environment.NewLine, problems));
        Assert.Equal(RootGroundTruth.Rows.Count, RootGroundTruth.Rows.Select(r => Root(graph, r).NodeId).Distinct(StringComparer.Ordinal).Count());
    }

    // ---------------------------------------------------------------------------------------------------
    // Premises
    // ---------------------------------------------------------------------------------------------------

    // The host stubs are copied beside the fixture but never indexed: no own node is theirs, and every type they declare
    // is a built-in host-contract entry, by its classification key.
    [Fact]
    public void Premise_TheHostStubsAreNotIndexed_AndDeclareExactlyBuiltInHostContracts()
    {
        var graph = MechanismGraphSource.Graph;
        var stubTypes = PublicTypeKeys(MechanismFixtureAssemblies.HostStubs);

        Assert.Equal(["Microsoft.Build.Framework.ITask", "Microsoft.CodeAnalysis.Diagnostics.DiagnosticAnalyzer"], stubTypes);
        Assert.All(stubTypes, t => Assert.Contains(t, CapabilityMap.Default.HostContracts));
        Assert.All(graph.Facts.Methods, f => Assert.NotEqual(MechanismFixtureAssemblies.HostStubsName, f.Assembly));
        Assert.DoesNotContain(graph.Facts.Types, t => stubTypes.Contains(t.TypeId));
        Assert.DoesNotContain(graph.Nodes, n => n.Kind != MethodNodeKind.External && n.NodeId.StartsWith("Microsoft.", StringComparison.Ordinal));
        Assert.Equal(
            [MechanismFixtureAssemblies.FixtureName, MechanismFixtureAssemblies.DebugFixtureName, MechanismFixtureAssemblies.DependencyName],
            graph.Facts.Methods.Select(f => f.Assembly).Distinct().Order(StringComparer.Ordinal));
        Assert.DoesNotContain(AppDomain.CurrentDomain.GetAssemblies(), a => a.GetName().Name == MechanismFixtureAssemblies.HostStubsName);
    }

    // The S1.2 rules on the new fixture methods: an exact mask where only one rule can apply, a flag where another may.
    [Theory]
    [InlineData("Roots.Visibility.Unreached.ReadsEnv()", RootClass.Hidden)]
    [InlineData("Roots.Visibility.UnreachedSafe.ReadsSafe()", RootClass.Hidden)]
    [InlineData("Roots.Visibility.NetResolver.MechanismFixture.Roots.Visibility.IResolver.Resolve()", RootClass.PublicApi)]
    [InlineData("Roots.Visibility.EnvGauge.Read()", RootClass.PublicContract)]
    [InlineData("Roots.Visibility.SafeGauge.Read()", RootClass.PublicContract)]
    [InlineData("Roots.Visibility.EnvLabel.ToString()", RootClass.PublicContract)]
    [InlineData("Roots.Visibility.SafeLabel.ToString()", RootClass.PublicContract)]
    [InlineData("Roots.Visibility.Gauges.Create()", RootClass.PublicApi)]
    [InlineData("Roots.Host.EnvTask.Execute()", RootClass.HostContract | RootClass.PublicApi)]
    [InlineData("Roots.Host.EnvAnalyzer..ctor()", RootClass.HostContract | RootClass.PublicApi)]
    [InlineData("Roots.Host.EnvAnalyzer.Initialize(System.Object)", RootClass.HostContract | RootClass.PublicApi)]
    [InlineData("Roots.Runtime.Exports.ExportsEnv()", RootClass.RuntimeInvoked | RootClass.PublicApi)]
    [InlineData("Roots.Tiers.UnmadeProbe.Run()", RootClass.Hidden)]
    [InlineData("Roots.Tiers.MadeProbe.Run()", RootClass.Hidden)]
    [InlineData("Roots.Tiers.Callers.CallsUnmade(System.Object)", RootClass.PublicApi)]
    public void Premise_TheNewFixtureMethods_CarryExactlyTheirRuleClasses(string method, RootClass expected)
    {
        Assert.Equal(expected, Facts(MechanismGraphSource.Graph, Fixture(method)).Roots);
    }

    // A protected finalizer of a sealed public type is no PublicApi (Family on a sealed type), but it is RuntimeInvoked.
    [Theory]
    [InlineData("Roots.Runtime.EnvFinalized.Finalize()")]
    [InlineData("Roots.Runtime.SafeFinalized.Finalize()")]
    public void Premise_AFinalizer_IsRuntimeInvoked_AndNoPublicApi(string method)
    {
        var roots = Facts(MechanismGraphSource.Graph, Fixture(method)).Roots;

        Assert.True(roots.HasFlag(RootClass.RuntimeInvoked) && !roots.HasFlag(RootClass.PublicApi), roots.ToString());
    }

    // The tier cases' types: UnmadeProbe is dead (internal, never newobj'd), MadeProbe live only by its newobj, and
    // EnvProbe live (newobj'd and publicly constructible).
    [Theory]
    [InlineData("Roots.Tiers.UnmadeProbe", false)]
    [InlineData("Roots.Tiers.UnmadeSafeProbe", false)]
    [InlineData("Roots.Tiers.MadeProbe", true)]
    [InlineData("Roots.Tiers.MadeSafeProbe", true)]
    [InlineData("Interface.EnvProbe", true)]
    public void Premise_TheTierCasesTypes_AreLiveOrDeadAsIntended(string type, bool live)
    {
        Assert.Equal(live, Assert.Single(MechanismGraphSource.Graph.Facts.Types, t => t.TypeId == Fixture(type)).Live);
    }

    // The ChaOnly case's only way to the sink is the Dispatch edge: its castclass names no method, and its callvirt
    // reaches the bodyless interface slot.
    [Fact]
    public void Premise_TheChaOnlyCase_ReachesItsImplementorOnlyByDispatch()
    {
        var graph = MechanismGraphSource.Graph;

        Assert.Equal(
            [(MethodEdgeKind.CallVirt, Fixture("Roots.Tiers.IUnmade.Run()")), (MethodEdgeKind.Dispatch, Fixture("Roots.Tiers.UnmadeProbe.Run()"))],
            graph.Successors(Fixture("Roots.Tiers.Callers.CallsUnmade(System.Object)")).Select(e => (e.Kind, e.To)));
        Assert.Equal(MethodNodeKind.OwnBodyless, graph.Node(Fixture("Roots.Tiers.IUnmade.Run()"))?.Kind);
    }

    // The mechanism fixture declares no internalcall, so no own node, abstract or interface ones included, is one.
    [Fact]
    public void Premise_TheMechanismFixtureHasNoInternalCall()
    {
        var graph = MechanismGraphSource.Graph;

        Assert.Contains(graph.Nodes, n => n.NodeId == Fixture("Roots.Tiers.IUnmade.Run()") && n.Kind == MethodNodeKind.OwnBodyless);
        Assert.Empty(graph.Facts.Methods.Where(f => f.InternalCall).Select(f => f.NodeId));
    }

    // ---------------------------------------------------------------------------------------------------
    // The whole graph
    // ---------------------------------------------------------------------------------------------------

    // Analysed whole, every root class reaches a capability: HostContract and RuntimeInvoked are no longer empty classes.
    [Fact]
    public void WholeGraph_EveryRootClassHasRoots_AndReachesACapability()
    {
        var report = Reachability.Analyze(MechanismGraphSource.Graph);

        Assert.False(report.Partial, report.PartialReason);
        Assert.All(allClasses, c =>
        {
            Assert.True(Assert.Single(report.Classes, s => s.Class == c).Roots > 0, $"{c} has no roots");
            Assert.Contains(report.Reaches, r => r.Class == c && r.Capability is not null);
        });
    }
    #endregion

    #region Helpers
    // The single own method a row's root regex names.
    private static OwnMethodFacts Root(MethodGraph graph, RootPath row)
    {
        var pattern = new Regex(row.RootRegex);
        var matches = graph.Facts.Methods.Where(f => pattern.IsMatch(f.NodeId)).ToArray();
        return matches.Length == 1 ? matches[0] : throw new InvalidOperationException($"{row.Id}: {row.RootRegex} names {matches.Length} own nodes, not one.");
    }

    // graph with only root's classes kept: every other own method stays a node with its facts, in no class.
    private static MethodGraph Alone(MethodGraph graph, string root) =>
        MethodGraph.FromParts(graph.Nodes, graph.Edges, graph.Opacities, graph.Coverage,
            graph.Facts with { Methods = [.. graph.Facts.Methods.Select(f => f.NodeId == root ? f : f with { Roots = RootClass.None })] });

    // The capability a sink node stands for: the map's for an External node, NativeInterop for an own P/Invoke.
    private static Capability? SinkCapability(MethodGraph graph, string nodeId) =>
        graph.Node(nodeId) switch
        {
            { Kind: MethodNodeKind.External } n => CapabilityMap.Default.Classify(n.ClassificationKey) is { Class: CapabilityClass.Capability } v ? v.Capability : null,
            { } => graph.Facts.Methods.Any(f => f.NodeId == nodeId && f.NativeImport) ? Capability.NativeInterop : null,
            null => null,
        };

    private static OwnMethodFacts Facts(MethodGraph graph, string nodeId) =>
        graph.Facts.Methods.SingleOrDefault(f => f.NodeId == nodeId) ?? throw new InvalidOperationException($"No facts for '{nodeId}'.");

    private static string Fixture(string idWithoutRoot) => $"{MechanismGroundTruth.RootNamespace}.{idWithoutRoot}";

    // The classification keys of the public types an assembly defines, read as metadata only (never indexed or loaded).
    private static string[] PublicTypeKeys(string path)
    {
        using var stream = File.OpenRead(path);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();
        return [.. metadata.TypeDefinitions
            .Select(metadata.GetTypeDefinition)
            .Where(t => (t.Attributes & System.Reflection.TypeAttributes.VisibilityMask) == System.Reflection.TypeAttributes.Public)
            .Select(t => $"{metadata.GetString(t.Namespace)}.{metadata.GetString(t.Name)}")
            .Order(StringComparer.Ordinal)];
    }
    #endregion

    #region Fields
    private static readonly RootClass[] allClasses =
        [RootClass.LoadTime, RootClass.HostContract, RootClass.RuntimeInvoked, RootClass.PublicApi, RootClass.PublicContract, RootClass.Hidden];
    #endregion
}
