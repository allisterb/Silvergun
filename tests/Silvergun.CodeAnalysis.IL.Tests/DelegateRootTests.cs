namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Reachability R2b, S1 (docs/agent/tasks/reachability-r2b.md, "S1 tests"; ADR 0037 amendment a1/a2) over the real graph
/// of <c>DelegateRootFixture</c>, indexed alone with the built-in map.
/// <para>
/// <b>Acceptance criterion 2:</b> a type initializer that only creates a delegate to its payload, and hands it to
/// <c>Task.Run</c>, a <c>Thread</c>, a <c>Timer</c>, <c>AssemblyLoadContext.Resolving</c> or an own helper, reports the
/// payload's capability at <see cref="RootClass.TypeInitializer"/>, without the Direct label, and the class never reads
/// <see cref="RootClassVerdict.None"/>. So does one that only builds an expression tree over it (an <c>ldtoken</c>, a
/// <see cref="MethodEdgeKind.LoadToken"/> edge; review W3). Each has a benign twin of the same shape. A control initializer calling the
/// capability itself is Direct. The finalizer and the <c>[UnmanagedCallersOnly]</c> export are their own classes,
/// each only on its own members.
/// </para>
/// A case is analysed alone (every other own method's classes cleared), so a row is that one root's.
/// </summary>
public sealed class DelegateRootTests
{
    #region Methods
    public static TheoryData<string, Capability> Scheduled() => new()
    {
        { "ViaTaskRun", Capability.FileSystem },
        { "ViaThread", Capability.FileSystem },
        { "ViaTimer", Capability.Network },
        { "ViaResolving", Capability.FileSystem },
        { "ViaHelper", Capability.FileSystem },
    };

    // ---------------------------------------------------------------------------------------------------
    // Premises
    // ---------------------------------------------------------------------------------------------------

    // Read as metadata only: never loaded here, so no initializer ran. The graph is whole and the assembly has no gap.
    [Fact]
    public void Premise_TheFixtureIsNeverLoaded_AndItsGraphIsCompleteWithNoGap()
    {
        Assert.DoesNotContain(AppDomain.CurrentDomain.GetAssemblies(), a => a.GetName().Name == DelegateRootFixtureAssembly.Name);
        Assert.False(Graph.Coverage.Truncated);
        Assert.Empty(Graph.Facts.Gaps);
    }

    // Each scheduled initializer and its twin really create a delegate to their own payload (an Ldftn edge) and do not
    // call it: the payload is reached by the Ldftn alone.
    [Theory]
    [MemberData(nameof(Scheduled))]
    public void Premise_EachScheduledInitializerAndItsTwin_CreateADelegateToTheirPayload_AndNeverCallIt(string type, Capability capability)
    {
        _ = capability;
        foreach (var t in new[] { type, type + "Safe" })
        {
            var payload = Assert.Single(Graph.Facts.Methods, f => f.NodeId.StartsWith($"{ScheduledNamespace}.{t}.Payload(", StringComparison.Ordinal)).NodeId;

            Assert.Equal([MethodEdgeKind.Ldftn], Graph.Edges.Where(e => e.To == payload).Select(e => e.Kind));
            Assert.Equal(Cctor(t), Assert.Single(Graph.Edges, e => e.To == payload).From);
        }
    }

    // The expression-tree initializer and its twin really hold an ldtoken of their own payload in their IL, read from the
    // file's bytes (System.Reflection.Metadata, not the model), and neither calls nor ldftns it; in the graph that is one
    // LoadToken edge from the .cctor, the payload's only incoming edge.
    [Theory]
    [InlineData("ViaExpressionTree")]
    [InlineData("ViaExpressionTreeSafe")]
    public void Premise_TheExpressionTreeInitializerAndItsTwin_LoadATokenOfTheirPayload_AndNeverCallIt(string type)
    {
        using var pe = new PEReader(File.OpenRead(DelegateRootFixtureAssembly.Path));
        var md = pe.GetMetadataReader();
        var definition = md.TypeDefinitions.Select(md.GetTypeDefinition).Single(t => md.GetString(t.Namespace) == TokensNamespace && md.GetString(t.Name) == type);
        MethodDefinitionHandle Method(string name) => definition.GetMethods().Single(h => md.GetString(md.GetMethodDefinition(h).Name) == name);
        var il = pe.GetMethodBody(md.GetMethodDefinition(Method(".cctor")).RelativeVirtualAddress).GetILBytes()!;
        var token = BitConverter.GetBytes(MetadataTokens.GetToken(Method("Payload")));
        bool Has(params byte[] opcode)
        {
            byte[] pattern = [.. opcode, .. token];
            return Enumerable.Range(0, il.Length - pattern.Length + 1).Any(i => il[i..(i + pattern.Length)].SequenceEqual(pattern));
        }

        Assert.True(Has(0xD0), $"{type}..cctor holds no ldtoken of its Payload");   // ldtoken <Payload>
        Assert.False(Has(0x28) || Has(0x6F) || Has(0xFE, 0x06) || Has(0xFE, 0x07));   // call, callvirt, ldftn, ldvirtftn
        var payload = Assert.Single(Graph.Facts.Methods, f => f.NodeId.StartsWith($"{TokensNamespace}.{type}.Payload(", StringComparison.Ordinal)).NodeId;
        var edge = Assert.Single(Graph.Edges, e => e.To == payload);
        Assert.Equal((TokenCctor(type), MethodEdgeKind.LoadToken), (edge.From, edge.Kind));
    }

    // ---------------------------------------------------------------------------------------------------
    // Adversarial method-handle initializer (review W3)
    // ---------------------------------------------------------------------------------------------------

    // The payload's capability, at TypeInitializer, Bound (a LoadToken edge is in every tier), but not Direct: the method
    // handle only runs if the tree is compiled and invoked later. The example goes through the LoadToken hop.
    [Fact]
    public void ExpressionTreeInitializer_ReachesThePayloadsCapability_AtTypeInitializer_NotDirect()
    {
        var cctor = TokenCctor("ViaExpressionTree");
        Assert.Equal(RootClass.TypeInitializer, Facts(cctor).Roots);

        var report = Reachability.Analyze(Alone(cctor));

        var row = Row(report, RootClass.TypeInitializer, Capability.FileSystem);
        Assert.Equal((1, 1, 1, 0), (row.Roots, row.Bound, row.Instantiated, row.Direct));
        var path = Assert.Single(row.Examples);
        Assert.Equal((cctor, ReachEvidence.Bound, false), (path.Root, path.Evidence, path.Direct));
        Assert.Equal([null, MethodEdgeKind.LoadToken, MethodEdgeKind.Call], path.Hops.Select(h => h.Via));
        var profile = Assert.Single(report.Profiles, p => p.Class == RootClass.TypeInitializer);
        Assert.Contains(Capability.FileSystem, profile.Capabilities);
        Assert.DoesNotContain(Capability.FileSystem, profile.DirectCapabilities);
        Assert.NotEqual(RootClassVerdict.None, Status(report, RootClass.TypeInitializer).Verdict);
    }

    // Twin: the same shape over a benign payload reaches neither payload capability.
    [Fact]
    public void ExpressionTreeInitializerTwin_ReachesNoPayloadCapability()
    {
        var report = Reachability.Analyze(Alone(TokenCctor("ViaExpressionTreeSafe")));

        Assert.DoesNotContain(report.Reaches, r => r.Capability is Capability.FileSystem or Capability.Network);
    }

    // ---------------------------------------------------------------------------------------------------
    // Adversarial delegate initializers (acceptance criterion 2)
    // ---------------------------------------------------------------------------------------------------

    // The payload's capability, at TypeInitializer, Bound (the Ldftn is in every tier) but not Direct: no Direct root,
    // the one example path goes through the delegate creation, and the profile lists it outside the Direct set.
    [Theory]
    [MemberData(nameof(Scheduled))]
    public void ScheduledInitializer_ReachesThePayloadsCapability_AtTypeInitializer_NotDirect(string type, Capability capability)
    {
        var cctor = Cctor(type);
        Assert.Equal(RootClass.TypeInitializer, Facts(cctor).Roots);   // the premise: the initializer is that class only

        var report = Reachability.Analyze(Alone(cctor));

        var row = Row(report, RootClass.TypeInitializer, capability);
        Assert.Equal((1, 1, 1, 0), (row.Roots, row.Bound, row.Instantiated, row.Direct));
        var path = Assert.Single(row.Examples);
        Assert.Equal((cctor, ReachEvidence.Bound, false), (path.Root, path.Evidence, path.Direct));
        Assert.Contains(path.Hops, h => h.Via is MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn);
        var profile = Assert.Single(report.Profiles, p => p.Class == RootClass.TypeInitializer);
        Assert.Contains(capability, profile.Capabilities);
        Assert.DoesNotContain(capability, profile.DirectCapabilities);
    }

    // ...and the class is never None: it reaches something, so a delegate is no way to read as clean.
    [Theory]
    [MemberData(nameof(Scheduled))]
    public void ScheduledInitializer_TheTypeInitializerVerdict_IsNeverNone(string type, Capability capability)
    {
        _ = capability;
        var report = Reachability.Analyze(Alone(Cctor(type)));

        var status = Status(report, RootClass.TypeInitializer);
        Assert.NotEqual(RootClassVerdict.None, status.Verdict);
        Assert.Equal(1, status.Roots);
    }

    // Twin: the same shape with a benign payload reaches neither payload capability, at any class.
    [Theory]
    [MemberData(nameof(Scheduled))]
    public void ScheduledInitializerTwin_ReachesNoPayloadCapability(string type, Capability capability)
    {
        _ = capability;
        var report = Reachability.Analyze(Alone(Cctor(type + "Safe")));

        Assert.DoesNotContain(report.Reaches, r => r.Capability is Capability.FileSystem or Capability.Network);
    }

    // Control: the initializer calling File.Exists itself is Direct: one Direct root, a Direct example with no delegate
    // hop, and the capability in the profile's Direct set.
    [Fact]
    public void DirectInitializer_ReachesFileSystem_Direct()
    {
        var cctor = Cctor("WithoutDelegate");
        var report = Reachability.Analyze(Alone(cctor));

        var row = Row(report, RootClass.TypeInitializer, Capability.FileSystem);
        Assert.Equal((1, 1, 1), (row.Roots, row.Bound, row.Direct));
        var path = Assert.Single(row.Examples);
        Assert.Equal((ReachEvidence.Bound, true, 2), (path.Evidence, path.Direct, path.Length));
        Assert.DoesNotContain(path.Hops, h => h.Via is MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn);
        Assert.Equal([Capability.FileSystem], Assert.Single(report.Profiles, p => p.Class == RootClass.TypeInitializer).DirectCapabilities);
        Assert.Equal(RootClassVerdict.Reaches, Status(report, RootClass.TypeInitializer).Verdict);
    }

    [Fact]
    public void DirectInitializerTwin_ReachesNothing()
    {
        Assert.Empty(Reachability.Analyze(Alone(Cctor("WithoutDelegateSafe"))).Reaches);
    }

    // The whole fixture: FileSystem is reached by six initializers (the four scheduled ones, the helper's and the
    // expression tree's), only one of them Direct, and that one leads the examples although it sorts last of the
    // Scheduled ones by node id (evidence, then Direct, then length, then node order; the Tokens one sorts after them).
    // Network by the Timer's alone, not Direct.
    [Fact]
    public void WholeFixture_TypeInitializer_CountsDirectRootsApart_AndPutsTheDirectExampleFirst()
    {
        var report = Reachability.Analyze(Graph);

        Assert.False(report.Partial, report.PartialReason);
        var fileSystem = Row(report, RootClass.TypeInitializer, Capability.FileSystem);
        Assert.Equal((6, 6, 1), (fileSystem.Roots, fileSystem.Bound, fileSystem.Direct));
        Assert.Equal([(Cctor("WithoutDelegate"), true), (Cctor("ViaHelper"), false), (Cctor("ViaResolving"), false)], fileSystem.Examples.Select(e => (e.Root, e.Direct)));
        var network = Row(report, RootClass.TypeInitializer, Capability.Network);
        Assert.Equal((1, 0), (network.Roots, network.Direct));
        Assert.Equal(RootClassVerdict.Reaches, Status(report, RootClass.TypeInitializer).Verdict);
    }

    // The long-named probe (three parameters of a 450-char type) is the one name the whole fixture's report cuts: NamesCut
    // 1, and the PublicApi FileSystem row's one example root is its bounded name. The R2b harness test reads the same
    // count through the child.
    [Fact]
    public void WholeFixture_CutsExactlyTheOneLongName()
    {
        var probe = Assert.Single(Graph.Facts.Methods, f => f.NodeId.StartsWith("DelegateRootFixture.LongNames.Probe.Exists(", StringComparison.Ordinal)).NodeId;
        Assert.True(probe.Length > Reachability.MaxNameChars, $"{probe.Length} chars");   // the premise
        Assert.Equal(RootClass.PublicApi, Facts(probe).Roots);

        var report = Reachability.Analyze(Graph);

        Assert.Equal(1, report.NamesCut);
        Assert.Equal(Reachability.BoundName(probe), Assert.Single(Row(report, RootClass.PublicApi, Capability.FileSystem).Examples).Root);
        Assert.DoesNotContain(Graph.Facts.Methods, f => f.NodeId != probe && f.NodeId.Length > Reachability.MaxNameChars);
    }

    // ---------------------------------------------------------------------------------------------------
    // Finalizer and NativeEntry
    // ---------------------------------------------------------------------------------------------------

    // ~T() of an internal sealed type: Finalizer (and PublicContract, Object.Finalize's slot being the platform's), and a
    // Finalizer reach of FileSystem; no TypeInitializer or NativeEntry row.
    [Fact]
    public void Finalizer_AFinalizerReachingACapability_IsAFinalizerReach()
    {
        const string finalize = "DelegateRootFixture.Finalizers.FileFinalized.Finalize()";
        Assert.Equal(RootClass.Finalizer | RootClass.PublicContract, Facts(finalize).Roots);

        var report = Reachability.Analyze(Alone(finalize));

        var row = Row(report, RootClass.Finalizer, Capability.FileSystem);
        Assert.Equal((1, 1, 1), (row.Roots, row.Bound, row.Direct));
        Assert.Equal(finalize, Assert.Single(row.Examples).Root);
        Assert.DoesNotContain(report.Reaches, r => r.Class is RootClass.TypeInitializer or RootClass.NativeEntry);
        Assert.Equal(RootClassVerdict.Reaches, Status(report, RootClass.Finalizer).Verdict);
    }

    [Fact]
    public void Finalizer_TheBenignTwin_ReachesNoCapability()
    {
        const string finalize = "DelegateRootFixture.Finalizers.SafeFinalized.Finalize()";
        Assert.True(Facts(finalize).Roots.HasFlag(RootClass.Finalizer));

        var report = Reachability.Analyze(Alone(finalize));

        Assert.DoesNotContain(report.Reaches, r => r.Capability is not null);
        Assert.Equal(RootClassVerdict.None, Status(report, RootClass.Finalizer).Verdict);
    }

    // An internal [UnmanagedCallersOnly] static: NativeEntry only, and a NativeEntry reach of FileSystem.
    [Fact]
    public void NativeEntry_AnExportReachingACapability_IsANativeEntryReach()
    {
        const string export = "DelegateRootFixture.Exports.NativeExports.ProbesFile()";
        Assert.Equal(RootClass.NativeEntry, Facts(export).Roots);

        var report = Reachability.Analyze(Alone(export));

        var row = Row(report, RootClass.NativeEntry, Capability.FileSystem);
        Assert.Equal((1, 1, 1), (row.Roots, row.Bound, row.Direct));
        Assert.Equal([RootClass.NativeEntry], report.Reaches.Select(r => r.Class).Distinct());
        Assert.Equal(RootClassVerdict.Reaches, Status(report, RootClass.NativeEntry).Verdict);
    }

    [Fact]
    public void NativeEntry_TheBenignTwin_ReachesNoCapability()
    {
        const string export = "DelegateRootFixture.Exports.NativeExports.ProbesNothing()";
        Assert.Equal(RootClass.NativeEntry, Facts(export).Roots);

        var report = Reachability.Analyze(Alone(export));

        Assert.Empty(report.Reaches);
        Assert.Equal(RootClassVerdict.None, Status(report, RootClass.NativeEntry).Verdict);
    }

    // Each runtime class is on exactly its own members: TypeInitializer on the sixteen .cctors, Finalizer on the two
    // Finalize overrides, NativeEntry on the two exports, and no method carries two of them. Four .cctors are the
    // expression-tree types': each type's own, and the compiler's lambda-singleton class <>c's, which only constructs <>c.
    [Fact]
    public void RuntimeClasses_AreEachOnExactlyTheirOwnMembers()
    {
        string[] Of(RootClass cls) => [.. Graph.Facts.Methods.Where(f => f.Roots.HasFlag(cls)).Select(f => f.NodeId)];
        string[] scheduled = ["ViaHelper", "ViaResolving", "ViaTaskRun", "ViaThread", "ViaTimer", "WithoutDelegate"];
        string[] tokens = ["ViaExpressionTree", "ViaExpressionTreeSafe"];

        Assert.Equal(
            scheduled.SelectMany(t => new[] { Cctor(t), Cctor(t + "Safe") }).Concat(tokens.SelectMany(t => new[] { TokenCctor(t), TokenCctor(t + ".<>c") })).Order(StringComparer.Ordinal),
            Of(RootClass.TypeInitializer));
        Assert.All(tokens, t => Assert.Equal([MethodEdgeKind.NewObj], Graph.Edges.Where(e => e.From == TokenCctor(t + ".<>c")).Select(e => e.Kind)));
        Assert.Equal(["DelegateRootFixture.Finalizers.FileFinalized.Finalize()", "DelegateRootFixture.Finalizers.SafeFinalized.Finalize()"], Of(RootClass.Finalizer));
        Assert.Equal(["DelegateRootFixture.Exports.NativeExports.ProbesFile()", "DelegateRootFixture.Exports.NativeExports.ProbesNothing()"], Of(RootClass.NativeEntry));
        Assert.DoesNotContain(Graph.Facts.Methods, f => RuntimeClassCount(f.Roots) > 1);
    }
    #endregion

    #region Helpers
    private static string Cctor(string type) => $"{ScheduledNamespace}.{type}..cctor()";

    private static string TokenCctor(string type) => $"{TokensNamespace}.{type}..cctor()";

    private static int RuntimeClassCount(RootClass roots) =>
        new[] { RootClass.TypeInitializer, RootClass.Finalizer, RootClass.NativeEntry }.Count(c => roots.HasFlag(c));

    // The graph with only root's classes kept: every other own method stays a node with its facts, in no class.
    private static MethodGraph Alone(string root)
    {
        _ = Facts(root);
        return MethodGraph.FromParts(Graph.Nodes, Graph.Edges, Graph.Opacities, Graph.Coverage,
            Graph.Facts with { Methods = [.. Graph.Facts.Methods.Select(f => f.NodeId == root ? f : f with { Roots = RootClass.None })] });
    }

    private static OwnMethodFacts Facts(string nodeId) =>
        Graph.Facts.Methods.SingleOrDefault(f => f.NodeId == nodeId)
            ?? throw new InvalidOperationException($"No facts for '{nodeId}'. Own nodes: {string.Join(", ", Graph.Facts.Methods.Select(f => f.NodeId))}");

    private static CapabilityReach Row(ReachabilityReport report, RootClass cls, Capability? capability) =>
        report.Reaches.SingleOrDefault(r => r.Class == cls && r.Capability == capability)
            ?? throw new InvalidOperationException($"No {cls} × {capability?.ToString() ?? "Unseen"} row. Rows: {string.Join("; ", report.Reaches.Select(r => $"{r.Class} × {r.Capability?.ToString() ?? "Unseen"}"))}");

    private static RootClassStatus Status(ReachabilityReport report, RootClass cls) => Assert.Single(report.Classes, c => c.Class == cls);
    #endregion

    #region Fields
    private const string ScheduledNamespace = "DelegateRootFixture.Scheduled";

    private const string TokensNamespace = "DelegateRootFixture.Tokens";

    // Built once per run; the MethodGraph holds plain strings, so the model is released as soon as it exists.
    private static readonly Lazy<MethodGraph> graph = new(() =>
    {
        using var assemblies = ModelAssemblies.Load(DelegateRootFixtureAssembly.Path);
        return MethodGraph.Build(assemblies.Index());
    });

    private static MethodGraph Graph => graph.Value;
    #endregion
}
