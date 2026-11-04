namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Review 4, <b>C-E</b>: an indexed assembly <c>FwdA</c> can carry an <c>ExportedType</c> row forwarding
/// <c>System.Environment</c> to System.Private.CoreLib AND define a decoy <c>System.Environment.GetEnvironmentVariable</c>
/// (or a nested <c>System+Environment</c> that renders the same node id). A caller in <c>FwdB</c> that references
/// <c>[FwdA]System.Environment::GetEnvironmentVariable</c> runs the PLATFORM method — the CLR follows the forwarder —
/// but <see cref="MemberIndex.Resolve"/> used to answer Exact → the decoy, hiding the sink. Analysis.Net's Model
/// carries no ExportedType rows, so the index now reads them itself (<see cref="TypeForwarders"/>) and follows them.
/// <para>
/// Every assembly here is EMITTED (<see cref="TypeForwarderFixture"/>), and the CLR itself is the oracle for where a
/// reference lands: the caller is run in an <see cref="IsolatedLoadContext"/> pinned to one variant of <c>FwdA</c>.
/// </para>
/// </summary>
public sealed class TypeForwarderResolutionTests : IClassFixture<TypeForwarderFixture>
{
    #region Constructors
    public TypeForwarderResolutionTests(TypeForwarderFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- the runtime oracle -----------------------------------------------------------------------------------------

    /// <summary>
    /// What the CLR binds <c>[FwdA]System.Environment::GetEnvironmentVariable</c> to, with each variant of <c>FwdA</c>
    /// pinned: the stub (a TypeDef, no forwarder) runs the decoy — the control that shows the oracle can tell the two
    /// apart — and every variant with a forwarder runs the platform method, decoy TypeDef or not.
    /// </summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.Stub), TypeForwarderFixture.Decoy)]
    [InlineData(nameof(TypeForwarderFixture.DefinedAndForwarded), Platform)]
    [InlineData(nameof(TypeForwarderFixture.NestedAndForwarded), Platform)]
    [InlineData(nameof(TypeForwarderFixture.PureForwarder), Platform)]
    public void Runtime_TheCallerBindsWhereTheForwarderSays(string variant, string expected)
    {
        Environment.SetEnvironmentVariable(fixture.Variable, Platform);
        try
        {
            Assert.Equal(expected, Run(new() { ["FwdA"] = fixture.Variant(variant) }, "Env"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(fixture.Variable, null);
        }
    }

    /// <summary>A forward into another emitted assembly is followed at run time too: <c>FwdT</c>'s bodies run (2), not the stub's (1).</summary>
    [Theory]
    [InlineData("Forwarded")]
    [InlineData("ForwardedGeneric")]
    public void Runtime_AForwardIntoAnotherAssembly_RunsThatAssemblysDefinition(string method) =>
        Assert.Equal(2, Run(new() { ["FwdA"] = fixture.ChainForwarder, ["FwdT"] = fixture.ChainTarget }, method));

    // ---- (a) / (b): a decoy and a forwarder ------------------------------------------------------------------------

    /// <summary>
    /// The emitted variants carry what they claim: the forwarder rows are read from the file by
    /// <see cref="AssemblyDisassembler.Create"/>, and the decoy renders the platform method's node id.
    /// </summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.DefinedAndForwarded))]
    [InlineData(nameof(TypeForwarderFixture.NestedAndForwarded))]
    public void Premise_TheDecoyRendersThePlatformId_AndTheForwardersAreRead(string variant)
    {
        using var loaded = ModelAssemblies.Load(fixture.Variant(variant), fixture.Caller);
        var index = loaded.Index();
        var forwarders = loaded.Disassemblers[0].Forwarders;

        Assert.True(forwarders.IsReadable);
        Assert.Equal(2, forwarders.Count);
        Assert.Equal([Core], forwarders.Targets("System", "Environment"));
        Assert.Equal([Core], forwarders.Targets("P", "Q`1"));
        Assert.True(index.IsOwnMethod(GetEnvironmentVariable));
        Assert.Equal("FwdA", Assert.Single(index.Methods, m => m.NodeId == GetEnvironmentVariable).Assembly);
        Assert.Equal(GetEnvironmentVariable, Site(index, Env).ReferenceNodeId);
        Assert.True(index.Coverage.IsComplete);
    }

    /// <summary>
    /// (a) TypeDef decoy + forwarder: Ambiguous over BOTH places the call can land — the own decoy and the platform
    /// method, the latter under its <see cref="MemberIndex.Qualified"/> id so it can never merge into the decoy's node.
    /// Never Exact to the decoy alone. (b), the NESTED decoy, was here too until A2Multi S2; it now follows the forwarder
    /// alone (<see cref="Resolve_ANestedDecoyBehindAForwarder_FollowsTheForwarderToThePlatformAlone"/>).
    /// </summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.DefinedAndForwarded))]
    public void Resolve_ADecoyBehindAForwarder_IsAmbiguousOverTheDecoyAndThePlatform(string variant)
    {
        using var loaded = ModelAssemblies.Load(fixture.Variant(variant), fixture.Caller);
        var index = loaded.Index();

        var resolution = index.Resolve(Site(index, Env).Target);

        Assert.True(resolution.Kind == ResolutionKind.Ambiguous,
            $"{resolution.NodeId} resolved {resolution.Kind} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); expected Ambiguous.");
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Equal([GetEnvironmentVariable, QualifiedGetEnvironmentVariable], resolution.Candidates);
        Assert.Equal(GetEnvironmentVariable, resolution.NodeId);
        Assert.Equal(EnvironmentKey, resolution.ClassificationKey);
        Assert.Equal("FwdA", resolution.Assembly);
        Assert.Equal($"FwdA forwards this type, and it resolves into FwdA, {Core}", resolution.Reason);
    }

    /// <summary>
    /// (a) in the graph: the caller has an edge to the decoy AND to an External node under the qualified id, which
    /// carries the platform method's classification key (so the sink is classified), plus an Ambiguous opacity. (b): see
    /// <see cref="Build_ANestedDecoyBehindAForwarder_EdgesToAQualifiedPlatformLeafOnly"/>.
    /// </summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.DefinedAndForwarded))]
    public void Build_ADecoyBehindAForwarder_EdgesToTheDecoyAndToAQualifiedPlatformLeaf(string variant)
    {
        using var loaded = ModelAssemblies.Load(fixture.Variant(variant), fixture.Caller);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);
        var site = Site(index, Env);

        Assert.Equal(
            [new MethodEdge(Env, GetEnvironmentVariable, MethodEdgeKind.Call, site.Offset), new MethodEdge(Env, QualifiedGetEnvironmentVariable, MethodEdgeKind.Call, site.Offset)],
            graph.Successors(Env));
        Assert.Equal(new MethodNode(QualifiedGetEnvironmentVariable, EnvironmentKey, MethodNodeKind.External), graph.Node(QualifiedGetEnvironmentVariable));
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(GetEnvironmentVariable)?.Kind);
        Assert.Equal(
            [new GraphOpacity(Env, site.Offset, OpacityKind.Ambiguous, $"{GetEnvironmentVariable}: FwdA forwards this type, and it resolves into FwdA, {Core}")],
            graph.Opacities.Where(o => o.Site == Env));
    }

    /// <summary>
    /// (b) Nested-type decoy (<c>System+Environment</c>, same joined node id) + forwarder. Since A2Multi S2 own
    /// definitions are bucketed by the declaring type's PARTS (namespace and nesting chain), so the nested decoy is not
    /// the namespace type <c>System.Environment</c> the reference names; the forwarder walk finds no own place in FwdA and
    /// follows the forward alone — External into CoreLib, which is exactly what the CLR runs (the oracle above, with this
    /// variant pinned, returns the platform value). Until S2 the decoy was an extra Ambiguous candidate: a precision cost
    /// A1 §2.9 had recorded.
    /// </summary>
    [Fact]
    public void Resolve_ANestedDecoyBehindAForwarder_FollowsTheForwarderToThePlatformAlone()
    {
        using var loaded = ModelAssemblies.Load(fixture.NestedAndForwarded, fixture.Caller);
        var index = loaded.Index();
        Assert.True(index.IsOwnMethod(GetEnvironmentVariable));   // the decoy still renders the platform id

        var resolution = index.Resolve(Site(index, Env).Target);

        Assert.Equal(ResolutionKind.External, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Equal(Core, resolution.Assembly);
        Assert.Equal(GetEnvironmentVariable, resolution.NodeId);
        Assert.Equal(EnvironmentKey, resolution.ClassificationKey);
        Assert.Empty(resolution.Candidates);
        Assert.Equal("forwarded by FwdA", resolution.Reason);
        Environment.SetEnvironmentVariable(fixture.Variable, Platform);
        try
        {
            Assert.Equal(Platform, Run(new() { ["FwdA"] = fixture.NestedAndForwarded }, "Env"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(fixture.Variable, null);
        }
    }

    /// <summary>
    /// (b) in the graph: ONE edge, to the platform method as an External leaf under its qualified id — the own nested
    /// decoy renders the same node id, so the leaf is kept apart from it and the collision reported as
    /// <see cref="OpacityKind.NameShadowed"/>; no edge to the decoy, and no Ambiguous opacity.
    /// </summary>
    [Fact]
    public void Build_ANestedDecoyBehindAForwarder_EdgesToAQualifiedPlatformLeafOnly()
    {
        using var loaded = ModelAssemblies.Load(fixture.NestedAndForwarded, fixture.Caller);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);
        var site = Site(index, Env);

        Assert.Equal([new MethodEdge(Env, QualifiedGetEnvironmentVariable, MethodEdgeKind.Call, site.Offset)], graph.Successors(Env));
        Assert.Equal(new MethodNode(QualifiedGetEnvironmentVariable, EnvironmentKey, MethodNodeKind.External), graph.Node(QualifiedGetEnvironmentVariable));
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(GetEnvironmentVariable)?.Kind);
        Assert.Equal([OpacityKind.NameShadowed], graph.Opacities.Where(o => o.Site == Env).Select(o => o.Kind));
    }

    // ---- (c) / (d): a pure forwarder ---------------------------------------------------------------------------------

    /// <summary>
    /// (c) A forwarder and no decoy anywhere: External into System.Private.CoreLib under the bare reference id,
    /// saying it was forwarded.
    /// </summary>
    [Fact]
    public void Resolve_APureForwarder_IsExternalIntoTheTarget()
    {
        using var loaded = ModelAssemblies.Load(fixture.PureForwarder, fixture.Caller);
        var index = loaded.Index();
        Assert.False(index.IsOwnMethod(GetEnvironmentVariable));

        var resolution = index.Resolve(Site(index, Env).Target);

        Assert.Equal(ResolutionKind.External, resolution.Kind);
        Assert.Equal(Core, resolution.Assembly);
        Assert.Equal(GetEnvironmentVariable, resolution.NodeId);
        Assert.Equal(EnvironmentKey, resolution.ClassificationKey);
        Assert.Null(resolution.Definition);
        Assert.Empty(resolution.Candidates);
        Assert.Equal("forwarded by FwdA", resolution.Reason);
    }

    /// <summary>(c) in the graph: a plain External leaf under the bare id — nothing to shadow, so no opacity at all.</summary>
    [Fact]
    public void Build_APureForwarder_LeadsToABarePlatformLeaf_WithoutOpacity()
    {
        using var loaded = ModelAssemblies.Load(fixture.PureForwarder, fixture.Caller);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);
        var site = Site(index, Env);

        Assert.Equal([new MethodEdge(Env, GetEnvironmentVariable, MethodEdgeKind.Call, site.Offset)], graph.Successors(Env));
        Assert.Equal(new MethodNode(GetEnvironmentVariable, EnvironmentKey, MethodNodeKind.External), graph.Node(GetEnvironmentVariable));
        Assert.Null(graph.Node(QualifiedGetEnvironmentVariable));
        Assert.DoesNotContain(graph.Opacities, o => o.Site == Env);
        Assert.DoesNotContain(graph.Opacities, o => o.Kind == OpacityKind.NameShadowed);
    }

    /// <summary>
    /// (d) The same pure forwarder, but another indexed assembly (<c>FwdC</c>) defines a method with the platform
    /// method's node id: the resolution is unchanged (External, forwarded), and in the graph the platform leaf is
    /// Qualified — never merged into FwdC's node — with a NameShadowed opacity that says it was forwarded.
    /// </summary>
    [Fact]
    public void Build_APureForwarder_WhenAnotherIndexedAssemblyDefinesThatId_IsAQualifiedLeafAndNameShadowed()
    {
        using var loaded = ModelAssemblies.Load(fixture.PureForwarder, fixture.Shadow, fixture.Caller);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);
        var site = Site(index, Env);
        Assert.Equal("FwdC", Assert.Single(index.Methods, m => m.NodeId == GetEnvironmentVariable).Assembly);

        var resolution = index.Resolve(site.Target);

        Assert.Equal((ResolutionKind.External, Core, GetEnvironmentVariable, "forwarded by FwdA"), (resolution.Kind, resolution.Assembly, resolution.NodeId, resolution.Reason));
        Assert.Equal([new MethodEdge(Env, QualifiedGetEnvironmentVariable, MethodEdgeKind.Call, site.Offset)], graph.Successors(Env));
        Assert.Equal(new MethodNode(QualifiedGetEnvironmentVariable, EnvironmentKey, MethodNodeKind.External), graph.Node(QualifiedGetEnvironmentVariable));
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(GetEnvironmentVariable)?.Kind);
        var shadowed = Assert.Single(graph.Opacities, o => o.Site == Env);
        Assert.Equal(OpacityKind.NameShadowed, shadowed.Kind);
        Assert.Equal(site.Offset, shadowed.Offset);
        Assert.Contains("forwarded by FwdA", shadowed.Detail, StringComparison.Ordinal);
        Assert.Equal($"{GetEnvironmentVariable} in {Core} shares its name with an own method (forwarded by FwdA)", shadowed.Detail);
    }

    // ---- (e): a forward into another indexed assembly ----------------------------------------------------------------

    /// <summary>
    /// (e) <c>FwdA</c> forwards <c>NS.T</c> and <c>NS.G`1</c> to the indexed <c>FwdT</c>, which defines them: the
    /// reference resolves to FwdT's definition — Exact for <c>NS.T.M()</c>, Substituted through <c>G&lt;int&gt;</c> —
    /// saying it was forwarded.
    /// </summary>
    [Theory]
    [InlineData(Forwarded, MethodEdgeKind.Call, ResolutionKind.Exact, "NS.T.M()")]
    [InlineData(ForwardedGeneric, MethodEdgeKind.CallVirt, ResolutionKind.Substituted, "NS.G`1.M(!0)")]
    public void Resolve_AForwardIntoAnIndexedAssembly_IsThatAssemblysDefinition(string caller, MethodEdgeKind kind, ResolutionKind expected, string definition)
    {
        using var loaded = ModelAssemblies.Load(fixture.ChainForwarder, fixture.ChainTarget, fixture.Caller);
        var index = loaded.Index();
        var site = Site(index, caller, kind);
        Assert.Equal("FwdA", site.DeclaringAssembly);

        var resolution = index.Resolve(site.Target);

        Assert.True(resolution.Kind == expected,
            $"{site.ReferenceNodeId} resolved {resolution.Kind} -> {resolution.NodeId} ({resolution.Reason}); expected {expected}.");
        Assert.Equal(definition, resolution.NodeId);
        Assert.Equal("FwdT", resolution.Assembly);
        Assert.Equal([definition], resolution.Candidates);
        Assert.Equal("forwarded by FwdA", resolution.Reason);
        var own = Assert.Single(index.Methods, m => ReferenceEquals(m.Definition, resolution.Definition));
        Assert.Equal(("FwdT", definition), (own.Assembly, own.NodeId));
    }

    /// <summary>(e) in the graph: an ordinary own edge into FwdT's body, with no opacity.</summary>
    [Fact]
    public void Build_AForwardIntoAnIndexedAssembly_EdgesIntoThatAssemblysBody()
    {
        using var loaded = ModelAssemblies.Load(fixture.ChainForwarder, fixture.ChainTarget, fixture.Caller);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);

        Assert.Equal([new MethodEdge(Forwarded, "NS.T.M()", MethodEdgeKind.Call, Site(index, Forwarded).Offset)], graph.Successors(Forwarded));
        Assert.Contains(graph.Successors(ForwardedGeneric), e => e.To == "NS.G`1.M(!0)" && e.Kind == MethodEdgeKind.CallVirt);
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node("NS.T.M()")?.Kind);
        Assert.DoesNotContain(graph.Opacities, o => o.Site is Forwarded or ForwardedGeneric);
    }

    // ---- (f): a cycle --------------------------------------------------------------------------------------------------

    /// <summary>
    /// (f) The oracle: with <c>FwdA</c> forwarding <c>NS.T</c> to <c>FwdT</c> and <c>FwdT</c> forwarding it back, the CLR
    /// cannot bind the reference at all — TypeLoadException, not a stack overflow and not either assembly's code.
    /// </summary>
    [Fact]
    public void Runtime_AForwarderCycle_ThrowsTypeLoadException() =>
        Assert.IsType<TypeLoadException>(Thrown(new() { ["FwdA"] = fixture.CycleForwarder, ["FwdT"] = fixture.CycleTarget }, "Forwarded"));

    /// <summary>
    /// (f) <c>FwdA</c> forwards <c>NS.T</c> to <c>FwdT</c>, which forwards it back, and neither defines it: the walk
    /// terminates, nothing throws, and the answer is Unresolved — a cycle back into FwdA, never External and never Own.
    /// </summary>
    [Fact]
    public void Resolve_AForwarderCycle_TerminatesUnresolved()
    {
        using var loaded = ModelAssemblies.Load(fixture.CycleForwarder, fixture.CycleTarget, fixture.Caller);
        var index = loaded.Index();
        Assert.Equal(["FwdT"], loaded.Disassemblers[0].Forwarders.Targets("NS", "T"));
        Assert.Equal(["FwdA"], loaded.Disassemblers[1].Forwarders.Targets("NS", "T"));

        MethodResolution? resolution = null;
        var thrown = Record.Exception(() => resolution = index.Resolve(Site(index, Forwarded).Target));

        Assert.Null(thrown);
        Assert.Equal(ResolutionKind.Unresolved, resolution!.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Contains("cycle", resolution.Reason, StringComparison.Ordinal);
        Assert.Equal($"forwarded by FwdA; {CycleBackToFwdA("FwdT")}", resolution.Reason);
        Assert.Equal(("NS.T.M()", "FwdA"), (resolution.NodeId, resolution.Assembly));
        Assert.Null(resolution.Definition);
        Assert.Empty(resolution.Candidates);
    }

    /// <summary>(f) in the graph: a leaf under the reference id and an Unresolved opacity naming the cycle.</summary>
    [Fact]
    public void Build_AForwarderCycle_KeepsTheSiteWithAnUnresolvedOpacity()
    {
        using var loaded = ModelAssemblies.Load(fixture.CycleForwarder, fixture.CycleTarget, fixture.Caller);
        var index = loaded.Index();

        MethodGraph? graph = null;
        Assert.Null(Record.Exception(() => graph = MethodGraph.Build(index)));

        var site = Site(index, Forwarded);
        Assert.Equal([new MethodEdge(Forwarded, "NS.T.M()", MethodEdgeKind.Call, site.Offset)], graph!.Successors(Forwarded));
        Assert.Equal(MethodNodeKind.External, graph.Node("NS.T.M()")?.Kind);
        Assert.Equal(
            [new GraphOpacity(Forwarded, site.Offset, OpacityKind.Unresolved, $"NS.T.M(): forwarded by FwdA; {CycleBackToFwdA("FwdT")}")],
            graph.Opacities.Where(o => o.Site == Forwarded));
    }

    // ---- review 5 W-A: a cycle or a self-forward, with a decoy -------------------------------------------------------

    /// <summary>
    /// W-A, the oracle: <c>FwdA</c> defines the <c>System.Environment</c> decoy and forwards the type — to <c>FwdT</c>,
    /// which forwards it back, or to itself. The CLR follows the forwarder, never the decoy, and the walk cannot end:
    /// TypeLoadException. (The stub, with the same decoy and no forwarder, runs the decoy — see the oracle above.)
    /// </summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.CycleDecoyForwarder))]
    [InlineData(nameof(TypeForwarderFixture.SelfForwarder))]
    public void Runtime_ACycleOrSelfForwardWithADecoy_ThrowsTypeLoadException(string variant)
    {
        Environment.SetEnvironmentVariable(fixture.Variable, Platform);
        try
        {
            Assert.IsType<TypeLoadException>(Thrown(new() { ["FwdA"] = fixture.Variant(variant), ["FwdT"] = fixture.CycleDecoyTarget }, "Env"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(fixture.Variable, null);
        }
    }

    /// <summary>
    /// W-A: a forward back to an assembly already on the walk is an Unresolved place, so the decoy is never the answer
    /// alone — Ambiguous over the decoy and <c>[FwdA]</c>-qualified leaf, with the cycle named in the reason. Before the
    /// fix the revisit was dropped, and the decoy was the only place left: Exact, hiding where the call goes.
    /// </summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.CycleDecoyForwarder), "FwdT")]
    [InlineData(nameof(TypeForwarderFixture.SelfForwarder), "FwdA")]
    public void Resolve_ACycleOrSelfForwardWithADecoy_IsAmbiguousOverTheDecoyAndTheRevisit(string variant, string backFrom)
    {
        using var loaded = ModelAssemblies.Load([fixture.Variant(variant), .. backFrom == "FwdT" ? [fixture.CycleDecoyTarget] : Array.Empty<string>(), fixture.Caller]);
        var index = loaded.Index();
        Assert.Equal([backFrom], loaded.Disassemblers[0].Forwarders.Targets("System", "Environment"));
        Assert.True(index.IsOwnMethod(GetEnvironmentVariable));

        var resolution = index.Resolve(Site(index, Env).Target);

        Assert.True(resolution.Kind == ResolutionKind.Ambiguous,
            $"{resolution.NodeId} resolved {resolution.Kind} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); expected Ambiguous.");
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Equal([GetEnvironmentVariable, FwdAGetEnvironmentVariable], resolution.Candidates);
        Assert.Equal((GetEnvironmentVariable, EnvironmentKey, "FwdA"), (resolution.NodeId, resolution.ClassificationKey, resolution.Assembly));
        Assert.Equal($"FwdA forwards this type, and it resolves into FwdA; {CycleBackToFwdA(backFrom)}", resolution.Reason);
        Assert.True(index.Coverage.IsComplete);
    }

    /// <summary>
    /// W-A in the graph: edges to the decoy's body AND to a separate <c>[FwdA]</c> leaf that keeps the platform key,
    /// and one Ambiguous opacity carrying the reason.
    /// </summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.CycleDecoyForwarder), "FwdT")]
    [InlineData(nameof(TypeForwarderFixture.SelfForwarder), "FwdA")]
    public void Build_ACycleOrSelfForwardWithADecoy_EdgesToTheDecoyAndToAQualifiedLeaf(string variant, string backFrom)
    {
        using var loaded = ModelAssemblies.Load([fixture.Variant(variant), .. backFrom == "FwdT" ? [fixture.CycleDecoyTarget] : Array.Empty<string>(), fixture.Caller]);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);
        var site = Site(index, Env);

        Assert.Equal(
            [new MethodEdge(Env, GetEnvironmentVariable, MethodEdgeKind.Call, site.Offset), new MethodEdge(Env, FwdAGetEnvironmentVariable, MethodEdgeKind.Call, site.Offset)],
            graph.Successors(Env));
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(GetEnvironmentVariable)?.Kind);
        Assert.Equal(new MethodNode(FwdAGetEnvironmentVariable, EnvironmentKey, MethodNodeKind.External), graph.Node(FwdAGetEnvironmentVariable));
        Assert.Equal(
            [new GraphOpacity(Env, site.Offset, OpacityKind.Ambiguous, $"{GetEnvironmentVariable}: FwdA forwards this type, and it resolves into FwdA; {CycleBackToFwdA(backFrom)}")],
            graph.Opacities.Where(o => o.Site == Env));
    }

    // ---- review 5 W-B: an export from another module file ------------------------------------------------------------

    /// <summary>
    /// W-B, the oracle: <c>FwdA</c> exports <c>System.Environment</c> from module file <c>FwdA2.netmodule</c> — with the
    /// decoy defined in the manifest module, or without it. CoreCLR follows the export (not the decoy) and refuses the
    /// module: FileLoadException naming the netmodule. (.NET Framework would load the netmodule and run its body.)
    /// </summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.ModuleDecoy))]
    [InlineData(nameof(TypeForwarderFixture.ModuleOnly))]
    public void Runtime_AModuleExport_IsFollowed_NotTheDecoy(string variant)
    {
        Environment.SetEnvironmentVariable(fixture.Variable, Platform);
        try
        {
            var thrown = Assert.IsType<System.IO.FileLoadException>(Thrown(new() { ["FwdA"] = fixture.Variant(variant) }, "Env"));
            Assert.Contains(TypeForwarderFixture.Module, thrown.Message, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(fixture.Variable, null);
        }
    }

    /// <summary>The File-implemented row is read as a module export, not a forward, and not dropped.</summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.ModuleDecoy))]
    [InlineData(nameof(TypeForwarderFixture.ModuleOnly))]
    public void Premise_AModuleExportIsReadAsAModule(string variant)
    {
        using var loaded = ModelAssemblies.Load(fixture.Variant(variant), fixture.Caller);
        var forwarders = loaded.Disassemblers[0].Forwarders;

        Assert.Equal((true, 1), (forwarders.IsReadable, forwarders.Count));
        Assert.Equal([TypeForwarderFixture.Module], forwarders.Modules("System", "Environment"));
        Assert.Empty(forwarders.Targets("System", "Environment"));
        Assert.Equal(variant == nameof(TypeForwarderFixture.ModuleDecoy), loaded.Index().IsOwnMethod(GetEnvironmentVariable));
    }

    /// <summary>
    /// W-B: a decoy plus a module export is Ambiguous over the decoy and an <c>[FwdA]</c>-qualified leaf (CCI loads only
    /// the manifest module, so the netmodule's body is never indexed), with the module named in the reason — worded
    /// "FwdA exports this type", since no forwarder was followed (review 6 N-f). Never the decoy alone — before the
    /// review 5 fix the File row was dropped and this was Exact.
    /// </summary>
    [Fact]
    public void Resolve_AModuleExportWithADecoy_IsAmbiguousOverTheDecoyAndTheModule()
    {
        using var loaded = ModelAssemblies.Load(fixture.ModuleDecoy, fixture.Caller);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);
        var site = Site(index, Env);

        var resolution = index.Resolve(site.Target);

        Assert.True(resolution.Kind == ResolutionKind.Ambiguous,
            $"{resolution.NodeId} resolved {resolution.Kind} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); expected Ambiguous.");
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Equal([GetEnvironmentVariable, FwdAGetEnvironmentVariable], resolution.Candidates);
        Assert.Equal((GetEnvironmentVariable, EnvironmentKey, "FwdA"), (resolution.NodeId, resolution.ClassificationKey, resolution.Assembly));
        Assert.Equal($"FwdA exports this type, and it resolves into FwdA; {ModuleReason}", resolution.Reason);

        Assert.Equal(
            [new MethodEdge(Env, GetEnvironmentVariable, MethodEdgeKind.Call, site.Offset), new MethodEdge(Env, FwdAGetEnvironmentVariable, MethodEdgeKind.Call, site.Offset)],
            graph.Successors(Env));
        Assert.Equal(new MethodNode(FwdAGetEnvironmentVariable, EnvironmentKey, MethodNodeKind.External), graph.Node(FwdAGetEnvironmentVariable));
        Assert.Equal(
            [new GraphOpacity(Env, site.Offset, OpacityKind.Ambiguous, $"{GetEnvironmentVariable}: FwdA exports this type, and it resolves into FwdA; {ModuleReason}")],
            graph.Opacities.Where(o => o.Site == Env));
    }

    /// <summary>
    /// W-B: a module export and no decoy is Unresolved into FwdA, saying the module is not indexed — not External (it
    /// is FwdA's own code, just unread) and not "no indexed definition matches". Nothing to shadow, so the leaf is bare.
    /// </summary>
    [Fact]
    public void Resolve_AModuleExportWithoutADecoy_IsUnresolved_NamingTheModule()
    {
        using var loaded = ModelAssemblies.Load(fixture.ModuleOnly, fixture.Caller);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);
        var site = Site(index, Env);

        var resolution = index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Empty(resolution.Candidates);
        Assert.Equal((GetEnvironmentVariable, EnvironmentKey, "FwdA"), (resolution.NodeId, resolution.ClassificationKey, resolution.Assembly));
        Assert.Equal(ModuleReason, resolution.Reason);

        Assert.Equal([new MethodEdge(Env, GetEnvironmentVariable, MethodEdgeKind.Call, site.Offset)], graph.Successors(Env));
        Assert.Equal(MethodNodeKind.External, graph.Node(GetEnvironmentVariable)?.Kind);
        Assert.Equal(
            [new GraphOpacity(Env, site.Offset, OpacityKind.Unresolved, $"{GetEnvironmentVariable}: {ModuleReason}")],
            graph.Opacities.Where(o => o.Site == Env));
    }

    /// <summary>
    /// W-B, the same rows built by hand: a module export only for OTHER types leaves a reference to a type the stub
    /// defines unchanged (Exact, Own) — and a module export of the referenced type makes every call into it non-own.
    /// </summary>
    [Fact]
    public void Resolve_AHandBuiltModuleExport_AffectsOnlyTheExportedName()
    {
        using var loaded = ModelAssemblies.Load(fixture.Stub, fixture.Caller);
        var (stub, caller) = (loaded.Disassemblers[0], loaded.Disassemblers[1]);
        var other = MemberIndex.Build([(stub.Assembly, TypeForwarders.Of([], [("Other", "Thing", "x.netmodule")])), (caller.Assembly, caller.Forwarders)]);
        var exported = MemberIndex.Build([(stub.Assembly, TypeForwarders.Of([], [("System", "Environment", TypeForwarderFixture.Module)])), (caller.Assembly, caller.Forwarders)]);

        Assert.Equal(Answers(loaded.Index()), Answers(other));
        var resolution = exported.Resolve(Site(exported, Env).Target);
        Assert.Equal((ResolutionKind.Ambiguous, $"FwdA exports this type, and it resolves into FwdA; {ModuleReason}"), (resolution.Kind, resolution.Reason));
        Assert.Equal([GetEnvironmentVariable, FwdAGetEnvironmentVariable], resolution.Candidates);
        Assert.True(exported.Resolve(Site(exported, Forwarded).Target).IsOwn);
    }

    /// <summary>
    /// Review 6 N-f wording: "exports" only when nothing but a module export was involved — a name that is BOTH
    /// forwarded and module-exported (with the decoy) is worded "forwards", and every place is kept.
    /// </summary>
    [Fact]
    public void Resolve_AForwardAndAModuleExportOfOneName_IsWordedForwards()
    {
        using var loaded = ModelAssemblies.Load(fixture.Stub, fixture.Caller);
        var (stub, caller) = (loaded.Disassemblers[0], loaded.Disassemblers[1]);
        var index = MemberIndex.Build([
            (stub.Assembly, TypeForwarders.Of([("System", "Environment", Core)], [("System", "Environment", TypeForwarderFixture.Module)])),
            (caller.Assembly, caller.Forwarders)]);

        var resolution = index.Resolve(Site(index, Env).Target);

        Assert.Equal(ResolutionKind.Ambiguous, resolution.Kind);
        Assert.Equal([GetEnvironmentVariable, FwdAGetEnvironmentVariable, QualifiedGetEnvironmentVariable], resolution.Candidates);
        Assert.Equal($"FwdA forwards this type, and it resolves into FwdA, {Core}; {ModuleReason}", resolution.Reason);
    }

    // ---- review 6 W-C: junk at the end of #Strings ----------------------------------------------------------------------

    /// <summary>
    /// W-C, the reviewer's scenario: an assembly with NO exported rows, whose <c>#Strings</c> stream ends in one junk
    /// padding byte after the last terminator, calls its own <c>G&lt;int&gt;.M(1)</c>. Its forwarders are readable and
    /// empty, the index is complete, and the call is Substituted to its own <c>G`1.M(!0)</c> — as the CLR runs it.
    /// (Under the review 5 check the table was Unreadable and the call Unresolved.)
    /// </summary>
    [Fact]
    public void Resolve_JunkStringsPaddingInAnAssemblyThatForwardsNothing_StaysSubstitutedOwn()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.SaveWithJunkStringsPadding("FwdH", DefineGenericCaller, null, "heapend");
        using var loaded = ModelAssemblies.Load(path);
        var index = loaded.Index();
        var site = Site(index, HeapCaller, MethodEdgeKind.CallVirt);

        var resolution = index.Resolve(site.Target);

        Assert.Equal((true, 0), (TypeForwarders.Read(path).IsReadable, TypeForwarders.Read(path).Count));
        Assert.Equal((true, 0), (loaded.Disassemblers[0].Forwarders.IsReadable, loaded.Disassemblers[0].Forwarders.Count));
        Assert.Equal(0, index.Coverage.ForwardersUnreadable);
        Assert.True(index.Coverage.IsComplete);
        Assert.True(resolution.Kind == ResolutionKind.Substituted, $"{resolution.NodeId} resolved {resolution.Kind} ({resolution.Reason}); expected Substituted.");
        Assert.True(resolution.IsOwn);
        Assert.Equal(("Heap.G`1.M(!0)", "FwdH", (string?)null), (resolution.NodeId, resolution.Assembly, resolution.Reason));
        using var context = new IsolatedLoadContext();
        Assert.Equal("G-BODY", context.LoadBytes(path).GetType("Heap.Caller", throwOnError: true)!.GetMethod("M0")!.Invoke(null, null));
    }

    /// <summary>
    /// W-C: a FORWARDING assembly with the same junk padding byte, every used string terminated — the forward is still
    /// read and followed (External into CoreLib, forwarded by FwdA), as the CLR does.
    /// </summary>
    [Fact]
    public void Resolve_AForwarderWithJunkStringsPadding_IsStillFollowed()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.SaveWithJunkStringsPadding("FwdA", module => Marker(module, "Junk"), EmittedAssembly.Forwarding(("System", "Environment", Core)), "junkfwd");
        using var loaded = ModelAssemblies.Load(path, fixture.Caller);
        var index = loaded.Index();

        var resolution = index.Resolve(Site(index, Env).Target);

        Assert.Equal([Core], loaded.Disassemblers[0].Forwarders.Targets("System", "Environment"));
        Assert.True(index.Coverage.IsComplete);
        Assert.Equal((ResolutionKind.External, Core, GetEnvironmentVariable, "forwarded by FwdA"), (resolution.Kind, resolution.Assembly, resolution.NodeId, resolution.Reason));
        Environment.SetEnvironmentVariable(fixture.Variable, Platform);
        try
        {
            Assert.Equal(Platform, Run(new() { ["FwdA"] = path }, "Env"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(fixture.Variable, null);
        }
    }

    // Heap.G`1<T>.M(T) returning "G-BODY", and Heap.Caller.M0() => new G<int>().M(1), in one module.
    private static void DefineGenericCaller(ModuleBuilder module)
    {
        var g = module.DefineType("Heap.G`1", TypeAttributes.Public | TypeAttributes.Class);
        var t = g.DefineGenericParameters("T")[0];
        var constructor = g.DefineDefaultConstructor(MethodAttributes.Public);
        var m = g.DefineMethod("M", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(string), [t]);
        var body = m.GetILGenerator();
        body.Emit(OpCodes.Ldstr, "G-BODY");
        body.Emit(OpCodes.Ret);
        var caller = module.DefineType("Heap.Caller", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var closed = g.MakeGenericType(typeof(int));
        var il = caller.DefineMethod("M0", MethodAttributes.Public | MethodAttributes.Static, typeof(string), Type.EmptyTypes).GetILGenerator();
        il.Emit(OpCodes.Newobj, TypeBuilder.GetConstructor(closed, constructor));
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, TypeBuilder.GetMethod(closed, m));
        il.Emit(OpCodes.Ret);
        g.CreateType();
        caller.CreateType();
    }

    private static void Marker(ModuleBuilder module, string space) =>
        module.DefineType(space + ".Marker", TypeAttributes.Public | TypeAttributes.Class).CreateType();

    // ---- (g): unreadable forwarders ------------------------------------------------------------------------------------

    /// <summary>
    /// (g), the control: the stub (a TypeDef decoy, no forwarder) with its own, readable, empty table — the call
    /// resolves Exact to the decoy, which is right: with no forwarder the CLR runs it (see the runtime oracle).
    /// </summary>
    [Fact]
    public void Resolve_IntoTheStubWithReadableEmptyForwarders_IsExact()
    {
        using var loaded = ModelAssemblies.Load(fixture.Stub, fixture.Caller);
        var index = loaded.Index();
        Assert.Equal((true, 0), (loaded.Disassemblers[0].Forwarders.IsReadable, loaded.Disassemblers[0].Forwarders.Count));

        var resolution = index.Resolve(Site(index, Env).Target);

        Assert.Equal(ResolutionKind.Exact, resolution.Kind);
        Assert.True(resolution.IsOwn);
        Assert.Null(resolution.Reason);
        Assert.Equal(new IndexCoverage(0, 0, 0, 0), index.Coverage);
    }

    /// <summary>
    /// (g) The same stub with forwarders that could not be read (Unreadable, or missing: null): whether it forwards
    /// the type is unknown, so the reference is Unresolved — never Own on a guess — and the index says it is
    /// incomplete. The graph leaf is Qualified (its id matching the decoy's is textual only) and still carries the
    /// platform method's classification key.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Resolve_IntoAnAssemblyWithUnreadableForwarders_IsUnresolved_AndCounted(bool missing)
    {
        using var loaded = ModelAssemblies.Load(fixture.Stub, fixture.Caller);
        var (stub, caller) = (loaded.Disassemblers[0], loaded.Disassemblers[1]);
        var index = MemberIndex.Build([(stub.Assembly, missing ? null! : TypeForwarders.Unreadable), (caller.Assembly, caller.Forwarders)]);
        var graph = MethodGraph.Build(index);
        var site = Site(index, Env);

        var resolution = index.Resolve(site.Target);

        Assert.Equal(new IndexCoverage(0, 0, 0, 1), index.Coverage);
        Assert.Equal(1, index.Coverage.ForwardersUnreadable);
        Assert.False(index.Coverage.IsComplete);
        Assert.Same(index.Coverage, graph.Coverage.Index);

        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Equal(("FwdA", GetEnvironmentVariable, EnvironmentKey), (resolution.Assembly, resolution.NodeId, resolution.ClassificationKey));
        Assert.Equal("the type forwarders of FwdA could not be read", resolution.Reason);

        var leaf = MemberIndex.Qualified("FwdA", GetEnvironmentVariable);
        Assert.Equal([new MethodEdge(Env, leaf, MethodEdgeKind.Call, site.Offset)], graph.Successors(Env));
        Assert.Equal(new MethodNode(leaf, EnvironmentKey, MethodNodeKind.External), graph.Node(leaf));
        Assert.Equal(
            [new GraphOpacity(Env, site.Offset, OpacityKind.Unresolved, $"{leaf}: the type forwarders of FwdA could not be read")],
            graph.Opacities.Where(o => o.Site == Env));
    }

    /// <summary>
    /// (g) An unreadable table blocks every reference into that assembly, not just forwarded names: the stub's
    /// <c>NS.T.M()</c>, Exact with readable forwarders, is Unresolved too.
    /// </summary>
    [Fact]
    public void Resolve_AnyReferenceIntoAnAssemblyWithUnreadableForwarders_IsNeverOwn()
    {
        using var loaded = ModelAssemblies.Load(fixture.Stub, fixture.Caller);
        var (stub, caller) = (loaded.Disassemblers[0], loaded.Disassemblers[1]);
        var readable = loaded.Index();
        var unreadable = MemberIndex.Build([(stub.Assembly, TypeForwarders.Unreadable), (caller.Assembly, caller.Forwarders)]);

        foreach (var (name, kind) in new[] { (Forwarded, MethodEdgeKind.Call), (ForwardedGeneric, MethodEdgeKind.CallVirt), (Generic, MethodEdgeKind.CallVirt) })
        {
            Assert.True(readable.Resolve(Site(readable, name, kind).Target).IsOwn, $"{name}: expected Own with readable forwarders.");
            var resolution = unreadable.Resolve(Site(unreadable, name, kind).Target);
            Assert.Equal((ResolutionKind.Unresolved, "the type forwarders of FwdA could not be read"), (resolution.Kind, resolution.Reason));
        }
    }

    /// <summary>
    /// Precision: an assembly that forwards only OTHER types resolves a reference to a type it defines exactly as if it
    /// forwarded nothing — Exact, no reason, Own — for every call site of the caller.
    /// </summary>
    [Fact]
    public void Resolve_IntoAnAssemblyThatForwardsOnlyOtherTypes_IsUnchanged()
    {
        using var loaded = ModelAssemblies.Load(fixture.Stub, fixture.Caller);
        var (stub, caller) = (loaded.Disassemblers[0], loaded.Disassemblers[1]);
        var plain = loaded.Index();
        var forwarding = MemberIndex.Build([(stub.Assembly, TypeForwarders.Of([("Other", "Thing", Core)])), (caller.Assembly, caller.Forwarders)]);

        Assert.Equal(Answers(plain), Answers(forwarding));
        var resolution = forwarding.Resolve(Site(forwarding, Env).Target);
        Assert.Equal((ResolutionKind.Exact, GetEnvironmentVariable, (string?)null), (resolution.Kind, resolution.NodeId, resolution.Reason));
        Assert.True(resolution.IsOwn);
    }

    /// <summary>
    /// A reference whose declaring type name cannot be read, into an indexed assembly that forwards types: it cannot be
    /// looked up in the forwarder table, so it is Unresolved and says why — never Own on a guess. Into the same
    /// assembly with no forwarders it is the ordinary "no indexed definition matches".
    /// </summary>
    [Fact]
    public void Resolve_AnUnreadableDeclaringType_IntoAnAssemblyThatForwards_IsUnresolved()
    {
        using var loaded = ModelAssemblies.Load(fixture.Stub, fixture.Caller);
        var (stub, caller) = (loaded.Disassemblers[0], loaded.Disassemblers[1]);
        var reference = SyntheticModel.Method(SyntheticModel.TypeRef("System", null!, assembly: "FwdA"), "GetEnvironmentVariable", SyntheticModel.TypeRef("System", "String"));
        var forwarding = MemberIndex.Build([(stub.Assembly, TypeForwarders.Of([("System", "Environment", Core)])), (caller.Assembly, caller.Forwarders)]);

        var resolution = forwarding.Resolve(reference);
        var control = loaded.Index().Resolve(reference);

        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.Equal("FwdA", resolution.Assembly);
        Assert.Null(resolution.Definition);
        Assert.Equal("the declaring type could not be read, and FwdA forwards types", resolution.Reason);
        Assert.Equal((ResolutionKind.Unresolved, "no indexed definition matches"), (control.Kind, control.Reason));
    }

    // ---- (h): a generic forwarded type, matched coarsely ---------------------------------------------------------------

    /// <summary>
    /// (h) A forwarder for <c>P.Q`1</c> and a TypeDef decoy <c>P.Q`1</c>: the reference through <c>P.Q&lt;int&gt;</c> is
    /// not resolved to the decoy alone — Ambiguous over the decoy and the qualified platform leaf, both of which the graph
    /// keeps. The nested decoy (<c>P+Q`1</c>): <see cref="Resolve_AGenericTypeBehindAForwarder_WithANestedDecoy_IsThePlatformAlone"/>.
    /// </summary>
    [Theory]
    [InlineData(nameof(TypeForwarderFixture.DefinedAndForwarded))]
    public void Resolve_AGenericTypeBehindAForwarder_IsNotTheDecoyAlone(string variant)
    {
        using var loaded = ModelAssemblies.Load(fixture.Variant(variant), fixture.Caller);
        var index = loaded.Index();
        var site = Site(index, Generic, MethodEdgeKind.CallVirt);
        Assert.Equal("P.Q`1.M(System.Int32)", site.ReferenceNodeId);
        var qualified = MemberIndex.Qualified(Core, site.ReferenceNodeId);

        var resolution = index.Resolve(site.Target);
        var graph = MethodGraph.Build(index);

        Assert.True(resolution.Kind == ResolutionKind.Ambiguous,
            $"{resolution.NodeId} resolved {resolution.Kind} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); expected Ambiguous.");
        Assert.Null(resolution.Definition);
        Assert.Equal(["P.Q`1.M(!0)", qualified], resolution.Candidates);
        Assert.Contains(graph.Successors(Generic), e => e.To == "P.Q`1.M(!0)" && e.Kind == MethodEdgeKind.CallVirt);
        Assert.Contains(graph.Successors(Generic), e => e.To == qualified && e.Kind == MethodEdgeKind.CallVirt);
        Assert.Equal(new MethodNode(qualified, CanonicalName.ClassificationKey(ModelNames.Of(site.Target)), MethodNodeKind.External), graph.Node(qualified));
    }

    /// <summary>
    /// (h) with the NESTED decoy <c>P+Q`1</c> (A2Multi S2): not the namespace type <c>P.Q`1</c> by parts, so the
    /// reference through <c>P.Q&lt;int&gt;</c> follows the forwarder alone — External into CoreLib, where the CLR sends it
    /// — and the graph has no edge to the decoy, only to the platform leaf. The instantiated reference id
    /// <c>P.Q`1.M(System.Int32)</c> is no own method's (the decoy's is <c>P.Q`1.M(!0)</c>), so the leaf keeps the bare id.
    /// </summary>
    [Fact]
    public void Resolve_AGenericTypeBehindAForwarder_WithANestedDecoy_IsThePlatformAlone()
    {
        using var loaded = ModelAssemblies.Load(fixture.NestedAndForwarded, fixture.Caller);
        var index = loaded.Index();
        var site = Site(index, Generic, MethodEdgeKind.CallVirt);
        Assert.Equal("P.Q`1.M(System.Int32)", site.ReferenceNodeId);
        Assert.True(index.IsOwnMethod("P.Q`1.M(!0)"));

        var resolution = index.Resolve(site.Target);
        var graph = MethodGraph.Build(index);

        Assert.Equal(ResolutionKind.External, resolution.Kind);
        Assert.Equal(Core, resolution.Assembly);
        Assert.Equal(site.ReferenceNodeId, resolution.NodeId);
        Assert.Empty(resolution.Candidates);
        Assert.DoesNotContain(graph.Successors(Generic), e => e.To == "P.Q`1.M(!0)");
        Assert.Contains(new MethodEdge(Generic, site.ReferenceNodeId, MethodEdgeKind.CallVirt, site.Offset), graph.Successors(Generic));
        Assert.Equal(MethodNodeKind.External, graph.Node(site.ReferenceNodeId)?.Kind);
    }

    /// <summary>
    /// (h) The coarse key on the ROW side too: the stub (which defines <c>P.Q`1</c>) with a hand-built forwarder table
    /// whose row spells the type <c>.P</c> / <c>Q</c> — no arity, a leading dot — still catches <c>P.Q&lt;int&gt;</c>.
    /// </summary>
    [Theory]
    [InlineData("P", "Q`1")]
    [InlineData(".P", "Q")]
    [InlineData("P", "Q`2")]
    public void Resolve_AGenericReference_IsCaughtByACoarselySpelledForwarderRow(string space, string name)
    {
        using var loaded = ModelAssemblies.Load(fixture.Stub, fixture.Caller);
        var (stub, caller) = (loaded.Disassemblers[0], loaded.Disassemblers[1]);
        var index = MemberIndex.Build([(stub.Assembly, TypeForwarders.Of([(space, name, Core)])), (caller.Assembly, caller.Forwarders)]);
        var site = Site(index, Generic, MethodEdgeKind.CallVirt);

        var resolution = index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Ambiguous, resolution.Kind);
        Assert.Equal(["P.Q`1.M(!0)", MemberIndex.Qualified(Core, site.ReferenceNodeId)], resolution.Candidates);
        Assert.True(index.Coverage.IsComplete);
    }

    // ---- (i): determinism ----------------------------------------------------------------------------------------------

    /// <summary>
    /// (i) Two builds over the same loads, and a build over the same files loaded in REVERSED order (fresh hosts), give
    /// identical resolutions at every call site and identical graphs, for every scenario above.
    /// </summary>
    [Theory]
    [InlineData("DefinedAndForwarded,Caller")]
    [InlineData("NestedAndForwarded,Caller")]
    [InlineData("PureForwarder,Shadow,Caller")]
    [InlineData("ChainForwarder,ChainTarget,Caller")]
    [InlineData("CycleForwarder,CycleTarget,Caller")]
    [InlineData("CycleDecoyForwarder,CycleDecoyTarget,Caller")]
    [InlineData("SelfForwarder,Caller")]
    [InlineData("ModuleDecoy,Caller")]
    [InlineData("ModuleOnly,Caller")]
    [InlineData("Stub,Caller")]
    public void Build_OverTheSameInputs_InEitherOrder_IsIdentical(string variants)
    {
        var paths = variants.Split(',').Select(fixture.Variant).ToArray();
        using var forward = ModelAssemblies.Load(paths);
        using var reversed = ModelAssemblies.Load([.. Enumerable.Reverse(paths)]);

        var (first, again, backwards) = (forward.Index(), forward.Index(), reversed.Index());

        var expected = Answers(first);
        Assert.NotEmpty(expected);
        Assert.Equal(expected, Answers(again));
        Assert.Equal(expected, Answers(backwards));

        var graph = MethodGraph.Build(first);
        foreach (var other in new[] { MethodGraph.Build(again), MethodGraph.Build(backwards) })
        {
            Assert.Equal(graph.Nodes, other.Nodes);
            Assert.Equal(graph.Edges, other.Edges);
            Assert.Equal(graph.Opacities, other.Opacities);
            Assert.Equal(graph.Coverage, other.Coverage);
        }
    }

    // Every call site's resolution, as comparable text (a Definition belongs to one host, so only its presence counts).
    private static string[] Answers(MemberIndex index) =>
        [.. ModelCallSite.All(index)
            .Select(s => (Site: s, Resolution: index.Resolve(s.Target)))
            .Select(x => string.Join(" | ",
                x.Site.Caller.NodeId, x.Site.Offset, x.Site.Kind, x.Resolution.Kind, x.Resolution.NodeId, x.Resolution.ClassificationKey,
                x.Resolution.Assembly, x.Resolution.IsOwn, x.Resolution.Reason, string.Join(", ", x.Resolution.Candidates)))
            .Order(StringComparer.Ordinal)];

    // Runs Client.Caller.method() from the emitted caller with each named assembly pinned to the given file.
    private object? Run(Dictionary<string, string> pinned, string method)
    {
        using var context = new IsolatedLoadContext(pinned);
        var caller = context.LoadBytes(fixture.Caller);
        return caller.GetType("Client.Caller", throwOnError: true)!.GetMethod(method)!.Invoke(null, null);
    }

    // What Run throws, unwrapped from the reflection invocation; fails if it returns.
    private Exception Thrown(Dictionary<string, string> pinned, string method)
    {
        var thrown = Record.Exception(() => Run(pinned, method));
        Assert.True(thrown is not null, $"{method} returned instead of failing to bind.");
        return thrown is TargetInvocationException { InnerException: { } inner } ? inner : thrown;
    }

    private static string CycleBackToFwdA(string from) => $"the type forwarders of {from} lead back to FwdA: a cycle, or a second way into it";

    private static ModelCallSite Site(MemberIndex index, string caller, MethodEdgeKind kind = MethodEdgeKind.Call) =>
        Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId == caller && s.Kind == kind);
    #endregion

    #region Fields
    private const string Core = "System.Private.CoreLib";
    private const string Platform = "PLATFORM-VALUE";
    private const string GetEnvironmentVariable = "System.Environment.GetEnvironmentVariable(System.String)";
    private const string QualifiedGetEnvironmentVariable = "[" + Core + "]" + GetEnvironmentVariable;
    private const string FwdAGetEnvironmentVariable = "[FwdA]" + GetEnvironmentVariable;
    private const string ModuleReason = "FwdA exports this type from module file " + TypeForwarderFixture.Module + ", which is not indexed";
    private const string EnvironmentKey = "System.Environment.GetEnvironmentVariable";
    private const string Env = "Client.Caller.Env()";
    private const string Generic = "Client.Caller.Generic()";
    private const string Forwarded = "Client.Caller.Forwarded()";
    private const string HeapCaller = "Heap.Caller.M0()";
    private const string ForwardedGeneric = "Client.Caller.ForwardedGeneric()";

    private readonly TypeForwarderFixture fixture;
    #endregion
}

/// <summary>
/// The emitted assemblies of <see cref="TypeForwarderResolutionTests"/>, each in its own subdirectory of one
/// <see cref="EmittedAssembly"/> (several variants share the name <c>FwdA</c>):
/// <list type="bullet">
/// <item><description><see cref="Stub"/> — <c>FwdA</c> defining every type the caller names, no forwarders: top-level
/// <c>System.Environment.GetEnvironmentVariable(string)</c> (the decoy), <c>P.Q`1.M(T)</c>, <c>NS.T.M()</c> (1) and
/// <c>NS.G`1.M(T)</c> (1).</description></item>
/// <item><description><see cref="Caller"/> — <c>FwdB</c>, emitted against the stub: <c>Client.Caller</c> with
/// <c>Env()</c> (<c>GetEnvironmentVariable(</c><see cref="Variable"/><c>)</c>), <c>Generic()</c>
/// (<c>new P.Q&lt;int&gt;().M(1)</c>), <c>Forwarded()</c> (<c>NS.T.M()</c>) and <c>ForwardedGeneric()</c>
/// (<c>new NS.G&lt;int&gt;().M(1)</c>).</description></item>
/// <item><description><see cref="DefinedAndForwarded"/> — <c>FwdA</c>: TypeDef decoys <c>System.Environment</c> and
/// <c>P.Q`1</c>, AND forwarders of both to System.Private.CoreLib.</description></item>
/// <item><description><see cref="NestedAndForwarded"/> — <c>FwdA</c>: nested decoys <c>System+Environment</c> and
/// <c>P+Q`1</c> (same node ids), and the same forwarders.</description></item>
/// <item><description><see cref="PureForwarder"/> — <c>FwdA</c>: only a forwarder of <c>System.Environment</c>.</description></item>
/// <item><description><see cref="Shadow"/> — <c>FwdC</c>: its own top-level <c>System.Environment.GetEnvironmentVariable(string)</c>.</description></item>
/// <item><description><see cref="ChainForwarder"/> / <see cref="ChainTarget"/> — <c>FwdA</c> forwards <c>NS.T</c> and
/// <c>NS.G`1</c> to <c>FwdT</c>, which defines them (2).</description></item>
/// <item><description><see cref="CycleForwarder"/> / <see cref="CycleTarget"/> — <c>FwdA</c> forwards <c>NS.T</c> to
/// <c>FwdT</c> and <c>FwdT</c> forwards it back; neither defines it.</description></item>
/// <item><description><see cref="CycleDecoyForwarder"/> / <see cref="CycleDecoyTarget"/> — <c>FwdA</c> defines the
/// <c>System.Environment</c> decoy AND forwards it to <c>FwdT</c>, which forwards it back (review 5 W-A).</description></item>
/// <item><description><see cref="SelfForwarder"/> — <c>FwdA</c> defines the decoy and forwards <c>System.Environment</c>
/// to itself (W-A).</description></item>
/// <item><description><see cref="ModuleDecoy"/> / <see cref="ModuleOnly"/> — <c>FwdA</c> exports
/// <c>System.Environment</c> from module file <see cref="Module"/> (an <c>ExportedType</c> implemented by a <c>File</c>
/// row), with and without the decoy (W-B).</description></item>
/// </list>
/// </summary>
public sealed class TypeForwarderFixture : IDisposable
{
    #region Constructors
    public TypeForwarderFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            Stub = emitted.Save("FwdA", module => { EnvironmentDecoy(module); QDecoy(module); Forwardable(module, 1); }, "stub");
            // The caller names [FwdA] types by token; it is emitted against the stub, loaded from bytes into a
            // collectible context so the default context never sees an assembly called FwdA.
            using (var context = new IsolatedLoadContext())
            {
                var stub = context.LoadBytes(Stub);
                Caller = emitted.Save("FwdB", module => DefineCaller(module, stub, Variable), "caller");
            }

            var toCore = EmittedAssembly.Forwarding(("System", "Environment", Core), ("P", "Q`1", Core));
            DefinedAndForwarded = emitted.Save("FwdA", module => { EnvironmentDecoy(module); QDecoy(module); }, toCore, "deffwd");
            NestedAndForwarded = emitted.Save("FwdA", NestedDecoys, toCore, "nestfwd");
            PureForwarder = emitted.Save("FwdA", module => Marker(module, "Pure"), EmittedAssembly.Forwarding(("System", "Environment", Core)), "pure");
            Shadow = emitted.Save("FwdC", EnvironmentDecoy, "shadow");
            ChainForwarder = emitted.Save("FwdA", module => Marker(module, "Chain"), EmittedAssembly.Forwarding(("NS", "T", "FwdT"), ("NS", "G`1", "FwdT")), "chain");
            ChainTarget = emitted.Save("FwdT", module => Forwardable(module, 2), "chain");
            CycleForwarder = emitted.Save("FwdA", module => Marker(module, "Cycle"), EmittedAssembly.Forwarding(("NS", "T", "FwdT")), "cycle");
            CycleTarget = emitted.Save("FwdT", module => Marker(module, "CycleBack"), EmittedAssembly.Forwarding(("NS", "T", "FwdA")), "cycle");
            CycleDecoyForwarder = emitted.Save("FwdA", EnvironmentDecoy, EmittedAssembly.Forwarding(("System", "Environment", "FwdT")), "cycledecoy");
            CycleDecoyTarget = emitted.Save("FwdT", module => Marker(module, "CycleBack"), EmittedAssembly.Forwarding(("System", "Environment", "FwdA")), "cycledecoy");
            SelfForwarder = emitted.Save("FwdA", EnvironmentDecoy, EmittedAssembly.Forwarding(("System", "Environment", "FwdA")), "self");
            ModuleDecoy = emitted.Save("FwdA", EnvironmentDecoy, EmittedAssembly.ExportingFromModule(Module, ("System", "Environment")), "moduledecoy");
            ModuleOnly = emitted.Save("FwdA", module => Marker(module, "Module"), EmittedAssembly.ExportingFromModule(Module, ("System", "Environment")), "moduleonly");
            // A2Multi S2: the nested decoys with NO forwarder, and a caller (FwdN) emitted against them, so its reference
            // names the NESTED type System+Environment itself (the positive control of MemberIndexHygieneTests).
            NestedOnly = emitted.Save("FwdA", NestedDecoys, "nestonly");
            using (var context = new IsolatedLoadContext())
            {
                var nested = context.LoadBytes(NestedOnly);
                NestedCaller = emitted.Save("FwdN", module => DefineNestedCaller(module, nested, Variable), "nestcaller");
            }
        }
        catch (Exception)
        {
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    /// <summary>The environment variable <c>Client.Caller.Env()</c> reads: unique per fixture, set only inside a test.</summary>
    public string Variable { get; } = $"SILVERGUN_FWD_TEST_{Guid.NewGuid():N}";

    public string Stub { get; }

    public string Caller { get; }

    public string DefinedAndForwarded { get; }

    public string NestedAndForwarded { get; }

    public string PureForwarder { get; }

    public string Shadow { get; }

    public string ChainForwarder { get; }

    public string ChainTarget { get; }

    public string CycleForwarder { get; }

    public string CycleTarget { get; }

    public string CycleDecoyForwarder { get; }

    public string CycleDecoyTarget { get; }

    public string SelfForwarder { get; }

    public string ModuleDecoy { get; }

    public string ModuleOnly { get; }

    /// <summary><c>FwdA</c> with only the nested decoys <c>System+Environment</c> and <c>P+Q`1</c>, and no forwarder (A2Multi S2).</summary>
    public string NestedOnly { get; }

    /// <summary><c>FwdN</c>, emitted against <see cref="NestedOnly"/>: <c>Client.NestedCaller.Env()</c> calls the NESTED <c>System+Environment.GetEnvironmentVariable</c>.</summary>
    public string NestedCaller { get; }
    #endregion

    #region Methods
    /// <summary>The path of the variant named by its property (so theories can name variants in attributes).</summary>
    public string Variant(string name) =>
        typeof(TypeForwarderFixture).GetProperty(name)?.GetValue(this) as string ?? throw new ArgumentException($"No variant '{name}'.", nameof(name));

    public void Dispose() => emitted.Dispose();

    private static void EnvironmentDecoy(ModuleBuilder module)
    {
        var environment = module.DefineType("System.Environment", StaticClass);
        Returning(environment, "GetEnvironmentVariable", StaticMethod, typeof(string), [typeof(string)], Decoy);
        environment.CreateType();
    }

    private static void QDecoy(ModuleBuilder module)
    {
        var q = module.DefineType("P.Q`1", TypeAttributes.Public | TypeAttributes.Class);
        var t = q.DefineGenericParameters("T")[0];
        q.DefineDefaultConstructor(MethodAttributes.Public);
        Returning(q, "M", InstanceMethod, typeof(string), [t], Decoy);
        q.CreateType();
    }

    // Global types System and P, with nested Environment and Q`1: the same node ids as the top-level decoys.
    private static void NestedDecoys(ModuleBuilder module)
    {
        var system = module.DefineType("System", StaticClass);
        var environment = system.DefineNestedType("Environment", TypeAttributes.NestedPublic | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        Returning(environment, "GetEnvironmentVariable", StaticMethod, typeof(string), [typeof(string)], Decoy);
        var p = module.DefineType("P", StaticClass);
        var q = p.DefineNestedType("Q`1", TypeAttributes.NestedPublic | TypeAttributes.Class);
        var t = q.DefineGenericParameters("T")[0];
        q.DefineDefaultConstructor(MethodAttributes.Public);
        Returning(q, "M", InstanceMethod, typeof(string), [t], Decoy);
        foreach (var type in new[] { system, environment, p, q })
            type.CreateType();
    }

    // NS.T.M() and NS.G`1<T>.M(T), each returning value.
    private static void Forwardable(ModuleBuilder module, int value)
    {
        var t = module.DefineType("NS.T", StaticClass);
        Returning(t, "M", StaticMethod, typeof(int), Type.EmptyTypes, value);
        var g = module.DefineType("NS.G`1", TypeAttributes.Public | TypeAttributes.Class);
        var parameter = g.DefineGenericParameters("T")[0];
        g.DefineDefaultConstructor(MethodAttributes.Public);
        Returning(g, "M", InstanceMethod, typeof(int), [parameter], value);
        t.CreateType();
        g.CreateType();
    }

    // Keeps a forwarder-only assembly from being empty of types.
    private static void Marker(ModuleBuilder module, string space) =>
        module.DefineType(space + ".Marker", TypeAttributes.Public | TypeAttributes.Class).CreateType();

    private static void DefineCaller(ModuleBuilder module, Assembly stub, string variable)
    {
        var caller = module.DefineType("Client.Caller", StaticClass);

        var il = Callers(caller, "Env", typeof(string));
        il.Emit(OpCodes.Ldstr, variable);
        il.Emit(OpCodes.Call, stub.GetType("System.Environment", throwOnError: true)!.GetMethod("GetEnvironmentVariable")!);
        il.Emit(OpCodes.Ret);

        CallThrough(Callers(caller, "Generic", typeof(string)), stub.GetType("P.Q`1", throwOnError: true)!.MakeGenericType(typeof(int)));

        il = Callers(caller, "Forwarded", typeof(int));
        il.Emit(OpCodes.Call, stub.GetType("NS.T", throwOnError: true)!.GetMethod("M")!);
        il.Emit(OpCodes.Ret);

        CallThrough(Callers(caller, "ForwardedGeneric", typeof(int)), stub.GetType("NS.G`1", throwOnError: true)!.MakeGenericType(typeof(int)));

        caller.CreateType();
    }

    // Client.NestedCaller.Env() => System+Environment.GetEnvironmentVariable(variable), naming the nested type itself.
    private static void DefineNestedCaller(ModuleBuilder module, Assembly nested, string variable)
    {
        var caller = module.DefineType("Client.NestedCaller", StaticClass);
        var il = Callers(caller, "Env", typeof(string));
        il.Emit(OpCodes.Ldstr, variable);
        il.Emit(OpCodes.Call, nested.GetType("System+Environment", throwOnError: true)!.GetMethod("GetEnvironmentVariable")!);
        il.Emit(OpCodes.Ret);
        caller.CreateType();
    }

    private static ILGenerator Callers(TypeBuilder caller, string name, Type returns) =>
        caller.DefineMethod(name, MethodAttributes.Public | MethodAttributes.Static, returns, Type.EmptyTypes).GetILGenerator();

    // newobj closed::.ctor; ldc.i4.1; callvirt closed::M; ret
    private static void CallThrough(ILGenerator il, Type closed)
    {
        il.Emit(OpCodes.Newobj, closed.GetConstructor(Type.EmptyTypes)!);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, closed.GetMethod("M")!);
        il.Emit(OpCodes.Ret);
    }

    private static void Returning(TypeBuilder owner, string name, MethodAttributes attributes, Type returns, Type[] parameters, object value)
    {
        var il = owner.DefineMethod(name, attributes, returns, parameters).GetILGenerator();
        if (value is string text)
            il.Emit(OpCodes.Ldstr, text);
        else
            il.Emit(OpCodes.Ldc_I4, (int)value);
        il.Emit(OpCodes.Ret);
    }
    #endregion

    #region Fields
    /// <summary>What every decoy body returns.</summary>
    public const string Decoy = "DECOY-BODY";

    /// <summary>The module file the <see cref="ModuleDecoy"/> and <see cref="ModuleOnly"/> variants export from (never written).</summary>
    public const string Module = "FwdA2.netmodule";

    private const string Core = "System.Private.CoreLib";
    private const TypeAttributes StaticClass = TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class;
    private const MethodAttributes StaticMethod = MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig;
    private const MethodAttributes InstanceMethod = MethodAttributes.Public | MethodAttributes.HideBySig;

    private readonly EmittedAssembly emitted;
    #endregion
}
