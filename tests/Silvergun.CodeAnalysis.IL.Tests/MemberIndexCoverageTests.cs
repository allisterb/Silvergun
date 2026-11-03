namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelTypes = Model.Types;

/// <summary>
/// Review 1's W-findings on the A1 member index (spec §2.5):
/// <list type="bullet">
/// <item><description><b>W1</b> — what the index could not read is COUNTED (<see cref="IndexCoverage"/>, surfaced as
/// <see cref="GraphCoverage.Index"/>), never skipped silently.</description></item>
/// <item><description><b>W2</b> — a reference whose declaring assembly cannot be read is
/// <see cref="ResolutionKind.Unresolved"/>, not <see cref="ResolutionKind.External"/>: External is a claim ("a platform
/// leaf, classify it"), and failing open to it dropped the walk.</description></item>
/// <item><description><b>W3</b> — the same <c>Model.Assembly</c> instance handed over twice is one assembly, not an
/// ambiguity and not an exception.</description></item>
/// </list>
/// W2 and the unreadable-assembly half of W1 use hand-built Model objects (Analysis.Net's public
/// <c>MethodReference</c>/<c>BasicType</c>/<c>Model.Assembly</c>), the cheap way to an unreadable input: no compiled
/// fixture can make a metadata name throw.
/// </summary>
public sealed class MemberIndexCoverageTests : IClassFixture<MechanismMethodGraphFixture>
{
    #region Constructors
    public MemberIndexCoverageTests(MechanismMethodGraphFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- W3 -----------------------------------------------------------------------------------------------------

    [Fact]
    public void Build_TheSameAssemblyInstanceTwice_DoesNotThrow_AndIndexesEachMethodOnce()
    {
        var mechanism = fixture.Assemblies.Disassemblers.Select(d => (d.Assembly, d.Forwarders)).ToArray();
        var doubled = mechanism.Concat(mechanism).Prepend(mechanism[0]).ToArray();

        MemberIndex? index = null;
        var thrown = Record.Exception(() => index = MemberIndex.Build(doubled));

        Assert.Null(thrown);
        Assert.NotNull(index);
        Assert.Equal(fixture.Index.Methods.Select(m => (m.Assembly, m.NodeId)), index!.Methods.Select(m => (m.Assembly, m.NodeId)));
        Assert.Equal(fixture.Index.Assemblies, index.Assemblies);
        Assert.All(index.TypeIds, id => Assert.Single(index.Types(id)));
        Assert.True(index.Coverage.IsComplete);

        // Not ambiguous: the graph over it is the graph over the single copy, the two honest Overloads sites aside.
        var graph = MethodGraph.Build(index);
        Assert.Equal(fixture.Graph.Edges, graph.Edges);
        Assert.Equal(fixture.Graph.Opacities, graph.Opacities);
        Assert.Equal(fixture.Graph.Coverage, graph.Coverage);
    }

    /// <summary>
    /// A null <c>Model.Assembly</c> is skipped — and so is its forwarder table: an entry that is not an assembly is not
    /// counted as an unreadable forwarder table either.
    /// </summary>
    [Fact]
    public void Build_WithNullEntries_SkipsThem()
    {
        var mechanism = fixture.Assemblies.Disassemblers.Select(d => (d.Assembly, d.Forwarders)).ToArray();

        var index = MemberIndex.Build([(null!, TypeForwarders.None), .. mechanism, (null!, null!)]);

        Assert.Equal(fixture.Index.Methods.Select(m => (m.Assembly, m.NodeId)), index.Methods.Select(m => (m.Assembly, m.NodeId)));
        Assert.Equal(new IndexCoverage(0, 0, 0), index.Coverage);
    }

    /// <summary>The disassembler overload skips null disassemblers the same way.</summary>
    [Fact]
    public void Build_WithNullDisassemblers_SkipsThem()
    {
        var index = MemberIndex.Build([null!, .. fixture.Assemblies.Disassemblers, null!]);

        Assert.Equal(fixture.Index.Methods.Select(m => (m.Assembly, m.NodeId)), index.Methods.Select(m => (m.Assembly, m.NodeId)));
        Assert.Equal(new IndexCoverage(0, 0, 0), index.Coverage);
    }

    // ---- W1 -----------------------------------------------------------------------------------------------------

    [Fact]
    public void Coverage_OnTheMechanismFixture_IsAllZero_AndComplete()
    {
        Assert.Equal(new IndexCoverage(0, 0, 0), fixture.Index.Coverage);
        Assert.True(fixture.Index.Coverage.IsComplete);
        Assert.Same(fixture.Index.Coverage, fixture.Graph.Coverage.Index);
    }

    [Fact]
    public void Coverage_OnTheSharedAndTheShadowFixtures_IsAllZero_AndComplete()
    {
        using var shared = ModelAssemblies.Load(SharedFixtureMethodGraphFixture.Path);
        using var shadow = ModelAssemblies.Load(ShadowFixtureAssembly.Path);

        Assert.Equal(new IndexCoverage(0, 0, 0), shared.Index().Coverage);
        Assert.Equal(new IndexCoverage(0, 0, 0), shadow.Index().Coverage);
    }

    [Theory]
    [InlineData(0, 0, 0, 0, true)]
    [InlineData(1, 0, 0, 0, false)]
    [InlineData(0, 1, 0, 0, false)]
    [InlineData(0, 0, 1, 0, false)]
    [InlineData(0, 0, 0, 1, false)]
    public void IndexCoverage_IsComplete_OnlyWhenNothingWasSkipped(int assemblies, int types, int methods, int forwarders, bool complete) =>
        Assert.Equal(complete, new IndexCoverage(assemblies, types, methods, forwarders).IsComplete);

    /// <summary>The three-argument form (no forwarder count) means every forwarder table was read.</summary>
    [Fact]
    public void IndexCoverage_WithoutAForwarderCount_CountsNoUnreadableForwarders() =>
        Assert.Equal(new IndexCoverage(0, 0, 0, 0), new IndexCoverage(0, 0, 0));

    /// <summary>
    /// An assembly whose type list cannot be read (here a <c>Model.Assembly</c> with no root namespace, so
    /// <c>GetAllTypes</c> throws) is counted in <see cref="IndexCoverage.AssembliesUnreadable"/>, surfaced unchanged in
    /// the graph's coverage, and does not cost the readable assemblies anything.
    /// </summary>
    [Fact]
    public void Build_WithAnAssemblyWhoseTypesCannotBeRead_CountsIt_AndIndexesTheRest()
    {
        var unreadable = new Model.Assembly(UnreadableAssembly);
        Assert.Null(unreadable.RootNamespace);

        // A synthetic assembly has no file, so it forwards nothing: only its type list is unreadable.
        var index = MemberIndex.Build([.. fixture.Assemblies.Disassemblers.Select(d => (d.Assembly, d.Forwarders)), (unreadable, TypeForwarders.None)]);
        var graph = MethodGraph.Build(index);

        Assert.Equal(new IndexCoverage(1, 0, 0), index.Coverage);
        Assert.False(index.Coverage.IsComplete);
        Assert.Same(index.Coverage, graph.Coverage.Index);
        Assert.Equal(fixture.Index.Methods.Select(m => (m.Assembly, m.NodeId)), index.Methods.Select(m => (m.Assembly, m.NodeId)));
        Assert.Equal(fixture.Graph.Edges, graph.Edges);
    }

    /// <summary>
    /// The unreadable assembly is still one of the INDEXED assemblies (its name was readable), so a reference into it
    /// cannot be called a platform leaf: it is <see cref="ResolutionKind.Unresolved"/> — fail closed — not External.
    /// </summary>
    [Fact]
    public void Resolve_IntoAnIndexedButUnreadableAssembly_IsUnresolved_NotExternal()
    {
        var index = MemberIndex.Build([
            .. fixture.Assemblies.Disassemblers.Select(d => (d.Assembly, d.Forwarders)),
            (new Model.Assembly(UnreadableAssembly), TypeForwarders.None)]);

        var resolution = index.Resolve(Reference("Unreadable.Space", "Thing", "Run", new Model.AssemblyReference(UnreadableAssembly)));

        Assert.Contains(UnreadableAssembly, index.Assemblies);
        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.Equal("Unreadable.Space.Thing.Run()", resolution.NodeId);
        Assert.Equal(UnreadableAssembly, resolution.Assembly);
        Assert.Equal("no indexed definition matches", resolution.Reason);
    }

    // ---- W2 -----------------------------------------------------------------------------------------------------

    /// <summary>
    /// The control for the W2 cases below: a hand-built reference (no host, no metadata) to a real fixture method
    /// resolves Exact, and one into an unindexed assembly External — so the synthetic references exercise the real
    /// paths, and only the unreadable assembly name makes the difference.
    /// </summary>
    [Fact]
    public void Resolve_AHandBuiltReference_TakesTheSamePathsAsARealOne()
    {
        var own = fixture.Index.Resolve(Reference("MechanismFixture.Direct", "Probes", "ReadsEnv", new Model.AssemblyReference(MechanismFixtureAssemblies.FixtureName)));
        var external = fixture.Index.Resolve(Reference("Some.Platform", "Thing", "Run", new Model.AssemblyReference("Some.Platform")));

        Assert.Equal(ResolutionKind.Exact, own.Kind);
        Assert.Equal("MechanismFixture.Direct.Probes.ReadsEnv()", own.NodeId);
        Assert.True(own.IsOwn);
        Assert.Equal(ResolutionKind.External, external.Kind);
        Assert.Equal("Some.Platform", external.Assembly);
    }

    [Fact]
    public void Resolve_WhenTheDeclaringAssemblyNameThrows_IsUnresolved_NotExternal()
    {
        var resolution = fixture.Index.Resolve(Reference("Some.Platform", "Thing", "Run", new ThrowingAssemblyReference()));

        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Assembly);
        Assert.Empty(resolution.Candidates);
        Assert.Equal("Some.Platform.Thing.Run()", resolution.NodeId);
        Assert.Equal("declaring assembly unreadable", resolution.Reason);
    }

    [Fact]
    public void Resolve_WhenTheDeclaringAssemblyIsMissing_IsUnresolved_NotExternal()
    {
        var resolution = fixture.Index.Resolve(Reference("Some.Platform", "Thing", "Run", null));

        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.Null(resolution.Assembly);
        Assert.Equal("declaring assembly unreadable", resolution.Reason);
    }

    // A parameterless static method reference built by hand: namespace.type.name() in `assembly`.
    private static ModelTypes.MethodReference Reference(string space, string type, string name, Model.IAssemblyReference? assembly) =>
        new(name, new ModelTypes.BasicType("Void") { ContainingNamespace = "System" })
        {
            ContainingType = new ModelTypes.BasicType(type) { ContainingNamespace = space, ContainingAssembly = assembly },
            IsStatic = true,
        };
    #endregion

    #region Fields
    private const string UnreadableAssembly = "Silvergun.Tests.UnreadableAssembly";

    private readonly MechanismMethodGraphFixture fixture;
    #endregion

    #region Child types
    /// <summary>An assembly reference whose name cannot be read - what a corrupt or hostile module can hand back.</summary>
    private sealed class ThrowingAssemblyReference : Model.IAssemblyReference
    {
        public string Name => throw new BadImageFormatException("unreadable assembly name (synthetic)");
    }
    #endregion
}
