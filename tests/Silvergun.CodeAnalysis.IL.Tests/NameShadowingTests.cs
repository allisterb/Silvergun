namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Review 1, finding C2 (spec §2.5): node ids are not assembly-qualified, so a package that defines its own
/// <c>System.Environment.GetEnvironmentVariable(string)</c> and ALSO calls the platform's used to have the platform
/// call merged into its own benign node — the sink was walked through the package's body instead of being classified,
/// and the capability vanished. The fix keeps them apart: a non-Own target whose node id is also an own method's gets
/// the id <c>[assembly]nodeId</c> (<see cref="MemberIndex.Qualified"/>) and a <see cref="OpacityKind.NameShadowed"/>
/// record; supertypes are scoped the same way, so the platform <c>System.IDisposable</c> and an own one stay two keys
/// in the subtype map (A2's CHA is driven from it).
/// <para>
/// Over <c>Silvergun.CodeAnalysis.IL.Tests.ShadowFixture</c> (located by path, see <see cref="ShadowFixtureAssembly"/>),
/// indexed ALONE: it calls the real sink through an extern alias (<c>platform::System.Environment</c>) and its own
/// shadow unqualified, and has one class implementing each <c>IDisposable</c>.
/// </para>
/// </summary>
public sealed class NameShadowingTests : IClassFixture<ShadowMethodGraphFixture>
{
    #region Constructors
    public NameShadowingTests(ShadowMethodGraphFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>The build-order-only reference really kept the fixture (and its public System.Environment) out of this host.</summary>
    [Fact]
    public void ShadowFixture_IsNeitherNextToTheTestAssembly_NorLoaded()
    {
        Assert.False(File.Exists(Path.Combine(AppContext.BaseDirectory, ShadowFixtureAssembly.Name + ".dll")));
        Assert.DoesNotContain(AppDomain.CurrentDomain.GetAssemblies(), a => a.GetName().Name == ShadowFixtureAssembly.Name);
        Assert.Equal([ShadowFixtureAssembly.Name], fixture.Index.Assemblies);
    }

    /// <summary>
    /// The premise, measured: both call sites render the SAME node id, one declared by the platform and one by the
    /// fixture. The platform's declaring assembly is read off the reference, not assumed: the fixture compiles against
    /// the net10.0 reference assemblies, where <c>System.Environment</c> is declared by <c>System.Runtime</c>.
    /// </summary>
    [Fact]
    public void Premise_ThePlatformSinkAndTheOwnShadow_ShareOneNodeId()
    {
        Assert.Equal(PlatformAssembly, fixture.PlatformSite.DeclaringAssembly);
        Assert.Equal(ShadowFixtureAssembly.Name, fixture.ShadowSite.DeclaringAssembly);
        Assert.Equal(GetEnv, fixture.PlatformSite.ReferenceNodeId);
        Assert.Equal(GetEnv, fixture.ShadowSite.ReferenceNodeId);
        Assert.True(fixture.Index.IsOwnMethod(GetEnv));
    }

    [Fact]
    public void Resolve_ThePlatformCall_IsExternal_InItsOwnDeclaringAssembly()
    {
        var resolution = fixture.Index.Resolve(fixture.PlatformSite.Target);

        Assert.Equal(ResolutionKind.External, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Equal(GetEnv, resolution.NodeId);
        Assert.Equal(PlatformAssembly, resolution.Assembly);
        Assert.Empty(resolution.Candidates);
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.EnvironmentProbe), CapabilityMap.Default.Classify(resolution.ClassificationKey));
    }

    /// <summary>
    /// The fix: the platform call's edge goes to the assembly-qualified External node — classified as the sink — and
    /// NOT to the own node of the same bare id.
    /// </summary>
    [Fact]
    public void Build_ThePlatformCall_GetsAnEdgeToTheAssemblyQualifiedExternalNode_ClassifiedAsTheSink()
    {
        var site = fixture.PlatformSite;

        Assert.Equal(QualifiedGetEnv, MemberIndex.Qualified(PlatformAssembly, GetEnv));
        Assert.Equal([new MethodEdge(ReadsPlatform, QualifiedGetEnv, MethodEdgeKind.Call, site.Offset)], fixture.Graph.Successors(ReadsPlatform));
        Assert.Equal(MethodNodeKind.External, fixture.Graph.Node(QualifiedGetEnv)?.Kind);
        Assert.Equal(Capability.EnvironmentProbe, MechanismGraphSource.From(fixture.Graph).CapabilityOf(QualifiedGetEnv));
        Assert.DoesNotContain(fixture.Graph.Edges, e => e.From == ReadsPlatform && e.To == GetEnv);
    }

    [Fact]
    public void Build_RecordsExactlyOneNameShadowedOpacity_AtThePlatformCallSite()
    {
        Assert.Equal(
            [new GraphOpacity(ReadsPlatform, fixture.PlatformSite.Offset, OpacityKind.NameShadowed, $"{GetEnv} in {PlatformAssembly} shares its name with an own method")],
            fixture.Graph.Opacities);
    }

    /// <summary>
    /// The own shadow is its own node (with a body, walked: it calls safe <c>String.Concat</c>), reached Exact from
    /// <c>ReadsShadowEnvironment</c> — and since own nodes are never classified, that caller reaches no capability while
    /// the platform caller reaches EnvironmentProbe. Before the fix both callers led to the one merged node.
    /// </summary>
    [Fact]
    public void Build_TheOwnShadow_IsADistinctOwnNode_WalkedFromReadsShadowEnvironment()
    {
        var resolution = fixture.Index.Resolve(fixture.ShadowSite.Target);
        var source = MechanismGraphSource.From(fixture.Graph);

        Assert.Equal(ResolutionKind.Exact, resolution.Kind);
        Assert.Equal(GetEnv, resolution.NodeId);
        Assert.Equal(ShadowFixtureAssembly.Name, resolution.Assembly);
        Assert.Equal(MethodNodeKind.OwnWithBody, fixture.Graph.Node(GetEnv)?.Kind);
        Assert.NotEqual(GetEnv, QualifiedGetEnv);
        Assert.Equal([new MethodEdge(ReadsShadow, GetEnv, MethodEdgeKind.Call, fixture.ShadowSite.Offset)], fixture.Graph.Successors(ReadsShadow));
        Assert.Contains(fixture.Graph.Successors(GetEnv), e => e.To == "System.String.Concat(System.String,System.String)");

        Assert.Null(WaypointMatcher.FindPathToSink(source.Adjacency, Anchored(ReadsShadow), n => source.CapabilityOf(n) is not null));
        Assert.Equal(
            [ReadsPlatform, QualifiedGetEnv],
            WaypointMatcher.FindPathToSink(source.Adjacency, Anchored(ReadsPlatform), n => source.CapabilityOf(n) == Capability.EnvironmentProbe));
    }

    /// <summary>
    /// Supertypes are scoped like method targets: <c>PlatformDisposable</c> implements the PLATFORM
    /// <c>System.IDisposable</c> and is listed under its qualified id; <c>ShadowDisposable</c> implements the OWN one and
    /// is listed under the bare id. <c>System.Object</c> is not shadowed, so it stays bare.
    /// </summary>
    [Fact]
    public void Subtypes_ThePlatformAndTheOwnIDisposable_StayDifferentKeys()
    {
        Assert.Equal(["ShadowFixture.PlatformDisposable"], fixture.Index.DirectSubtypes(QualifiedIDisposable));
        Assert.Equal(["ShadowFixture.ShadowDisposable"], fixture.Index.DirectSubtypes("System.IDisposable"));
        Assert.Equal(["System.Object", QualifiedIDisposable], Assert.Single(fixture.Index.Types("ShadowFixture.PlatformDisposable")).Supertypes);
        Assert.Equal(["System.IDisposable", "System.Object"], Assert.Single(fixture.Index.Types("ShadowFixture.ShadowDisposable")).Supertypes);
        Assert.Contains("System.IDisposable", fixture.Index.TypeIds);
        Assert.DoesNotContain(QualifiedIDisposable, fixture.Index.TypeIds);
    }

    /// <summary>Nothing skipped, nothing ambiguous; every own site Exact and every platform site External.</summary>
    [Fact]
    public void Coverage_IsComplete_AndTheCountsAddUp()
    {
        var own = fixture.Sites.Count(s => s.DeclaringAssembly == ShadowFixtureAssembly.Name);
        var counts = fixture.Graph.Coverage.Resolutions;

        Assert.True(fixture.Index.Coverage.IsComplete);
        Assert.Equal(new IndexCoverage(0, 0, 0), fixture.Graph.Coverage.Index);
        Assert.Equal(new ResolutionCounts(own, 0, fixture.Sites.Count - own, 0, 0), counts);
        Assert.Equal(fixture.Sites.Count, fixture.Graph.Edges.Count);
    }

    private static string Anchored(string nodeId) => "^" + Regex.Escape(nodeId) + "$";
    #endregion

    #region Fields
    private const string PlatformAssembly = "System.Runtime";
    private const string GetEnv = "System.Environment.GetEnvironmentVariable(System.String)";
    private const string QualifiedGetEnv = "[System.Runtime]System.Environment.GetEnvironmentVariable(System.String)";
    private const string QualifiedIDisposable = "[System.Runtime]System.IDisposable";
    private const string ReadsPlatform = "ShadowFixture.Callers.ReadsPlatformEnvironment()";
    private const string ReadsShadow = "ShadowFixture.Callers.ReadsShadowEnvironment()";

    private readonly ShadowMethodGraphFixture fixture;
    #endregion
}

/// <summary>The shadow fixture loaded by path, indexed alone, and its A1 graph built; plus the two call sites under test.</summary>
public sealed class ShadowMethodGraphFixture : IDisposable
{
    #region Constructors
    public ShadowMethodGraphFixture()
    {
        Assemblies = ModelAssemblies.Load(ShadowFixtureAssembly.Path);
        try
        {
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
            Sites = ModelCallSite.All(Index);
            PlatformSite = Sites.Single(s => s.Caller.NodeId == "ShadowFixture.Callers.ReadsPlatformEnvironment()");
            ShadowSite = Sites.Single(s => s.Caller.NodeId == "ShadowFixture.Callers.ReadsShadowEnvironment()");
        }
        catch (Exception)
        {
            Assemblies.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public MethodGraph Graph { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }

    /// <summary>The single call site of <c>ReadsPlatformEnvironment</c>: <c>platform::System.Environment.GetEnvironmentVariable</c>.</summary>
    public ModelCallSite PlatformSite { get; }

    /// <summary>The single call site of <c>ReadsShadowEnvironment</c>: the own <c>System.Environment.GetEnvironmentVariable</c>.</summary>
    public ModelCallSite ShadowSite { get; }
    #endregion

    #region Methods
    public void Dispose() => Assemblies.Dispose();
    #endregion
}
