namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

/// <summary>
/// <see cref="PackageGraphs"/> (CHA A2Multi S1, docs/agent/tasks/cha-a2multi-package-graphs.md M1–M3 and "Tests"): one
/// call graph per package folder, over that folder's own assemblies only.
/// <list type="bullet">
/// <item><description>Grouping: TFM copies stay apart, <c>runtimes/&lt;rid&gt;/lib/&lt;tfm&gt;</c> and a nested directory
/// are their own graphs, one folder's assemblies go together, folders come in ordinal order.</description></item>
/// <item><description>Cross-assembly within a folder: the mechanism fixture and its Dependency in one
/// <c>lib/net10.0</c> hold the CrossAssembly path.</description></item>
/// <item><description>Load failures are recorded per assembly; the rest of the folder still builds; a folder of only
/// failures has no graph.</description></item>
/// <item><description>Laziness, determinism, and per-folder budget truncation.</description></item>
/// </list>
/// Packages are built on the fly (<see cref="NupkgBuilder"/>) from fixture DLLs located BY PATH next to this test
/// assembly, and every DLL is read only through <see cref="PackageGraphs"/> (or, for an oracle, <see cref="AssemblyDisassembler"/>)
/// — never loaded by the test host.
/// </summary>
public sealed class PackageGraphsTests : IDisposable
{
    #region Constructors
    public PackageGraphsTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        root = Directory.CreateTempSubdirectory("silvergun-pkggraphs-").FullName;
        shared = File.ReadAllBytes(Beside(SharedFixture));
        mechanism = File.ReadAllBytes(Beside(MechanismFixture));
        dependency = File.ReadAllBytes(Beside(MechanismDependency));
    }
    #endregion

    #region Methods
    // ---- grouping ------------------------------------------------------------------------------------------------------

    /// <summary>
    /// The same DLL under <c>lib/net8.0/</c> and <c>lib/netstandard2.0/</c> gives two graphs, one per folder, and each is
    /// exactly the graph over that one copy alone: nothing merged across copies, so no Ambiguous resolution or opacity and
    /// no edge that a single copy would not have.
    /// </summary>
    [Fact]
    public void Build_TfmCopiesOfOneAssembly_StayApart_EachTheGraphOfThatCopyAlone()
    {
        using var package = Open("TfmCopies", ($"lib/net8.0/{SharedFixture}", shared), ($"lib/netstandard2.0/{SharedFixture}", shared));

        var graphs = PackageGraphs.Build(package).ToArray();

        Assert.Equal(["lib/net8.0", "lib/netstandard2.0"], graphs.Select(g => g.Folder));
        var alone = Alone(Beside(SharedFixture));
        foreach (var graph in graphs)
        {
            Assert.Equal([$"{graph.Folder}/{SharedFixture}"], graph.Assemblies);
            Assert.Empty(graph.LoadFailures);
            Assert.NotNull(graph.Graph);
            Assert.Equal(0, graph.Graph!.Coverage.Resolutions.Ambiguous);
            Assert.DoesNotContain(graph.Graph.Opacities, o => o.Kind == OpacityKind.Ambiguous);
            Assert.Equal(alone.Edges, graph.Graph.Edges);
            Assert.Equal(alone.Nodes, graph.Graph.Nodes);
        }
    }

    /// <summary>
    /// The mechanism fixture and its Dependency in ONE folder are one graph, so the cross-assembly path holds:
    /// <c>CrossAssembly.Callers.UsesDependency()</c> → <c>Dependency.EnvReader.Read()</c> (an own node, walked) → the
    /// platform sink.
    /// </summary>
    [Fact]
    public void Build_OneFoldersAssemblies_AreOneGraph_WhereTheCrossAssemblyPathHolds()
    {
        using var package = Open("OneFolder", ($"lib/net10.0/{MechanismFixture}", mechanism), ($"lib/net10.0/{MechanismDependency}", dependency));

        var graph = Assert.Single(PackageGraphs.Build(package));

        Assert.Equal("lib/net10.0", graph.Folder);
        // Ordinal within the folder: "…MechanismFixture.Dependency.dll" < "…MechanismFixture.dll" ('D' < 'd').
        Assert.Equal([$"lib/net10.0/{MechanismDependency}", $"lib/net10.0/{MechanismFixture}"], graph.Assemblies);
        AssertCrossAssemblyPath(graph.Graph!);
        Assert.True(graph.Graph!.Coverage.Index.IsComplete);
    }

    /// <summary>
    /// Each directory is its own graph — the root, <c>analyzers/…</c>, <c>lib/net8.0</c>, a NESTED <c>lib/net8.0/sub</c>,
    /// <c>runtimes/win-x64/lib/net8.0</c> (never merged with <c>lib/net8.0</c>, which it replaces at run time) and
    /// <c>tools/…</c> — in ordinal order of the folder path ("" for the root first), whatever the entry order.
    /// </summary>
    [Fact]
    public void Build_EveryDirectoryIsItsOwnGraph_InOrdinalOrder()
    {
        using var package = Open("Layout",
            ($"tools/net8.0/any/{SharedFixture}", shared),
            ($"runtimes/win-x64/lib/net8.0/{SharedFixture}", shared),
            ($"lib/net8.0/sub/{MechanismDependency}", dependency),
            ($"lib/net8.0/{SharedFixture}", shared),
            ($"analyzers/dotnet/cs/{SharedFixture}", shared),
            (SharedFixture, shared));

        var graphs = PackageGraphs.Build(package).ToArray();

        Assert.Equal(["", "analyzers/dotnet/cs", "lib/net8.0", "lib/net8.0/sub", "runtimes/win-x64/lib/net8.0", "tools/net8.0/any"], graphs.Select(g => g.Folder));
        Assert.Equal(graphs.Select(g => g.Folder).Order(StringComparer.Ordinal), graphs.Select(g => g.Folder));
        Assert.All(graphs, g => Assert.Single(g.Assemblies));
        Assert.Equal([$"lib/net8.0/sub/{MechanismDependency}"], graphs[3].Assemblies);
        Assert.All(graphs, g => Assert.Equal(0, g.Graph!.Coverage.Resolutions.Ambiguous));
    }

    // ---- one folder spelled in two cases -------------------------------------------------------------------------------

    /// <summary>
    /// Entries spelling one folder two ways, <c>lib/net8.0/A.dll</c> and <c>LIB/net8.0/B.dll</c> (A = the mechanism
    /// fixture, which calls B = its Dependency). On Windows' case-insensitive file system both are extracted into ONE
    /// directory, the <c>lib</c> that A's entry created first, so B's on-disk path is <c>lib/net8.0/B.dll</c>. Pinned from
    /// reading <c>NuGetPackage.Open</c>: its containment gate compares on-disk relative paths with the declared entry names
    /// ORDINALLY, so B's file matches no declared name and is skipped, and the declared <c>LIB/net8.0/B.dll</c> is reported
    /// in <see cref="NuGetPackage.UninventoriedEntryNames"/>, never analysed silently. <see cref="PackageGraphs"/> then sees
    /// one folder holding A alone, and A's call to B is an External leaf. (A gap in the package intake, surfaced as
    /// uninventoried, not a PackageGraphs fault.)
    /// </summary>
    [WindowsExtractionFact("a case-insensitive file system extracts lib/ and LIB/ into one directory")]
    public void Build_OneFolderSpelledInTwoCases_OnWindows_KeepsTheCaseVariantEntryAsUninventoried()
    {
        using var package = Open("TwoCases", ($"lib/net8.0/{MechanismFixture}", mechanism), ($"LIB/net8.0/{MechanismDependency}", dependency));
        var a = Assert.Single(package.Assemblies, x => x.RelativePath.EndsWith("/" + MechanismFixture, StringComparison.Ordinal));
        Assert.True(File.Exists(Path.Combine(Path.GetDirectoryName(a.FullPath)!, MechanismDependency)),
            "B was not extracted next to A: the two spellings did not land in one directory");

        var graph = Assert.Single(PackageGraphs.Build(package));

        Assert.Contains($"LIB/net8.0/{MechanismDependency}", package.UninventoriedEntryNames);
        Assert.Equal([$"lib/net8.0/{MechanismFixture}"], package.Assemblies.Select(a => a.RelativePath));
        Assert.Equal("lib/net8.0", graph.Folder);
        Assert.Equal([$"lib/net8.0/{MechanismFixture}"], graph.Assemblies);
        Assert.Empty(graph.LoadFailures);
        Assert.Contains(graph.Graph!.Successors("MechanismFixture.CrossAssembly.Callers.UsesDependency()"), e => e.To == DependencyRead);
        Assert.Equal(MethodNodeKind.External, graph.Graph.Node(DependencyRead)?.Kind);
    }

    /// <summary>
    /// The Linux twin: a case-sensitive file system keeps <c>LIB/</c> and <c>lib/</c> as two directories, so they are two
    /// folders (ordinal: <c>LIB</c> before <c>lib</c>), both inventoried, and A's call to B crosses folders, so it is an
    /// External leaf there too. No cross-folder edge is ever made.
    /// </summary>
    [LinuxExtractionFact("a case-sensitive file system keeps lib/ and LIB/ apart")]
    public void Build_OneFolderSpelledInTwoCases_OnLinux_IsTwoFolders()
    {
        using var package = Open("TwoCases", ($"lib/net8.0/{MechanismFixture}", mechanism), ($"LIB/net8.0/{MechanismDependency}", dependency));

        var graphs = PackageGraphs.Build(package).ToArray();

        Assert.Empty(package.UninventoriedEntryNames);
        Assert.Equal(["LIB/net8.0", "lib/net8.0"], graphs.Select(g => g.Folder));
        Assert.Equal(MethodNodeKind.External, graphs[1].Graph!.Node(DependencyRead)?.Kind);
        Assert.Equal(MethodNodeKind.OwnWithBody, graphs[0].Graph!.Node(DependencyRead)?.Kind);
    }

    // ---- load failures -------------------------------------------------------------------------------------------------

    /// <summary>
    /// A non-managed <c>.dll</c> in a folder becomes a <see cref="PackageGraphLoadFailure"/> with a reason, and the
    /// folder is still built from the rest — the CrossAssembly path included. A folder whose only DLL is garbage has no
    /// graph, only its failure.
    /// </summary>
    [Fact]
    public void Build_AGarbageDll_IsALoadFailure_TheRestOfTheFolderBuilds_AndAFolderOfOnlyGarbageHasNoGraph()
    {
        using var package = Open("Failures",
            ($"lib/net10.0/{MechanismFixture}", mechanism),
            ($"lib/net10.0/{MechanismDependency}", dependency),
            ("lib/net10.0/native.dll", NupkgBuilder.NotManagedBytes),
            ("lib/net9.0/garbage.dll", Encoding.UTF8.GetBytes("not a portable executable")));

        var graphs = PackageGraphs.Build(package).ToArray();

        Assert.Equal(["lib/net10.0", "lib/net9.0"], graphs.Select(g => g.Folder));
        var built = graphs[0];
        var failure = Assert.Single(built.LoadFailures);
        Assert.Equal("lib/net10.0/native.dll", failure.RelativePath);
        Assert.False(string.IsNullOrWhiteSpace(failure.Reason));
        Assert.Equal([$"lib/net10.0/{MechanismDependency}", $"lib/net10.0/{MechanismFixture}"], built.Assemblies);
        AssertCrossAssemblyPath(built.Graph!);

        var unbuilt = graphs[1];
        Assert.Null(unbuilt.Graph);
        Assert.Empty(unbuilt.Assemblies);
        Assert.Equal("lib/net9.0/garbage.dll", Assert.Single(unbuilt.LoadFailures).RelativePath);
        Assert.False(string.IsNullOrWhiteSpace(unbuilt.LoadFailures[0].Reason));
    }

    // ---- laziness, determinism, budget ----------------------------------------------------------------------------------

    /// <summary>
    /// Graphs are built lazily, one folder per step: after the first folder is enumerated, the second folder's DLL —
    /// garbage when <see cref="PackageGraphs.Build(IEnumerable{PackageAssembly}, GraphBudget?)"/> was called — is replaced
    /// by a real assembly, and the second step loads THAT. An eager build would have recorded a load failure for it.
    /// </summary>
    [Fact]
    public void Build_IsLazy_OneFolderPerStep()
    {
        var first = Stage("a", MechanismDependency, dependency);
        var second = Stage("b", MechanismDependency, NupkgBuilder.NotManagedBytes);

        using var graphs = PackageGraphs.Build([first, second]).GetEnumerator();
        Assert.True(graphs.MoveNext());
        Assert.Equal("a", graphs.Current.Folder);
        Assert.NotNull(graphs.Current.Graph);
        File.WriteAllBytes(second.FullPath, dependency);
        Assert.True(graphs.MoveNext());

        Assert.Equal("b", graphs.Current.Folder);
        Assert.Empty(graphs.Current.LoadFailures);
        Assert.Equal(["b/" + MechanismDependency], graphs.Current.Assemblies);
        Assert.NotNull(graphs.Current.Graph);
        Assert.False(graphs.MoveNext());
    }

    /// <summary>Two builds over one package give identical folders, assemblies, failures, edges, opacities and coverage.</summary>
    [Fact]
    public void Build_Twice_IsIdentical()
    {
        using var package = Open("Twice",
            ($"lib/net10.0/{MechanismFixture}", mechanism), ($"lib/net10.0/{MechanismDependency}", dependency),
            ("lib/net10.0/native.dll", NupkgBuilder.NotManagedBytes), ($"lib/netstandard2.0/{SharedFixture}", shared));

        var first = PackageGraphs.Build(package).ToArray();
        var second = PackageGraphs.Build(package).ToArray();

        Assert.Equal(first.Length, second.Length);
        foreach (var (a, b) in first.Zip(second))
        {
            Assert.Equal(a.Folder, b.Folder);
            Assert.Equal(a.Assemblies, b.Assemblies);
            Assert.Equal(a.LoadFailures, b.LoadFailures);
            Assert.Equal(a.Graph!.Nodes, b.Graph!.Nodes);
            Assert.Equal(a.Graph.Edges, b.Graph.Edges);
            Assert.Equal(a.Graph.Opacities, b.Graph.Opacities);
            Assert.Equal(a.Graph.Coverage, b.Graph.Coverage);
        }
    }

    /// <summary>
    /// The budget applies per folder: with <c>MaxEdges = 5</c> every folder's graph is truncated by "edges" at exactly 5
    /// edges — the second folder is not starved by the first.
    /// </summary>
    [Fact]
    public void Build_ASmallBudget_TruncatesEachFolderSeparately()
    {
        using var package = Open("Budget", ($"lib/net8.0/{SharedFixture}", shared), ($"lib/netstandard2.0/{SharedFixture}", shared));

        var graphs = PackageGraphs.Build(package, new GraphBudget(int.MaxValue, 5)).ToArray();

        Assert.Equal(2, graphs.Length);
        Assert.All(graphs, g =>
        {
            Assert.True(g.Graph!.Coverage.Truncated);
            Assert.Equal("edges budget of 5 reached", g.Graph.Coverage.TruncatedBy);
            Assert.Equal(5, g.Graph.Edges.Count);
        });
        Assert.True(PackageGraphs.Build(package).All(g => !g.Graph!.Coverage.Truncated));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(root, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    // The CrossAssembly mechanism's path, edge by edge, in a graph over the fixture and its Dependency.
    private static void AssertCrossAssemblyPath(MethodGraph graph)
    {
        const string read = "MechanismFixture.Dependency.EnvReader.Read()";
        Assert.Contains(graph.Successors("MechanismFixture.CrossAssembly.Callers.UsesDependency()"), e => e.To == read && e.Kind == MethodEdgeKind.Call);
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(read)?.Kind);
        Assert.Contains(graph.Successors(read), e => e.To == "System.Environment.GetEnvironmentVariable(System.String)");
    }

    // The graph over one DLL on its own (the oracle for "not merged"); its host is released before returning.
    private static MethodGraph Alone(string path)
    {
        var created = AssemblyDisassembler.Create(path);
        Assert.True(created.IsSuccess, created.Message);
        using var disassembler = created.Value;
        return MethodGraph.Build(MemberIndex.Build([disassembler]));
    }

    // A package with the given payload entries, opened (extracted).
    private NuGetPackage Open(string id, params (string Name, byte[] Bytes)[] payload)
    {
        var path = Path.Combine(root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path,
            [($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(id, "1.0.0", "Silvergun Tests", "PackageGraphs test package.", "net8.0", []))), .. payload]);
        var open = NuGetPackage.Open(path);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    // One file written under this test's directory, as a PackageAssembly in folder `folder`.
    private PackageAssembly Stage(string folder, string name, byte[] bytes)
    {
        var full = Path.Combine(Directory.CreateDirectory(Path.Combine(root, "staged", folder)).FullName, name);
        File.WriteAllBytes(full, bytes);
        return new PackageAssembly($"{folder}/{name}", full, null, PackageItemRole.Other, string.Empty);
    }

    // A fixture DLL next to this test assembly (copied there by its ProjectReference); fails loudly if missing.
    private static string Beside(string file)
    {
        var path = Path.Combine(AppContext.BaseDirectory, file);
        return File.Exists(path) ? path : throw new InvalidOperationException($"'{file}' was not found in '{AppContext.BaseDirectory}'.");
    }
    #endregion

    #region Fields
    private const string SharedFixture = "Silvergun.CodeAnalysis.IL.Tests.Fixture.dll";
    private const string MechanismFixture = "Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.dll";
    private const string MechanismDependency = "Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.Dependency.dll";
    private const string DependencyRead = "MechanismFixture.Dependency.EnvReader.Read()";

    private readonly string root;
    private readonly byte[] shared;
    private readonly byte[] mechanism;
    private readonly byte[] dependency;
    #endregion
}
