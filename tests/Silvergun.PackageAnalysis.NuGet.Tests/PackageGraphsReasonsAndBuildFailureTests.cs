namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Graph worker review round 1, in-process:
/// <list type="bullet">
/// <item><description>W3: a load failure's reason names the assembly by its package path, never by its extraction path, so two
/// extractions of one package give identical reasons.</description></item>
/// <item><description>W4: a folder build that throws as a whole sets <see cref="PackageGraph.BuildFailure"/> (with every member a
/// load failure carrying that reason), which the worker turns into <c>fatal</c> instead of a folder that loaded nothing.</description></item>
/// </list>
/// </summary>
public sealed class PackageGraphsReasonsAndBuildFailureTests : IDisposable
{
    #region Constructors
    public PackageGraphsReasonsAndBuildFailureTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        root = Directory.CreateTempSubdirectory("silvergun-pkggraphs-reasons-").FullName;
    }
    #endregion

    #region Methods: W3
    /// <summary>
    /// A corrupt DLL and a non-PE one, in two extractions of one package: the reasons are identical, name the package path,
    /// and name neither extraction directory.
    /// </summary>
    [Fact]
    public void LoadFailureReasons_AreTheSameForEveryExtraction_AndNameThePackagePath()
    {
        var nupkg = Write("Reasons",
            ("lib/net9.0/corrupt.dll", Encoding.UTF8.GetBytes("not a portable executable")),
            ("lib/net9.0/native.dll", NupkgBuilder.NotManagedBytes),
            ($"lib/net9.0/{GraphStage.MechanismDependency}", GraphStage.Dependency));
        using var first = Open(nupkg);
        using var second = Open(nupkg);
        Assert.NotEqual(first.ExtractionDir, second.ExtractionDir);

        var a = Assert.Single(PackageGraphs.Build(first));
        var b = Assert.Single(PackageGraphs.Build(second));

        Assert.Equal(2, a.LoadFailures.Count);
        Assert.Equal(a.LoadFailures, b.LoadFailures);
        foreach (var failure in a.LoadFailures)
        {
            Assert.Contains(failure.RelativePath, failure.Reason, StringComparison.Ordinal);
            Assert.DoesNotContain(first.ExtractionDir, failure.Reason, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar), failure.Reason, StringComparison.OrdinalIgnoreCase);
        }
        Assert.Null(a.BuildFailure);
    }

    /// <summary>A missing file's reason is relative too.</summary>
    [Fact]
    public void AMissingFilesReason_NamesThePackagePath()
    {
        var missing = Path.Combine(root, "lib", "gone.dll");

        var built = PackageGraphs.BuildFolder("lib", [("lib/gone.dll", missing)], GraphBudget.Default, CapabilityMap.Default);

        var failure = Assert.Single(built.LoadFailures);
        Assert.Contains("lib/gone.dll", failure.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(root, failure.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Null(built.BuildFailure);
    }
    #endregion

    #region Methods: W4
    /// <summary>
    /// A build that throws outside a load's own result: the only in-process trigger short of out-of-memory is the member list
    /// itself (AssemblyDisassembler.Create catches everything, and the index and graph do not throw), here a list whose first
    /// enumeration throws after its first member. The folder has no graph, BuildFailure says why, and every member is a load
    /// failure with that same reason, named by package path.
    /// </summary>
    [Fact]
    public void ABuildThatThrows_SetsBuildFailure_AndFailsEveryMember()
    {
        var dependency = GraphStage.Beside(GraphStage.MechanismDependency);
        var members = new ThrowsOnce([("lib/a/dep.dll", dependency), ("lib/a/other.dll", dependency)]);

        var built = PackageGraphs.BuildFolder("lib/a", members, GraphBudget.Default, CapabilityMap.Default);

        Assert.Null(built.Graph);
        Assert.Empty(built.Assemblies);
        Assert.NotNull(built.BuildFailure);
        Assert.StartsWith("the folder's graph could not be built: ", built.BuildFailure, StringComparison.Ordinal);
        Assert.Contains("injected", built.BuildFailure, StringComparison.Ordinal);
        Assert.Equal(["lib/a/dep.dll", "lib/a/other.dll"], built.LoadFailures.Select(f => f.RelativePath));
        Assert.All(built.LoadFailures, f => Assert.Equal(built.BuildFailure, f.Reason));
    }

    /// <summary>A normal build, graph or not, has no BuildFailure: NothingLoaded stays a folder that loaded nothing.</summary>
    [Fact]
    public void ANormalBuild_HasNoBuildFailure()
    {
        var garbage = Path.Combine(root, "garbage.dll");
        File.WriteAllBytes(garbage, NupkgBuilder.NotManagedBytes);

        var built = PackageGraphs.BuildFolder("lib", [("lib/garbage.dll", garbage)], GraphBudget.Default, CapabilityMap.Default);
        var graph = PackageGraphs.BuildFolder("lib", [("lib/dep.dll", GraphStage.Beside(GraphStage.MechanismDependency))], GraphBudget.Default, CapabilityMap.Default);

        Assert.Null(built.Graph);
        Assert.Null(built.BuildFailure);
        Assert.NotNull(graph.Graph);
        Assert.Null(graph.BuildFailure);
    }
    #endregion

    #region Methods: helpers
    public void Dispose() => GraphFiles.DeleteTree(root);

    private string Write(string id, params (string Name, byte[] Bytes)[] payload)
    {
        var path = Path.Combine(root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path,
            [($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(id, "1.0.0", "Silvergun Tests", "Reasons test package.", "net8.0", []))), .. payload]);
        return path;
    }

    private static NuGetPackage Open(string path)
    {
        var open = NuGetPackage.Open(path);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }
    #endregion

    #region Fields
    private readonly string root;
    #endregion

    #region Nested types
    /// <summary>A member list whose first enumeration throws after yielding its first item; later enumerations are plain.</summary>
    private sealed class ThrowsOnce((string RelativePath, string FullPath)[] items) : IReadOnlyList<(string RelativePath, string FullPath)>
    {
        public int Count => items.Length;

        public (string RelativePath, string FullPath) this[int index] => items[index];

        public IEnumerator<(string RelativePath, string FullPath)> GetEnumerator()
        {
            if (thrown)
                return ((IEnumerable<(string, string)>)items).GetEnumerator();
            thrown = true;
            return First();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private IEnumerator<(string RelativePath, string FullPath)> First()
        {
            yield return items[0];
            throw new InvalidOperationException("injected: the member list failed mid-build");
        }

        private bool thrown;
    }
    #endregion
}
