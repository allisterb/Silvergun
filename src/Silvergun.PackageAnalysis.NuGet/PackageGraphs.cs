namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

/// <summary>An assembly of a package folder that could not be loaded for its call graph, and why.</summary>
public sealed record PackageGraphLoadFailure(string RelativePath, string Reason);

/// <summary>
/// The call graph over one package folder's assemblies (<see cref="PackageGraphs"/>). <see cref="Folder"/> is the
/// folder's path inside the package ("" for the root), <see cref="Assemblies"/> the relative paths of the assemblies
/// that were loaded into <see cref="Graph"/>, and <see cref="LoadFailures"/> the ones that were not — a native binary,
/// a corrupt file. <see cref="Graph"/> is null only when no assembly of the folder could be loaded, or when
/// <see cref="BuildFailure"/> says why the build failed as a whole (every assembly is then a load failure with that reason).
/// </summary>
public sealed record PackageGraph(
    string Folder,
    IReadOnlyList<string> Assemblies,
    IReadOnlyList<PackageGraphLoadFailure> LoadFailures,
    MethodGraph? Graph)
{
    #region Properties
    /// <summary>Why the folder's build failed after loading began (an exception outside a load's own result), or null.</summary>
    public string? BuildFailure { get; init; }
    #endregion
}

/// <summary>
/// Call graphs over a package (CHA phase A2Multi, <c>docs/agent/tasks/cha-a2multi-package-graphs.md</c>): one
/// <see cref="MethodGraph"/> per folder that holds assemblies, over that folder's own assemblies only.
/// <para>
/// A folder is what loads together: NuGet copies one <c>lib/&lt;tfm&gt;</c> into an app, a tool runs from its own
/// folder, an analyzer folder is loaded as a set. So the copies of one assembly a package ships for several target
/// frameworks or runtimes are never merged into one index, where nearly every call would be ambiguous between them,
/// while calls between a folder's own assemblies are joined. Dependencies are not loaded: every call out of the folder
/// is an external leaf, classified like a platform call (dependency depth 0, decision M2).
/// </para>
/// <para>
/// In-process, so only for trusted input: untrusted packages go through <see cref="Graph.PackageReachability"/>, which
/// runs this same per-folder build in worker processes (ADR 0021). Graphs are built lazily, one folder per step, and
/// each folder's Analysis.Net hosts are disposed before the next is loaded, so the caller decides how many finished
/// graphs to keep. Folders come in ordinal order of their path inside the package. A load failure's reason names the
/// assembly by its package path, never by where it was extracted, so it is the same in every run. Never throws.
/// </para>
/// </summary>
public static class PackageGraphs
{
    #region Methods
    /// <summary>
    /// The graphs of <paramref name="package"/>'s folders, each within <paramref name="budget"/> (default
    /// <see cref="GraphBudget.Default"/>), with root facts from <paramref name="map"/> (default <see cref="CapabilityMap.Default"/>).
    /// </summary>
    public static IEnumerable<PackageGraph> Build(NuGetPackage package, GraphBudget? budget = null, CapabilityMap? map = null) =>
        Build(package.Assemblies, budget, map);

    /// <summary>
    /// The graphs of the folders <paramref name="assemblies"/> lie in. A folder is the directory an assembly was
    /// extracted to, so two entries the file system stores in one directory are one folder.
    /// </summary>
    public static IEnumerable<PackageGraph> Build(IEnumerable<PackageAssembly> assemblies, GraphBudget? budget = null, CapabilityMap? map = null) =>
        Folders(assemblies)
            .Select(g => BuildFolder(g.Folder, g.Members, budget ?? GraphBudget.Default, map ?? CapabilityMap.Default));

    /// <summary>
    /// The folders <paramref name="assemblies"/> lie in, each with its members in ordinal order of their package path,
    /// in the order <see cref="Build(IEnumerable{PackageAssembly}, GraphBudget?, CapabilityMap?)"/> builds them.
    /// </summary>
    internal static IReadOnlyList<(string Folder, PackageAssembly[] Members)> Folders(IEnumerable<PackageAssembly> assemblies) =>
        [.. assemblies
            .GroupBy(a => Path.GetDirectoryName(a.FullPath) ?? string.Empty, StringComparer.Ordinal)
            .Select(g => (Directory: g.Key, Members: g.OrderBy(a => a.RelativePath, StringComparer.Ordinal).ToArray()))
            .Select(g => (Folder: FolderOf(g.Members[0].RelativePath), g.Directory, g.Members))
            .OrderBy(g => g.Folder, StringComparer.Ordinal)
            .ThenBy(g => g.Directory, StringComparer.Ordinal)
            .Select(g => (g.Folder, g.Members))];

    /// <summary>
    /// One folder's graph: load each of <paramref name="members"/> (package path, path on disk), index the ones that
    /// loaded, build, and release every host before returning. Never throws.
    /// </summary>
    internal static PackageGraph BuildFolder(string folder, IReadOnlyList<PackageAssembly> members, GraphBudget budget, CapabilityMap map) =>
        BuildFolder(folder, [.. members.Select(m => (m.RelativePath, m.FullPath))], budget, map);

    /// <inheritdoc cref="BuildFolder(string, IReadOnlyList{PackageAssembly}, GraphBudget, CapabilityMap)"/>
    internal static PackageGraph BuildFolder(string folder, IReadOnlyList<(string RelativePath, string FullPath)> members, GraphBudget budget, CapabilityMap map)
    {
        var loaded = new List<(string RelativePath, AssemblyDisassembler Disassembler)>();
        var failures = new List<PackageGraphLoadFailure>();
        try
        {
            foreach (var member in members)
            {
                var created = AssemblyDisassembler.Create(member.FullPath);
                if (created.IsSuccess)
                    loaded.Add((member.RelativePath, created.Value));
                else
                    failures.Add(new(member.RelativePath, Relative(created.Message ?? "the assembly could not be loaded", members)));
            }
            var graph = loaded.Count == 0 ? null : MethodGraph.Build(MemberIndex.Build(loaded.Select(l => l.Disassembler)), budget, map);
            return new PackageGraph(folder, [.. loaded.Select(l => l.RelativePath)], failures, graph);
        }
        catch (Exception ex)
        {
            // Upholds never-throws: the index and the graph do not throw, so this is a load failing outside its Result, or
            // the process running short (an OutOfMemoryException under a GC heap hard limit). The whole folder is then
            // reported unbuilt, every assembly with the reason, rather than partly, and BuildFailure says so.
            var reason = Relative($"the folder's graph could not be built: {ex.Message}", members);
            return new PackageGraph(folder, [], [.. members.Select(m => new PackageGraphLoadFailure(m.RelativePath, reason))], null) { BuildFailure = reason };
        }
        finally
        {
            foreach (var (_, disassembler) in loaded)
                disassembler.Dispose();
        }
    }

    // `message` with every member's path on disk replaced by its package path: the extraction directory differs per run.
    private static string Relative(string message, IReadOnlyList<(string RelativePath, string FullPath)> members) =>
        members.Where(m => m.FullPath.Length > 0)
            .OrderByDescending(m => m.FullPath.Length)
            .Aggregate(message, (text, m) => text.Replace(m.FullPath, m.RelativePath, StringComparison.Ordinal));

    // The folder part of a package-relative path ("lib/net8.0/Foo.dll" -> "lib/net8.0"), "" at the root.
    private static string FolderOf(string relativePath) =>
        relativePath.LastIndexOf('/') is var slash and >= 0 ? relativePath[..slash] : string.Empty;
    #endregion
}
