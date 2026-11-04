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
/// a corrupt file. <see cref="Graph"/> is null only when no assembly of the folder could be loaded.
/// </summary>
public sealed record PackageGraph(
    string Folder,
    IReadOnlyList<string> Assemblies,
    IReadOnlyList<PackageGraphLoadFailure> LoadFailures,
    MethodGraph? Graph);

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
/// In-process, and not called by the scanner or the CLI yet: running each folder in a child process (ADR 0021) comes
/// with that wiring. Graphs are built lazily, one folder per step, and each folder's Analysis.Net hosts are disposed
/// before the next is loaded, so the caller decides how many finished graphs to keep. Folders come in ordinal order of
/// their path inside the package. Never throws.
/// </para>
/// </summary>
public static class PackageGraphs
{
    #region Methods
    /// <summary>The graphs of <paramref name="package"/>'s folders, each within <paramref name="budget"/> (default <see cref="GraphBudget.Default"/>).</summary>
    public static IEnumerable<PackageGraph> Build(NuGetPackage package, GraphBudget? budget = null) =>
        Build(package.Assemblies, budget);

    /// <summary>
    /// The graphs of the folders <paramref name="assemblies"/> lie in. A folder is the directory an assembly was
    /// extracted to, so two entries the file system stores in one directory are one folder.
    /// </summary>
    public static IEnumerable<PackageGraph> Build(IEnumerable<PackageAssembly> assemblies, GraphBudget? budget = null) =>
        assemblies
            .GroupBy(a => Path.GetDirectoryName(a.FullPath) ?? string.Empty, StringComparer.Ordinal)
            .Select(g => (Directory: g.Key, Members: g.OrderBy(a => a.RelativePath, StringComparer.Ordinal).ToArray()))
            .Select(g => (Folder: FolderOf(g.Members[0].RelativePath), g.Directory, g.Members))
            .OrderBy(g => g.Folder, StringComparer.Ordinal)
            .ThenBy(g => g.Directory, StringComparer.Ordinal)
            .ToArray()
            .Select(g => BuildFolder(g.Folder, g.Members, budget ?? GraphBudget.Default));

    // One folder: load each assembly, index the ones that loaded, build, and release every host before returning.
    private static PackageGraph BuildFolder(string folder, IReadOnlyList<PackageAssembly> members, GraphBudget budget)
    {
        var loaded = new List<(PackageAssembly Assembly, AssemblyDisassembler Disassembler)>();
        var failures = new List<PackageGraphLoadFailure>();
        try
        {
            foreach (var member in members)
            {
                var created = AssemblyDisassembler.Create(member.FullPath);
                if (created.IsSuccess)
                    loaded.Add((member, created.Value));
                else
                    failures.Add(new(member.RelativePath, created.Message ?? "the assembly could not be loaded"));
            }
            var graph = loaded.Count == 0 ? null : MethodGraph.Build(MemberIndex.Build(loaded.Select(l => l.Disassembler)), budget);
            return new PackageGraph(folder, [.. loaded.Select(l => l.Assembly.RelativePath)], failures, graph);
        }
        catch (Exception ex)
        {
            // Upholds never-throws: the index and the graph do not throw, so this is a load failing outside its Result.
            // The whole folder is then reported unbuilt, every assembly with the reason, rather than partly.
            return new PackageGraph(folder, [], [.. members.Select(m => new PackageGraphLoadFailure(m.RelativePath, $"the folder's graph could not be built: {ex.Message}"))], null);
        }
        finally
        {
            foreach (var (_, disassembler) in loaded)
                disassembler.Dispose();
        }
    }

    // The folder part of a package-relative path ("lib/net8.0/Foo.dll" -> "lib/net8.0"), "" at the root.
    private static string FolderOf(string relativePath) =>
        relativePath.LastIndexOf('/') is var slash and >= 0 ? relativePath[..slash] : string.Empty;
    #endregion
}
