namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL.Tests.VoidReturnFixture;

/// <summary>
/// Locates the multi-targeted <c>Silvergun.CodeAnalysis.IL.Tests.VoidReturnFixture</c> assembly (net472 and
/// net10.0, built from identical source) once per target framework. Mirrors
/// <see cref="MatrixFixtureAssemblies"/>'s discovery approach, but deliberately kept as its own small class
/// rather than generalizing that one — this fixture exists specifically so its shapes stay off
/// <c>MatrixFixture</c>'s pinned baselines, and sharing the discovery machinery would recouple the two.
/// <b>Fails loudly, never skips</b>: a missing flavour throws naming what was found and where it looked,
/// rather than a matrix test silently passing over a TFM whose output happens to be absent.
/// </summary>
public static class VoidReturnFixtureAssemblies
{
    #region Properties
    public static string Net10 => For("net10.0");

    public static string Net472 => For("net472");

    /// <summary>Target framework moniker to the full path of the fixture assembly built for it.</summary>
    public static IReadOnlyDictionary<string, string> ByTargetFramework => layout.Value.ByTargetFramework;
    #endregion

    #region Methods
    public static string For(string targetFramework) =>
        ByTargetFramework.TryGetValue(targetFramework, out var path)
            ? path
            : throw new InvalidOperationException(
                $"No '{layout.Value.AssemblyName}' build for target framework '{targetFramework}'. " +
                $"Found [{string.Join(", ", ByTargetFramework.Keys.OrderBy(k => k, StringComparer.Ordinal))}] " +
                $"under '{layout.Value.BinDirectory}'.");

    // Starting point is the loaded fixture assembly, which at test time is the copy the ProjectReference put
    // in THIS project's output — .../<host project>/bin/<configuration>/<host tfm>/<name>.dll. Only the
    // host's own TFM is copied there, so the other flavour is read from the fixture project's own bin: walk
    // up from the location, take the configuration from the path, and find the sibling project directory by
    // name (same approach as MatrixFixtureAssemblies.Discover).
    private static MatrixLayout Discover()
    {
        var assembly = typeof(Widget).Assembly;
        var name = assembly.GetName().Name
            ?? throw new InvalidOperationException("The VoidReturnFixture assembly has no simple name.");

        if (string.IsNullOrEmpty(assembly.Location))
        {
            throw new InvalidOperationException(
                $"'{name}' reports no Location (single-file or dynamic host), so it cannot be located on disk.");
        }

        var tfmDirectory = new DirectoryInfo(Path.GetDirectoryName(assembly.Location)!);
        var configuration = tfmDirectory.Parent?.Name
            ?? throw new InvalidOperationException($"Unexpected output layout: '{tfmDirectory.FullName}' has no parent directory.");

        var projectDirectory = SelfAndAncestors(tfmDirectory)
            .Select(directory => Path.Combine(directory.FullName, name))
            .FirstOrDefault(candidate => File.Exists(Path.Combine(candidate, name + ".csproj")))
            ?? throw new InvalidOperationException(
                $"Could not find the '{name}' project directory above '{tfmDirectory.FullName}'.");

        var binDirectory = Path.Combine(projectDirectory, "bin", configuration);

        var byTargetFramework = (Directory.Exists(binDirectory) ? Directory.EnumerateDirectories(binDirectory) : Enumerable.Empty<string>())
            .Select(directory => (TargetFramework: Path.GetFileName(directory), Path: Path.Combine(directory, name + ".dll")))
            .Where(candidate => File.Exists(candidate.Path))
            .ToDictionary(candidate => candidate.TargetFramework, candidate => candidate.Path, StringComparer.Ordinal);

        return new MatrixLayout(name, binDirectory, byTargetFramework);
    }

    private static IEnumerable<DirectoryInfo> SelfAndAncestors(DirectoryInfo directory)
    {
        for (var current = directory; current is not null; current = current.Parent)
            yield return current;
    }
    #endregion

    #region Fields
    // Lazy rather than a static constructor: a discovery failure then surfaces as itself, not wrapped in a
    // TypeInitializationException that hides the message.
    private static readonly Lazy<MatrixLayout> layout = new(Discover);
    #endregion

    #region Child types
    private sealed record MatrixLayout(
        string AssemblyName,
        string BinDirectory,
        IReadOnlyDictionary<string, string> ByTargetFramework);
    #endregion
}
