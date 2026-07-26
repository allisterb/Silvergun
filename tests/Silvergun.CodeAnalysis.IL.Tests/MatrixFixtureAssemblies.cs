namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL.Tests.MatrixFixture;

/// <summary>
/// Locates the multi-targeted fixture assembly (<c>Silvergun.CodeAnalysis.IL.Tests.MatrixFixture</c>) once per
/// target framework, so a test can analyze the <em>same source</em> as compiled by each flavour of the
/// toolchain and assert the analyzer agrees. See <c>docs/agent/tasks/tfm-matrix-tests.md</c>.
/// <para>
/// <b>Fail loudly, never skip.</b> A matrix test that quietly skips a TFM whose output happens to be missing
/// proves nothing, so nothing here degrades gracefully: <see cref="AssertMatrixIsComplete"/> and
/// <see cref="For"/> throw with a message naming what was actually found and where it looked. The usual cause
/// of a missing flavour is the extra <c>ProjectReference</c> in this project's <c>.csproj</c> (the one with
/// <c>ReferenceOutputAssembly="false"</c> and <c>AdditionalProperties="TargetFramework=..."</c>) having been
/// dropped — without it MSBuild builds only the TFM that best matches this project.
/// </para>
/// </summary>
public static class MatrixFixtureAssemblies
{
    #region Properties
    /// <summary>Simple name of the fixture assembly, which is also its file name in every TFM directory.</summary>
    public static string AssemblyName => layout.Value.AssemblyName;

    /// <summary>The build configuration the tests are running under — read from the path, never hardcoded.</summary>
    public static string Configuration => layout.Value.Configuration;

    /// <summary>The fixture project's <c>bin/{Configuration}</c> directory, whose subdirectories are the TFMs.</summary>
    public static string BinDirectory => layout.Value.BinDirectory;

    /// <summary>
    /// Target framework moniker (the <c>bin/{Configuration}</c> subdirectory name, e.g. <c>net472</c>) to the
    /// full path of the fixture assembly built for it. Discovered by enumeration, so adding a TFM to the
    /// fixture's <c>TargetFrameworks</c> extends this map with no change here.
    /// </summary>
    public static IReadOnlyDictionary<string, string> ByTargetFramework => layout.Value.ByTargetFramework;

    /// <summary>
    /// The matrix the tests are written against, mirroring the fixture's <c>&lt;TargetFrameworks&gt;</c>.
    /// net8.0 is deliberately absent — its guarded shape set is identical to net10.0's.
    /// </summary>
    public static IReadOnlySet<string> ExpectedTargetFrameworks { get; } =
        new HashSet<string>(["net472", "net10.0"], StringComparer.Ordinal);
    #endregion

    #region Methods
    /// <summary>The fixture assembly built for <paramref name="targetFramework"/>; throws if it was not built.</summary>
    public static string For(string targetFramework) =>
        ByTargetFramework.TryGetValue(targetFramework, out var path)
            ? path
            : throw new InvalidOperationException(
                $"No '{AssemblyName}' build for target framework '{targetFramework}'. {Describe()}");

    /// <summary>
    /// Throws unless the discovered set of TFMs is <em>exactly</em> <see cref="ExpectedTargetFrameworks"/>.
    /// Both directions matter: a missing flavour means the matrix silently shrank, an extra one means it grew
    /// without the tests being extended to cover it.
    /// </summary>
    public static void AssertMatrixIsComplete()
    {
        if (!ByTargetFramework.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(ExpectedTargetFrameworks))
        {
            throw new InvalidOperationException(
                $"The TFM matrix does not match the one the tests are written against. " +
                $"Expected [{Join(ExpectedTargetFrameworks)}]. {Describe()}");
        }
    }

    private static string Describe() =>
        $"Found [{Join(ByTargetFramework.Keys)}] under '{BinDirectory}' (searching each subdirectory for " +
        $"'{AssemblyName}.dll' by name — stale assemblies with other names are ignored).";

    private static string Join(IEnumerable<string> targetFrameworks) =>
        string.Join(", ", targetFrameworks.OrderBy(t => t, StringComparer.Ordinal));

    // Starting point is the loaded fixture assembly, which at test time is the copy the ProjectReference put in
    // THIS project's output — .../<host project>/bin/<configuration>/<host tfm>/<name>.dll. Only the host's own
    // TFM is copied there, so the other flavours are read from the fixture project's own bin: walk up from the
    // location, take the configuration from the path, and find the sibling project directory by name.
    private static MatrixLayout Discover()
    {
        var assembly = typeof(ModernInteropOps).Assembly;
        var name = assembly.GetName().Name
            ?? throw new InvalidOperationException("The matrix fixture assembly has no simple name.");

        if (string.IsNullOrEmpty(assembly.Location))
        {
            throw new InvalidOperationException(
                $"'{name}' reports no Location (single-file or dynamic host), so the TFM matrix cannot be located on disk.");
        }

        var tfmDirectory = new DirectoryInfo(Path.GetDirectoryName(assembly.Location)!);
        var configuration = tfmDirectory.Parent?.Name
            ?? throw new InvalidOperationException($"Unexpected output layout: '{tfmDirectory.FullName}' has no parent directory.");

        // The fixture project directory is named after the assembly; look for it on the way up rather than
        // assuming a fixed number of levels.
        var projectDirectory = SelfAndAncestors(tfmDirectory)
            .Select(directory => Path.Combine(directory.FullName, name))
            .FirstOrDefault(candidate => File.Exists(Path.Combine(candidate, name + ".csproj")))
            ?? throw new InvalidOperationException(
                $"Could not find the '{name}' project directory above '{tfmDirectory.FullName}'.");

        var binDirectory = Path.Combine(projectDirectory, "bin", configuration);

        // Enumerate TFM directories rather than assuming any list, but select the fixture assembly BY NAME:
        // a TFM directory can hold output from a previous build under a different assembly name, and globbing
        // *.dll would pick that up. A directory without the assembly is not a TFM of this matrix.
        var byTargetFramework = (Directory.Exists(binDirectory) ? Directory.EnumerateDirectories(binDirectory) : Enumerable.Empty<string>())
            .Select(directory => (TargetFramework: Path.GetFileName(directory), Path: Path.Combine(directory, name + ".dll")))
            .Where(candidate => File.Exists(candidate.Path))
            .ToDictionary(candidate => candidate.TargetFramework, candidate => candidate.Path, StringComparer.Ordinal);

        return new MatrixLayout(name, configuration, binDirectory, byTargetFramework);
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
        string Configuration,
        string BinDirectory,
        IReadOnlyDictionary<string, string> ByTargetFramework);
    #endregion
}
