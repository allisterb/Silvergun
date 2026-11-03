namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>
/// Locates <c>Silvergun.CodeAnalysis.IL.Tests.ShadowFixture.dll</c> — the name-shadowing fixture (review 1, finding
/// C2) that defines its own public <c>System.Environment</c> and <c>System.IDisposable</c>.
/// <para>
/// It is a <b>build-order-only</b> reference (<c>ReferenceOutputAssembly="false"</c> in this project's csproj): its
/// public <c>System.Environment</c> must never be on this project's reference set or next to this assembly. So it is
/// found in the fixture project's OWN output, <c>bin/{Configuration}/net10.0</c>, with the configuration read from
/// this test assembly's path (never hardcoded) and the project directory found by name on the way up — the same
/// discovery <see cref="MatrixFixtureAssemblies"/> uses. Read as metadata, never loaded. <b>Fails loudly, never
/// skips</b>.
/// </para>
/// </summary>
public static class ShadowFixtureAssembly
{
    #region Properties
    /// <summary>Full path of the built fixture assembly.</summary>
    public static string Path => path.Value;
    #endregion

    #region Methods
    private static string Locate()
    {
        var tfmDirectory = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar));
        var configuration = tfmDirectory.Parent?.Name
            ?? throw new InvalidOperationException($"Unexpected output layout: '{tfmDirectory.FullName}' has no parent directory.");

        var projectDirectory = SelfAndAncestors(tfmDirectory)
            .Select(directory => System.IO.Path.Combine(directory.FullName, Name))
            .FirstOrDefault(candidate => File.Exists(System.IO.Path.Combine(candidate, Name + ".csproj")))
            ?? throw new InvalidOperationException($"Could not find the '{Name}' project directory above '{tfmDirectory.FullName}'.");

        var assembly = System.IO.Path.Combine(projectDirectory, "bin", configuration, TargetFramework, Name + ".dll");
        return File.Exists(assembly)
            ? assembly
            : throw new InvalidOperationException(
                $"'{assembly}' was not found. It is built by the ReferenceOutputAssembly=\"false\" ProjectReference in " +
                "Silvergun.CodeAnalysis.IL.Tests.csproj - rebuild the test project.");
    }

    private static IEnumerable<DirectoryInfo> SelfAndAncestors(DirectoryInfo directory)
    {
        for (var current = directory; current is not null; current = current.Parent)
            yield return current;
    }
    #endregion

    #region Fields
    /// <summary>The fixture's simple assembly name (also its project directory and file name).</summary>
    public const string Name = "Silvergun.CodeAnalysis.IL.Tests.ShadowFixture";

    private const string TargetFramework = "net10.0";

    private static readonly Lazy<string> path = new(Locate);
    #endregion
}
