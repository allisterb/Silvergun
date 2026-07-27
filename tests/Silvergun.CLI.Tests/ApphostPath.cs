namespace Silvergun.CLI.Tests;

using System;
using System.IO;

/// <summary>
/// Resolves the platform-appropriate file name for a <c>dotnet build</c>-produced apphost that a test spawns as
/// a child process (the CLI apphost copied next to this test assembly's output by its project reference). A
/// <c>dotnet</c> apphost carries a <c>.exe</c> suffix only on Windows; on Linux/macOS the apphost has no
/// extension at all, so hardcoding <c>.exe</c> makes it unfindable off Windows.
/// <para>
/// Duplicated (not shared) in <c>Silvergun.CodeAnalysis.IL.Tests</c> — the two test assemblies have no project
/// reference between them, and adding one solely to share this one-liner would outweigh the small duplication.
/// </para>
/// </summary>
internal static class ApphostPath
{
    #region Methods
    /// <summary>
    /// Combines <paramref name="baseDirectory"/> with the apphost file name for <paramref name="assemblyName"/>
    /// (the target project's assembly name, no extension), appending <c>.exe</c> only when running on Windows.
    /// </summary>
    public static string Resolve(string baseDirectory, string assemblyName) =>
        Path.Combine(baseDirectory, OperatingSystem.IsWindows() ? $"{assemblyName}.exe" : assemblyName);
    #endregion
}
