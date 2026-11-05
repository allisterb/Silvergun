namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;

/// <summary>
/// Locates the mechanism-fixture assemblies (<c>Silvergun.CodeAnalysis.IL.Tests.MechanismFixture</c>, its
/// <c>.Dependency</c>, and since A2 S2 the Debug-built <c>.Debug</c>) next to this test assembly, where the plain
/// <c>ProjectReference</c> copies them.
/// <para>
/// Deliberately by <b>path</b>, never via <c>typeof(...)</c>: naming a fixture type would load the assembly into
/// the test host, and the fixture has a <c>[ModuleInitializer]</c> and type initializers whose bodies are capability
/// sinks. They are inert, but a test suite about install-time execution should not execute any. <b>Fails loudly,
/// never skips</b>: a missing assembly throws naming where it looked.
/// </para>
/// </summary>
public static class MechanismFixtureAssemblies
{
    #region Properties
    /// <summary>Full path of <c>Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.dll</c>.</summary>
    public static string Fixture => Locate(FixtureName);

    /// <summary>Full path of <c>Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.Dependency.dll</c>.</summary>
    public static string Dependency => Locate(DependencyName);

    /// <summary>
    /// Full path of <c>Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.Debug.dll</c>: the Debug-built (Optimize off)
    /// state-machine shapes, namespace root <c>MechanismFixture.Debug</c>.
    /// </summary>
    public static string DebugFixture => Locate(DebugFixtureName);

    /// <summary>
    /// Full path of <c>Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.HostStubs.dll</c>: the MSBuild and Roslyn
    /// host-contract stand-ins (reachability R1, S3). Copied beside the fixture, and never indexed.
    /// </summary>
    public static string HostStubs => Locate(HostStubsName);
    #endregion

    #region Methods
    private static string Locate(string assemblyName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, assemblyName + ".dll");
        return File.Exists(path)
            ? path
            : throw new InvalidOperationException(
                $"'{assemblyName}.dll' was not found in '{AppContext.BaseDirectory}'. It is copied there by the " +
                "ProjectReference in Silvergun.CodeAnalysis.IL.Tests.csproj - rebuild the test project.");
    }
    #endregion

    #region Fields
    public const string FixtureName = "Silvergun.CodeAnalysis.IL.Tests.MechanismFixture";
    public const string DependencyName = "Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.Dependency";
    public const string DebugFixtureName = "Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.Debug";
    public const string HostStubsName = "Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.HostStubs";
    #endregion
}
