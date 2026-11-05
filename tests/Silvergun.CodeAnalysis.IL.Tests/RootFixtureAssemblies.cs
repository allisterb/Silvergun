namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;

/// <summary>
/// Locates the root-class fixture (<c>Silvergun.CodeAnalysis.IL.Tests.RootFixture</c>) and its never-indexed host stubs
/// next to this test assembly, where the plain <c>ProjectReference</c> copies them. By <b>path</b>, never via
/// <c>typeof(...)</c>: the fixture has a <c>[ModuleInitializer]</c>, and the suite must not run it. <b>Fails loudly,
/// never skips</b>.
/// </summary>
public static class RootFixtureAssemblies
{
    #region Properties
    /// <summary>Full path of <c>Silvergun.CodeAnalysis.IL.Tests.RootFixture.dll</c>.</summary>
    public static string Fixture => Locate(FixtureName);

    /// <summary>Full path of <c>Silvergun.CodeAnalysis.IL.Tests.RootFixture.HostStubs.dll</c> (never indexed).</summary>
    public static string HostStubs => Locate(HostStubsName);

    /// <summary>Full path of <c>Silvergun.CodeAnalysis.IL.Tests.RootFixture.Other.dll</c>: a second own assembly, indexed with the fixture only by the cross-assembly tests.</summary>
    public static string Other => Locate(OtherName);
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
    public const string FixtureName = "Silvergun.CodeAnalysis.IL.Tests.RootFixture";
    public const string HostStubsName = "Silvergun.CodeAnalysis.IL.Tests.RootFixture.HostStubs";
    public const string OtherName = "Silvergun.CodeAnalysis.IL.Tests.RootFixture.Other";
    #endregion
}
