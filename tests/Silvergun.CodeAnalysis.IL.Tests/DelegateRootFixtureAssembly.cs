namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;

/// <summary>
/// Locates <c>Silvergun.CodeAnalysis.IL.Tests.DelegateRootFixture</c> next to this test assembly, where the plain
/// <c>ProjectReference</c> copies it. By <b>path</b>, never via <c>typeof(...)</c>: its type initializers must not run.
/// <b>Fails loudly, never skips</b>.
/// </summary>
public static class DelegateRootFixtureAssembly
{
    #region Properties
    /// <summary>Full path of <c>Silvergun.CodeAnalysis.IL.Tests.DelegateRootFixture.dll</c>.</summary>
    public static string Path
    {
        get
        {
            var path = System.IO.Path.Combine(AppContext.BaseDirectory, Name + ".dll");
            return File.Exists(path)
                ? path
                : throw new InvalidOperationException(
                    $"'{Name}.dll' was not found in '{AppContext.BaseDirectory}'. It is copied there by the ProjectReference in " +
                    "Silvergun.CodeAnalysis.IL.Tests.csproj - rebuild the test project.");
        }
    }
    #endregion

    #region Fields
    public const string Name = "Silvergun.CodeAnalysis.IL.Tests.DelegateRootFixture";
    #endregion
}
