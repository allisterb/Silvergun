namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.MsBuild;

using Xunit;

/// <summary>
/// An extracted package for <see cref="MsBuildAnalysis"/> (MCP task S4): files written under a content root in a temp
/// directory, every <c>.targets</c>/<c>.props</c> handed over as a <see cref="PackageScript"/> the way the scan reports it.
/// </summary>
internal sealed class MsBuildPackage : IDisposable
{
    #region Constructors
    public MsBuildPackage(string id = "Acme.Tool")
    {
        Id = id;
        top = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-msbuild-tests", Guid.NewGuid().ToString("N"))).FullName;
        Root = Directory.CreateDirectory(Path.Combine(top, id.ToLowerInvariant() + ".1.0.0.nupkg")).FullName;
    }
    #endregion

    #region Properties
    public string Id { get; }

    public string Root { get; }
    #endregion

    #region Methods
    public string Add(string relative, string text) => Add(relative, new UTF8Encoding(false).GetBytes(text));

    public string Add(string relative, byte[] bytes)
    {
        var full = Full(relative);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, bytes);
        return full;
    }

    /// <summary>The extracted full path of a package-relative name.</summary>
    public string Full(string relative) => Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));

    public MsBuildIntegration Analyze(long budgetChars = MsBuildExpander.DefaultBudgetChars)
    {
        var all = Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories).ToList();
        var scripts = all.Where(f => f.EndsWith(".targets", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".props", StringComparison.OrdinalIgnoreCase))
            .Select(f => new PackageScript(NuGetPackage.RelativeUnderRoot(Root, f), f, PackageItemRole.Build)).ToList();
        return MsBuildAnalysis.Analyze(Id, Root, scripts, all, budgetChars);
    }

    public void Dispose()
    {
        try { Directory.Delete(top, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
    #endregion

    #region Fields
    private readonly string top;
    #endregion
}

internal static class MsBuildTest
{
    #region Methods
    public static MsBuildFileFacts File(this MsBuildIntegration integration, string name) => Assert.Single(integration.Files, f => f.Name == name);

    /// <summary>A project file of <paramref name="body"/>.</summary>
    public static string Project(string body) => "<Project>\n" + body + "\n</Project>\n";
    #endregion

    #region Fields
    /// <summary>The expander's own anchor bracket, U+E000, built from its code point.</summary>
    public static readonly char Mark = (char)0xE000;
    #endregion
}
