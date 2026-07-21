namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

/// <summary>
/// Builds minimal, valid <c>.nupkg</c> archives with pure BCL <see cref="ZipArchive"/> — no NuGet
/// client and no network. A nupkg is a zip containing a <c>&lt;id&gt;.nuspec</c> (see
/// <see cref="NuspecXml"/>) plus payload files. Used by <see cref="PackageFixture"/> to stage the
/// PkgA / PkgB test packages.
/// </summary>
internal static class NupkgBuilder
{
    #region Fields
    /// <summary>Standard nuspec namespace required by <c>NuspecReader</c>.</summary>
    public const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";

    /// <summary>Arbitrary non-PE bytes standing in for a native/unmanaged dll (must fail managed load).</summary>
    public static readonly byte[] NotManagedBytes = [0x00, 0x01, 0x02, 0x03, 0x2A, 0x7F, 0x55, 0xAA, 0x13, 0x37];
    #endregion

    #region Methods
    /// <summary>Writes a zip at <paramref name="path"/> with the given (entry-name, bytes) pairs. Forward-slash names.</summary>
    public static void WriteNupkg(string path, IEnumerable<(string Name, byte[] Bytes)> entries) =>
        WriteNupkg(path, entries, []);

    /// <summary>
    /// Writes a zip at <paramref name="path"/> from <paramref name="entries"/> plus <paramref name="rawEntries"/>.
    /// Both are stored verbatim — <see cref="ZipArchive.CreateEntry(string)"/> does not normalize names — but
    /// <paramref name="rawEntries"/> exist to stage path-traversal ("zip-slip") names such as
    /// <c>../../evil.dll</c> that must be skipped on extraction.
    /// </summary>
    public static void WriteNupkg(
        string path,
        IEnumerable<(string Name, byte[] Bytes)> entries,
        IEnumerable<(string Name, byte[] Bytes)> rawEntries)
    {
        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Create);
        foreach (var (name, bytes) in entries)
            WriteEntry(zip, name, bytes);
        foreach (var (name, bytes) in rawEntries)
            WriteEntry(zip, name, bytes);
    }

    /// <summary>
    /// Writes one zip entry at the exact caller-supplied <paramref name="entryName"/> with <paramref name="bytes"/>.
    /// <see cref="ZipArchive.CreateEntry(string)"/> stores the name verbatim (no normalization), so a traversal
    /// name such as <c>../../evil.dll</c> is preserved — letting tests stage "zip-slip" payloads.
    /// </summary>
    public static void WriteEntry(ZipArchive zip, string entryName, byte[] bytes)
    {
        var entry = zip.CreateEntry(entryName);
        using var s = entry.Open();
        s.Write(bytes, 0, bytes.Length);
    }

    /// <summary>
    /// Minimal nuspec: id/version/authors/description plus a dependency group with the given ids. When
    /// <paramref name="repositoryUrl"/> and/or <paramref name="projectUrl"/> are non-null they are emitted as a
    /// <c>&lt;repository url="…"&gt;</c> element and a <c>&lt;projectUrl&gt;</c> element respectively (the
    /// project-health repo hints read by <c>NuGetPackage.ReadIdentity</c>, ADR 0015); when null they are omitted,
    /// exercising the back-compat "both stay null" path.
    /// </summary>
    public static string NuspecXml(
        string id, string version, string authors, string description,
        string dependencyTargetFramework, IEnumerable<(string Id, string Version)> dependencies,
        string? repositoryUrl = null, string? projectUrl = null)
    {
        var deps = string.Join(
            "\n        ",
            System.Linq.Enumerable.Select(
                dependencies, d => $"<dependency id=\"{d.Id}\" version=\"{d.Version}\" />"));

        var projectUrlElement = projectUrl is null ? string.Empty : $"\n    <projectUrl>{projectUrl}</projectUrl>";
        var repositoryElement = repositoryUrl is null ? string.Empty : $"\n    <repository url=\"{repositoryUrl}\" />";

        return $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>{version}</version>
                <authors>{authors}</authors>
                <description>{description}</description>{projectUrlElement}{repositoryElement}
                <dependencies>
                  <group targetFramework="{dependencyTargetFramework}">
                    {deps}
                  </group>
                </dependencies>
              </metadata>
            </package>
            """;
    }
    #endregion
}
