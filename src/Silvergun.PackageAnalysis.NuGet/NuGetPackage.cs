namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

using global::NuGet.Common;
using global::NuGet.Frameworks;
using global::NuGet.Packaging;

/// <summary>
/// An opened, extracted <c>.nupkg</c> session. <see cref="Open"/> reads the nuspec identity, inventories
/// the assemblies (all <c>.dll</c>/<c>.exe</c> anywhere in the package, incl. <see cref="PackageItemRole.Other"/>
/// per ADR 0004 §3 as amended 2026-07-15) and scripts (<c>.ps1</c>/
/// <c>.targets</c>/<c>.props</c>), and extracts only those inventoried files to a unique temp directory.
/// <see cref="Dispose"/> deletes that directory (idempotent). Obtain instances through <see cref="Open"/>;
/// the constructor is private. Never throws from the factory — failures are returned as a <see cref="Result{T}"/>.
/// </summary>
public sealed class NuGetPackage : Runtime, IDisposable
{
    #region Constructors
    private NuGetPackage(
        PackageIdentityInfo identity,
        IReadOnlyList<PackageAssembly> assemblies,
        IReadOnlyList<PackageScript> scripts,
        string extractionDir)
    {
        Identity = identity;
        Assemblies = assemblies;
        Scripts = scripts;
        ExtractionDir = extractionDir;
    }
    #endregion

    #region Properties
    /// <summary>Package identity and declared dependency tree, read from the nuspec.</summary>
    public PackageIdentityInfo Identity { get; }

    /// <summary>Inventoried binaries: all <c>.dll</c>/<c>.exe</c> anywhere in the package (incl. <see cref="PackageItemRole.Other"/>), extracted to disk.</summary>
    public IReadOnlyList<PackageAssembly> Assemblies { get; }

    /// <summary>Inventoried scripts/build files (<c>.ps1</c>/<c>.targets</c>/<c>.props</c>) anywhere in the package.</summary>
    public IReadOnlyList<PackageScript> Scripts { get; }

    /// <summary>The unique temp directory this package's files were extracted into.</summary>
    public string ExtractionDir { get; }
    #endregion

    #region Methods
    /// <summary>
    /// Opens <paramref name="nupkgPath"/>, reads its nuspec, inventories assemblies and scripts, and extracts
    /// the inventoried files to a unique temp directory. Never throws: a missing file, non-zip content, or any
    /// read/extract failure is returned as a failure <see cref="Result{T}"/> (the temp dir is cleaned up first).
    /// </summary>
    public static Result<NuGetPackage> Open(string nupkgPath)
    {
        if (string.IsNullOrWhiteSpace(nupkgPath) || !File.Exists(nupkgPath))
            return Result.FailureWithError<NuGetPackage>($"NuGet package file not found: {nupkgPath}.");

        var extractionDir = Path.Combine(Path.GetTempPath(), "silvergun", "pkg-" + RandomString(12));
        using var op = Begin("Opening NuGet package {0}", nupkgPath);
        try
        {
            Directory.CreateDirectory(extractionDir);
            using var reader = new PackageArchiveReader(
                nupkgPath, DefaultFrameworkNameProvider.Instance, DefaultCompatibilityProvider.Instance);

            var identity = ReadIdentity(reader.NuspecReader);
            var files = reader.GetFiles().ToArray();

            var assemblies = files
                .Where(IsAssembly)
                .Select(entry => (entry, full: TryExtract(reader, entry, extractionDir)))
                .Where(x => x.full is not null)
                .Select(x => MakeAssembly(x.entry, x.full!))
                .ToArray();

            var scripts = files
                .Where(IsScript)
                .Select(entry => { TryExtract(reader, entry, extractionDir); return new PackageScript(entry, RoleOf(entry)); })
                .ToArray();

            Info("Opened package {0}: {1} assemblies, {2} scripts.", identity.Id, assemblies.Length, scripts.Length);
            op.Complete();
            return Result.Success(new NuGetPackage(identity, assemblies, scripts, extractionDir));
        }
        catch (Exception ex)
        {
            TryDeleteDir(extractionDir);
            return Result.FailureWithError<NuGetPackage>($"Failed to open NuGet package {nupkgPath}.", ex);
        }
    }

    /// <summary>Deletes the extraction directory. Idempotent; IO failures are swallowed and warned.</summary>
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        TryDeleteDir(ExtractionDir);
    }

    private static PackageIdentityInfo ReadIdentity(NuspecReader nuspec)
    {
        var dependencies = nuspec.GetDependencyGroups()
            .SelectMany(g => g.Packages.Select(p => new PackageDependencyInfo(
                p.Id,
                p.VersionRange?.ToNormalizedString() ?? string.Empty,
                g.TargetFramework.GetShortFolderName())))
            .ToArray();

        return new PackageIdentityInfo(
            nuspec.GetId(),
            nuspec.GetVersion().ToNormalizedString(),
            NullIfEmpty(nuspec.GetAuthors()),
            NullIfEmpty(nuspec.GetDescription()),
            dependencies);
    }

    // Extracts a single inventoried entry; returns the on-disk path, or null on failure (warned, non-fatal).
    private static string? TryExtract(PackageArchiveReader reader, string entry, string extractionDir)
    {
        try
        {
            var target = Path.Combine(extractionDir, entry.Replace('/', Path.DirectorySeparatorChar));

            // Zip-slip defense: the entry name is untrusted; a crafted "../../evil.dll" would escape the
            // extraction dir. Reject any entry whose resolved path is not under the extraction directory.
            var fullTarget = Path.GetFullPath(target);
            var root = Path.GetFullPath(extractionDir);
            if (!root.EndsWith(Path.DirectorySeparatorChar)) root += Path.DirectorySeparatorChar;
            if (!fullTarget.StartsWith(root, StringComparison.Ordinal))
            {
                Warn("Skipping package entry {0}: resolves outside the extraction directory.", entry);
                return null;
            }

            return reader.ExtractFile(entry, target, NullLogger.Instance);
        }
        catch (Exception ex)
        {
            Warn("Failed to extract package entry {0}: {1}", entry, ex.Message);
            return null;
        }
    }

    private static PackageAssembly MakeAssembly(string entry, string fullPath)
    {
        var role = RoleOf(entry);
        using var fs = File.OpenRead(fullPath);
        var sha = Convert.ToHexStringLower(SHA256.HashData(fs));
        return new PackageAssembly(entry, fullPath, TargetFrameworkOf(entry, role), role, sha);
    }

    private static bool IsAssembly(string entry) =>
        HasExtension(entry, ".dll") || HasExtension(entry, ".exe");

    private static bool IsScript(string entry) =>
        HasExtension(entry, ".ps1") || HasExtension(entry, ".targets") || HasExtension(entry, ".props");

    private static bool HasExtension(string entry, string ext) =>
        entry.EndsWith(ext, StringComparison.OrdinalIgnoreCase);

    private static PackageItemRole RoleOf(string entry) => Segments(entry)[0].ToLowerInvariant() switch
    {
        "lib" => PackageItemRole.Lib,
        "runtimes" => PackageItemRole.Runtimes,
        "tools" => PackageItemRole.Tools,
        "build" => PackageItemRole.Build,
        "buildtransitive" => PackageItemRole.BuildTransitive,
        "analyzers" => PackageItemRole.Analyzers,
        "content" or "contentfiles" => PackageItemRole.Content,
        _ => PackageItemRole.Other
    };

    // Lib/Build/BuildTransitive: the TFM is the 2nd segment (e.g. lib/net6.0/Foo.dll). Runtimes: it is the 4th
    // (runtimes/<rid>/lib/<tfm>/Foo.dll). Present only when a file follows the TFM segment; else null.
    private static string? TargetFrameworkOf(string entry, PackageItemRole role)
    {
        var segments = Segments(entry);
        return role switch
        {
            PackageItemRole.Lib or PackageItemRole.Build or PackageItemRole.BuildTransitive =>
                segments.Length >= 3 ? segments[1] : null,
            PackageItemRole.Runtimes =>
                segments.Length >= 5 && segments[2].Equals("lib", StringComparison.OrdinalIgnoreCase)
                    ? segments[3] : null,
            _ => null
        };
    }

    private static string[] Segments(string entry) => entry.Split('/');

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static void TryDeleteDir(string dir)
    {
        try
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Warn("Failed to delete extraction directory {0}: {1}", dir, ex.Message);
        }
    }
    #endregion

    #region Fields
    private bool disposed;
    #endregion
}
