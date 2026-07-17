namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;

using global::NuGet.Frameworks;
using global::NuGet.Packaging;

using Microsoft.CST.RecursiveExtractor;

/// <summary>
/// An opened, extracted <c>.nupkg</c> session. <see cref="Open"/> reads the nuspec identity, extracts the
/// package to a unique temp directory with <see cref="Extractor">RecursiveExtractor</see> (bomb/nesting-resistant
/// per ADR 0008), then inventories the assemblies (all <c>.dll</c>/<c>.exe</c> anywhere in the package, incl.
/// <see cref="PackageItemRole.Other"/> per ADR 0004 §3 as amended 2026-07-15) and scripts (<c>.ps1</c>/
/// <c>.targets</c>/<c>.props</c>) from disk. <see cref="Dispose"/> deletes that directory (idempotent). Obtain
/// instances through <see cref="Open"/>; the constructor is private. Never throws from the factory — failures
/// are returned as a <see cref="Result{T}"/>.
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

            // NuGet's reader is used ONLY for nuspec metadata (ADR 0008); disposed before extraction so it
            // does not hold the .nupkg while RecursiveExtractor reads it.
            PackageIdentityInfo identity;
            using (var reader = new PackageArchiveReader(
                nupkgPath, DefaultFrameworkNameProvider.Instance, DefaultCompatibilityProvider.Instance))
            {
                identity = ReadIdentity(reader.NuspecReader);
            }

            // Content extraction is delegated to RecursiveExtractor — bomb/nesting-resistant (ADR 0008).
            // On a decompression bomb the resource governor aborts (throws), caught below and surfaced as a
            // failure Result; a non-Ok status is likewise a failure. Never throws out of the factory.
            var opts = new ExtractorOptions
            {
                MaxExtractedBytes = 2L * 1024 * 1024 * 1024, // absolute cap (2 GiB)
                MaxExtractedBytesRatio = 200.0,               // zip-bomb ratio cap (its default; set explicitly)
                Timeout = TimeSpan.FromMinutes(2),
                // Recurse=false inventories the nupkg's own entries only. Unwinding *nested* archives inside a
                // nupkg (e.g. a dll hidden in a bundled zip) is a real hostile-input enhancement but changes
                // inventory results — deferred to a follow-up so this increment stays behavior-preserving.
                Recurse = false,
            };
            var status = new Extractor().ExtractToDirectory(extractionDir, nupkgPath, opts);
            if (status != ExtractionStatusCode.Ok)
            {
                TryDeleteDir(extractionDir);
                return Result.FailureWithError<NuGetPackage>($"Failed to extract package {nupkgPath} (status {status}).");
            }

            // RecursiveExtractor nests the archive's entries under a directory named after the .nupkg file.
            var contentRoot = Path.Combine(extractionDir, Path.GetFileName(nupkgPath));
            if (!Directory.Exists(contentRoot)) contentRoot = extractionDir;

            // Zip-slip containment (defense in depth over RecursiveExtractor — ADR 0008): the declared entry
            // names are untrusted. RecursiveExtractor neutralizes a traversal entry (e.g. "../../evil.dll") by
            // clamping it into the archive root rather than writing outside, so it cannot be excluded by an
            // on-disk under-root test alone. We validate the declared names here and inventory only files that
            // correspond to a contained (non-escaping) entry — preserving the pre-RE "escaping entries are
            // never inventoried" semantics.
            var contained = ContainedEntryPaths(nupkgPath, contentRoot);

            var files = Directory.EnumerateFiles(contentRoot, "*", SearchOption.AllDirectories)
                .Select(full => (full, rel: RelativeUnderRoot(contentRoot, full)))
                .Where(x => IsContained(x.rel, x.full, contained, extractionDir))
                .ToArray();

            var assemblies = files
                .Where(x => IsAssembly(x.rel))
                .Select(x => MakeAssembly(x.rel, x.full))
                .ToArray();

            var scripts = files
                .Where(x => IsScript(x.rel))
                .Select(x => new PackageScript(x.rel, RoleOf(x.rel)))
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

    // The declared entry names (read straight from the zip central directory — names only, no decompression,
    // so bomb-safe) whose target path stays under contentRoot, normalized to forward slashes. Untrusted names
    // are validated here as the zip-slip containment layer; RecursiveExtractor is the primary guard (ADR 0008).
    private static HashSet<string> ContainedEntryPaths(string nupkgPath, string contentRoot)
    {
        var root = Path.GetFullPath(contentRoot);
        if (!root.EndsWith(Path.DirectorySeparatorChar)) root += Path.DirectorySeparatorChar;

        using var zip = ZipFile.OpenRead(nupkgPath);
        return zip.Entries
            .Select(e => e.FullName)
            .Where(name => !string.IsNullOrEmpty(name) && !name.EndsWith('/'))
            .Where(name =>
            {
                var target = Path.GetFullPath(Path.Combine(contentRoot,
                    name.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar)));
                return target.StartsWith(root, StringComparison.Ordinal);
            })
            .Select(name => name.Replace('\\', '/'))
            .ToHashSet(StringComparer.Ordinal);
    }

    // Path of an extracted file relative to the content root, normalized to forward slashes.
    private static string RelativeUnderRoot(string contentRoot, string fullPath) =>
        Path.GetRelativePath(contentRoot, fullPath).Replace('\\', '/');

    // Inventory gate: the file must correspond to a contained declared entry (zip-slip containment), and its
    // canonical path must remain under the extraction directory (belt-and-suspenders, defense in depth).
    private static bool IsContained(string rel, string fullPath, HashSet<string> contained, string extractionDir)
    {
        if (!contained.Contains(rel))
        {
            Warn("Skipping extracted file {0}: does not match a contained package entry.", rel);
            return false;
        }

        var full = Path.GetFullPath(fullPath);
        var root = Path.GetFullPath(extractionDir);
        if (!root.EndsWith(Path.DirectorySeparatorChar)) root += Path.DirectorySeparatorChar;
        if (!full.StartsWith(root, StringComparison.Ordinal))
        {
            Warn("Skipping extracted file {0}: resolves outside the extraction directory.", rel);
            return false;
        }

        return true;
    }

    private static PackageAssembly MakeAssembly(string relativePath, string fullPath)
    {
        var role = RoleOf(relativePath);
        using var fs = File.OpenRead(fullPath);
        var sha = Convert.ToHexStringLower(SHA256.HashData(fs));
        return new PackageAssembly(relativePath, fullPath, TargetFrameworkOf(relativePath, role), role, sha);
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

    // Entry names may use '/' or '\' separators — some packing tools (Windows Compress-Archive) and malformed/
    // malicious packages emit backslashes, which ZipArchive/PackageArchiveReader preserve verbatim. Treat both
    // as separators everywhere entry paths are interpreted.
    private static string[] Segments(string entry) => entry.Split('/', '\\');

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
