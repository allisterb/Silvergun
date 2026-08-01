namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using global::NuGet.Common;
using global::NuGet.Packaging;
using global::NuGet.Protocol;
using global::NuGet.Protocol.Core.Types;
using global::NuGet.Versioning;

/// <summary>Which <c>lib/</c> folder was chosen for a package, what else was on offer, and why.</summary>
public sealed record TfmChoice(string? Tfm, IReadOnlyList<string> Available)
{
    #region Properties
    /// <summary>True when <see cref="TfmSelection"/>'s rule found nothing it is willing to scan.</summary>
    public bool IsEmpty => Tfm is null;
    #endregion
}

/// <summary>
/// The TFM rule, stated once and applied identically to every package. A package ships many <c>lib/&lt;tfm&gt;</c>
/// folders; silently scanning a different one per package would make cross-package comparison meaningless, so the
/// rule is fixed here and the chosen TFM is written into the report next to every number derived from it.
/// <para><b>Rule.</b> Among <c>lib/&lt;tfm&gt;/</c> folders containing at least one <c>.dll</c>:</para>
/// <list type="number">
/// <item><description>prefer the highest <c>net&lt;major&gt;.&lt;minor&gt;</c> (numeric compare, no platform
/// suffix - <c>net8.0-windows</c> is deliberately <b>not</b> a candidate, because its surface differs from plain
/// <c>net8.0</c> and mixing the two across packages is exactly the incomparability this rule exists to prevent);
/// </description></item>
/// <item><description>else exactly <c>netstandard2.0</c>;</description></item>
/// <item><description>else none - the package is reported as <c>no-scannable-tfm</c>, never silently dropped.
/// </description></item>
/// </list>
/// </summary>
public static class TfmSelection
{
    #region Methods
    /// <summary>Applies the rule to the package-relative file paths of a <c>.nupkg</c>.</summary>
    public static TfmChoice Choose(IEnumerable<string> packageFiles)
    {
        var available = packageFiles
            .Select(LibFolderOf)
            .Where(f => f is not null)
            .Select(f => f!)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToArray();

        var newest = available
            .Select(f => (Tfm: f, Match: NetCoreTfm.Match(f)))
            .Where(c => c.Match.Success)
            .OrderByDescending(c => int.Parse(c.Match.Groups[1].Value))
            .ThenByDescending(c => int.Parse(c.Match.Groups[2].Value))
            .Select(c => c.Tfm)
            .FirstOrDefault();

        return new TfmChoice(
            newest ?? available.FirstOrDefault(f => string.Equals(f, NetStandard, StringComparison.Ordinal)),
            available);
    }

    /// <summary>The <c>lib/&lt;tfm&gt;</c> folder a <c>.dll</c> entry sits directly in, or null for anything else.</summary>
    public static string? LibFolderOf(string packageFile)
    {
        var parts = packageFile.Split('/');
        return parts.Length == 3
            && parts[0].Equals("lib", StringComparison.OrdinalIgnoreCase)
            && parts[2].EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? parts[1]
                : null;
    }
    #endregion

    #region Fields
    public const string NetStandard = "netstandard2.0";

    private static readonly Regex NetCoreTfm = new(@"^net(\d+)\.(\d+)$", RegexOptions.CultureInvariant);
    #endregion
}

/// <summary>A cached package on disk: the .nupkg, the chosen TFM, and the assemblies extracted from it.</summary>
public sealed record CachedPackage(
    ManifestEntry Entry,
    string? NupkgPath,
    TfmChoice Tfm,
    IReadOnlyList<string> AssemblyPaths,
    string? Failure);

/// <summary>
/// Downloads pinned <c>.nupkg</c>s through <c>NuGet.Protocol</c>'s <see cref="FindPackageByIdResource"/> and caches
/// them <b>outside the repository</b> (default <c>%LOCALAPPDATA%/Silvergun/benign-corpus</c>). A cached .nupkg is
/// never re-downloaded, which is what makes the second determinism run offline-safe and fast; a .nupkg is never
/// written anywhere the repo could pick it up.
/// </summary>
public sealed class PackageCache(string root, string feedUrl = PackageCache.NuGetV3Feed)
{
    #region Properties
    /// <summary>The cache root. Created on first use.</summary>
    public string Root { get; } = root;
    #endregion

    #region Methods
    /// <summary>
    /// Ensures <paramref name="entry"/> is downloaded and its chosen-TFM assemblies extracted. Never throws: every
    /// failure comes back as <see cref="CachedPackage.Failure"/> so the driver can report the package rather than
    /// lose it.
    /// </summary>
    public async Task<CachedPackage> AcquireAsync(ManifestEntry entry, CancellationToken ct = default)
    {
        try
        {
            var nupkg = Path.Combine(Root, "packages", $"{entry.Id}.{entry.Version}.nupkg");
            if (!File.Exists(nupkg))
            {
                var downloaded = await DownloadAsync(entry, nupkg, ct);
                if (downloaded is not null)
                    return new CachedPackage(entry, null, new TfmChoice(null, []), [], downloaded);
            }

            using var reader = new PackageArchiveReader(nupkg);
            var files = reader.GetFiles().ToArray();
            var choice = TfmSelection.Choose(files);
            if (choice.IsEmpty)
                return new CachedPackage(entry, nupkg, choice, [], null);

            var target = Path.Combine(Root, "extracted", $"{entry.Id}.{entry.Version}", choice.Tfm!);
            Directory.CreateDirectory(target);

            var assemblies = files
                .Where(f => string.Equals(TfmSelection.LibFolderOf(f), choice.Tfm, StringComparison.Ordinal))
                .OrderBy(f => f, StringComparer.Ordinal)
                .Select(f => reader.ExtractFile(f, Path.Combine(target, Path.GetFileName(f)), NullLogger.Instance))
                .ToArray();

            return new CachedPackage(entry, nupkg, choice, assemblies, null);
        }
        catch (Exception ex)
        {
            return new CachedPackage(entry, null, new TfmChoice(null, []), [], $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    // Returns null on success, or a reason string. The .nupkg is written to a temp name and moved into place so an
    // interrupted download can never be mistaken for a cached package on the next run.
    private async Task<string?> DownloadAsync(ManifestEntry entry, string nupkg, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(nupkg)!);

        if (!NuGetVersion.TryParse(entry.Version, out var version))
            return $"unparseable version '{entry.Version}'";

        var resource = await repository.GetResourceAsync<FindPackageByIdResource>(ct);
        if (resource is null)
            return "feed did not offer a FindPackageByIdResource";

        var temp = nupkg + ".partial";
        using var cache = new SourceCacheContext();
        bool copied;
        await using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            copied = await resource.CopyNupkgToStreamAsync(
                entry.Id, version, stream, cache, NullLogger.Instance, ct);

        if (!copied)
        {
            File.Delete(temp);
            return $"nuget.org has no {entry.Id} {entry.Version}";
        }

        File.Move(temp, nupkg, overwrite: true);
        return null;
    }
    #endregion

    #region Fields
    public const string NuGetV3Feed = "https://api.nuget.org/v3/index.json";

    private readonly SourceRepository repository = Repository.Factory.GetCoreV3(feedUrl);
    #endregion
}
