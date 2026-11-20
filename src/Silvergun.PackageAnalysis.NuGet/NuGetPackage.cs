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

using Silvergun.PackageAnalysis.NuGet.Yara;

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
        string? nuspecPath,
        string extractionDir,
        string contentRoot,
        IReadOnlyList<string> declaredEntryNames,
        IReadOnlyList<(string Declared, string Reported)> uninventoried,
        IReadOnlyList<string> yaraInventory,
        IReadOnlyList<NativeBinary> nativeBinaries,
        IReadOnlyList<string> nativeBinaryUnreadFiles,
        IReadOnlyList<UnextractedBundleRow> unextractedBundleEntries,
        IReadOnlyList<BundleFile> bundleYaraInventory)
    {
        Identity = identity;
        Assemblies = assemblies;
        Scripts = scripts;
        NuspecPath = nuspecPath;
        ExtractionDir = extractionDir;
        ContentRoot = contentRoot;
        DeclaredEntryNames = declaredEntryNames;
        UninventoriedDeclaredEntries = uninventoried;
        UninventoriedEntryNames = uninventoried.Select(x => x.Reported).ToArray();
        YaraInventory = yaraInventory;
        NativeBinaries = nativeBinaries;
        NativeBinaryUnreadFiles = nativeBinaryUnreadFiles;
        UnextractedBundleEntries = unextractedBundleEntries;
        BundleYaraInventory = bundleYaraInventory;
    }
    #endregion

    #region Properties
    /// <summary>Package identity and declared dependency tree, read from the nuspec.</summary>
    public PackageIdentityInfo Identity { get; }

    /// <summary>Inventoried binaries: all <c>.dll</c>/<c>.exe</c> anywhere in the package (incl. <see cref="PackageItemRole.Other"/>), extracted to disk.</summary>
    public IReadOnlyList<PackageAssembly> Assemblies { get; }

    /// <summary>Inventoried scripts/build files (<c>.ps1</c>/<c>.psm1</c>/<c>.targets</c>/<c>.props</c>) anywhere in the package.</summary>
    public IReadOnlyList<PackageScript> Scripts { get; }

    /// <summary>
    /// Extracted absolute path of the package manifest (top-level <c>*.nuspec</c>) when present and contained,
    /// else <c>null</c>. Deliberately kept out of <see cref="Scripts"/> (avoids inventory noise per ADR 0012);
    /// exposed only so the content scanner can rule-scan the manifest (ADR 0012 follow-up). Not serialized.
    /// </summary>
    public string? NuspecPath { get; }

    /// <summary>The unique temp directory this package's files were extracted into.</summary>
    public string ExtractionDir { get; }

    /// <summary>
    /// The directory every package-relative path is taken against — the one RecursiveExtractor nests the archive's
    /// entries under, named after the <c>.nupkg</c> — spelled <b>as it is on disk</b>, which is how
    /// <see cref="YaraInventory"/> and every extracted <c>FullPath</c> spell it. Computed once by <see cref="Open"/>
    /// (<see cref="ContentRootOf"/>) and shared, so the inventories and <c>PackageScanner</c>'s YARA hit paths cannot
    /// disagree about it; <see cref="ExtractionDir"/> itself when no such directory can be identified.
    /// </summary>
    internal string ContentRoot { get; }

    /// <summary>
    /// Every entry name declared in the <c>.nupkg</c>'s zip central directory, verbatim and UNFILTERED, in archive
    /// order — directory entries and zip-slip entries included. Names only: read without decompressing anything, so
    /// it stays bomb-safe (ADR 0008), on the same single archive pass the containment set is built from.
    ///
    /// ⚠️ These are raw, attacker-authored strings: they may contain control characters, bidi overrides or traversal
    /// segments. They are the input to <see cref="PackageEntryNameAnalyzer"/> (ADR 0031), which is what escapes them;
    /// never log or render one directly. This is what the package author WROTE, which is deliberately not the same as
    /// what the extractor put on disk — extraction clamps, renames, skips and silently overwrites.
    /// </summary>
    public IReadOnlyList<string> DeclaredEntryNames { get; }

    /// <summary>
    /// Declared FILE entries of ANY kind whose bytes as NuGet installs them were never analysed: never written as an
    /// extracted file of their own (dropped, renamed, clamped back inside the content root, or written over another
    /// entry's file), or written as a file whose bytes differ from what NuGet installs for that entry (ADR 0036). In
    /// archive order, deduplicated, already escaped with <see cref="YaraPathSafety.Escape"/> (safe to log and render).
    ///
    /// This is <b>coverage we did not deliver</b> (ADR 0030). It INCLUDES every entry that escapes the content root:
    /// containment still keeps such an entry out of the inventory (ADR 0008), but the extractor clamps its bytes onto
    /// a path inside the root — over a real file of that name, while NuGet installs the first copy — so its presence
    /// is lost coverage too (entry-aliasing review 5). The other known causes are extractor/OS-side: Windows cannot
    /// create a file whose name is a reserved DOS device (measured 2026-08-22 — RecursiveExtractor silently skips
    /// <c>lib/net8.0/COM1.dll</c> and still returns <c>Ok</c>), a case-only collision overwrites one of two entries, a
    /// name the filesystem refuses, a trailing space or dot that Windows silently drops when it creates the file (so the
    /// bytes land under a name no entry declares), two DIFFERENT declared names that fold to the SAME extracted path,
    /// where one entry's bytes overwrite the other's, a duplicate name whose copies differ, a Windows 8.3 short-name
    /// alias written over the long-named file, a name the extractor rewrites onto another entry's path (a leading drive
    /// segment dropped, on every platform; <c>&lt;</c>, <c>?</c>, <c>|</c>, <c>:</c> mapped to <c>_</c>, on Windows),
    /// and a record whose local header disagrees with the central directory (name, method or size).
    /// <see cref="PackageScanner"/> turns each of these into a skipped <see cref="AssemblyScanResult"/> so the package
    /// cannot report as complete.
    /// </summary>
    public IReadOnlyList<string> UninventoriedEntryNames { get; }

    /// <summary>
    /// The same lost entries as <see cref="UninventoriedEntryNames"/>, in the same order, each paired as
    /// (<c>Declared</c>: the raw entry name; <c>Reported</c>: its escaped form, which is the element published above).
    ///
    /// <para>Internal, because <c>Declared</c> is an unescaped attacker-authored string that must never be logged or
    /// rendered (ADR 0031 decision 4) — but role and target framework must be derived from it, not from
    /// <c>Reported</c>: escaping rewrites the characters it neutralizes, so a name carrying one would yield
    /// <see cref="PackageItemRole.Other"/> and a null TFM in the skip row <see cref="PackageScanner"/> synthesizes.</para>
    /// </summary>
    internal IReadOnlyList<(string Declared, string Reported)> UninventoriedDeclaredEntries { get; }

    /// <summary>
    /// The package's <b>YARA inventory</b> (ADR 0034): the absolute path of every file under <see cref="ExtractionDir"/>,
    /// listed by <see cref="Open"/> straight after extraction with <c>Directory.GetFiles(extractionDir, "*",
    /// SearchOption.AllDirectories)</c> — the same call, and so the same link and reparse-point semantics, that the YARA
    /// backends' own directory walk uses. It is the set YARA coverage is judged against:
    /// <see cref="PackageScanner"/> scans exactly these files (<see cref="IYaraScanner.ScanFiles"/>), so a file that is
    /// gone by the time YARA runs, minutes of CIL analysis later, is unscanned rather than silently absent.
    ///
    /// <para>Deliberately <b>unfiltered</b> by containment: YARA's scope is every extracted byte, including files no
    /// contained entry declares (which the assembly and script inventories drop).</para>
    ///
    /// <para>Internal, because these are <b>raw, attacker-authored</b> paths: they may contain control characters, bidi
    /// overrides or invisible characters, and must never be logged or rendered without <see cref="YaraPathSafety.Escape"/>.
    /// They stay raw because they are opened.</para>
    /// </summary>
    internal IReadOnlyList<string> YaraInventory { get; }

    /// <summary>
    /// Every contained file whose header is PE, ELF or Mach-O, whatever its name, except IL-only PEs the CIL inventory
    /// takes (<see cref="NativeBinaryCode"/>): read straight after extraction. Includes native and ReadyToRun
    /// <c>.dll</c>/<c>.exe</c> that are also in <see cref="Assemblies"/>, and extensionless executables that are not.
    /// </summary>
    public IReadOnlyList<NativeBinary> NativeBinaries { get; }

    /// <summary>Contained files whose header could not be read for <see cref="NativeBinaries"/>: escaped path and the
    /// exception type. Non-empty means that list may be missing entries.</summary>
    public IReadOnlyList<string> NativeBinaryUnreadFiles { get; }

    /// <summary>
    /// Single-file bundle entries (or whole bundles) that were NOT extracted, so their content was never analysed.
    /// <see cref="PackageScanner"/> reports each as a skipped assembly, so the package cannot read complete. Paths are
    /// escaped (<c>host!/entry</c>).
    /// </summary>
    internal IReadOnlyList<UnextractedBundleRow> UnextractedBundleEntries { get; }

    /// <summary>
    /// Every single-file bundle entry extracted under <see cref="BundleRoot"/>, of any kind, with its escaped
    /// <c>host!/entry</c> path: the second YARA inventory, judged exactly like <see cref="YaraInventory"/> (ADR 0034).
    /// <c>FullPath</c> is raw (opened, never logged).
    /// </summary>
    internal IReadOnlyList<BundleFile> BundleYaraInventory { get; }

    /// <summary>Where single-file bundles were unpacked: a sibling of <see cref="ExtractionDir"/>.</summary>
    internal string BundleRoot => BundleRootOf(ExtractionDir);
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
            string manifestName;
            using (var reader = new PackageArchiveReader(
                nupkgPath, DefaultFrameworkNameProvider.Instance, DefaultCompatibilityProvider.Instance))
            {
                identity = ReadIdentity(reader.NuspecReader);
                manifestName = reader.GetNuspecFile();
            }

            // Content extraction is delegated to RecursiveExtractor — bomb/nesting-resistant (ADR 0008).
            // On a decompression bomb the resource governor aborts (throws), caught below and surfaced as a
            // failure Result; a non-Ok status is likewise a failure. Never throws out of the factory.
            var opts = new ExtractorOptions
            {
                MaxExtractedBytes = MaxExtractedBytes,        // absolute cap (2 GiB)
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

            // The YARA inventory (ADR 0034), taken FIRST, before anything else reads the tree: what YARA must later account
            // for, file by file. Same call as the backends' own walk, no containment filter; a failure here fails Open
            // through the catch below like any other.
            var yaraInventory = Directory.GetFiles(extractionDir, "*", SearchOption.AllDirectories);

            // RecursiveExtractor nests the archive's entries under a directory named after the .nupkg file; ONE content
            // root, in its on-disk spelling, for everything below and for PackageScanner (see ContentRootOf).
            var contentRoot = ContentRootOf(extractionDir, nupkgPath);

            // Zip-slip containment (defense in depth over RecursiveExtractor — ADR 0008): the declared entry
            // names are untrusted. RecursiveExtractor neutralizes a traversal entry (e.g. "../../evil.dll") by
            // clamping it into the archive root rather than writing outside, so it cannot be excluded by an
            // on-disk under-root test alone. We validate the declared names here and inventory only files that
            // correspond to a contained (non-escaping) entry — preserving the pre-RE "escaping entries are
            // never inventoried" semantics.
            // One pass over the central directory yields both: the contained set (the inventory gate below) and the
            // full, unfiltered declared-name list that PackageEntryNameAnalyzer reports on (ADR 0031). (The content check
            // below re-opens the archive to decompress entries; this pass reads names only.)
            var (declaredEntryNames, contained) = ReadEntryNames(nupkgPath);

            // Derived from the YARA inventory rather than a second walk, so the tree is listed once: its files under
            // contentRoot by the same ordinal prefix RelativeUnderRoot strips — the sequence a walk of contentRoot yields,
            // because a recursive enumeration's order restricted to a subtree is that subtree's own order. Files outside
            // contentRoot (none when it IS extractionDir) were never in that walk, so they leave here, unwarned, before
            // the containment gate. The prefix holds because contentRoot is spelled as the inventory spells it.
            var files = yaraInventory
                .Where(full => IsUnderRoot(contentRoot, full))
                .Select(full => (full, rel: RelativeUnderRoot(contentRoot, full)))
                .Where(x => IsContained(x.rel, contained))
                .ToArray();

            // The other half of containment (ADR 0030): an entry we DECLARED, judged contained, and then never
            // inventoried is not a file that analysed clean — it is a file nothing looked at. Computed here, warned
            // distinctly from the zip-slip drops above, and carried on the package so PackageScanner can make the
            // report say so. Every entry that DOES claim a file is also checked to hold NuGet's bytes (ADR 0036), which
            // re-reads the archive: a second open, after extraction, deliberately separate from the names-only pass above.
            IReadOnlyList<(string Declared, string Reported)> uninventoried;
            using (var nugetView = ZipFile.OpenRead(nupkgPath))
                uninventoried = UninventoriedEntries(
                    declaredEntryNames,
                    files.Select(x => x.rel),
                    ContentMatchesNuGet(nugetView, files.ToDictionary(x => x.rel, x => x.full, StringComparer.Ordinal)));

            var assemblies = files
                .Where(x => IsAssembly(x.rel))
                .Select(x => MakeAssembly(x.rel, x.full))
                .ToArray();

            // RelativePath escaped at the DTO boundary for the same reason as MakeAssembly's (ADR 0031 decision 4);
            // FullPath stays raw because ScriptRuleScanner opens it.
            var scripts = files
                .Where(x => IsScript(x.rel))
                .Select(x => new PackageScript(YaraPathSafety.Escape(x.rel), x.full, RoleOf(x.rel)))
                .ToArray();

            // Native binaries by header, over every contained file (not just .dll/.exe): read now, while the tree is fresh.
            var (topNativeBinaries, nativeUnread, bundleHosts) = InventoryNativeBinaries(files);

            // Single-file bundles (native-binaries-3): their managed entries join the CIL inventory, their native entries
            // the native list, and every entry that could not be extracted becomes a reported coverage gap.
            // Bundle paths share the YARA finding namespace with EVERY extracted file, so they are made unique against all
            // of them (a top-level entry literally named "tools/App.exe!/readme.txt" must not alias a bundled one).
            var bundles = UnpackBundles(bundleHosts, BundleRootOf(extractionDir),
                assemblies.Select(a => a.RelativePath).Concat(topNativeBinaries.Select(b => b.RelativePath))
                    .Concat(yaraInventory.Select(f => YaraPathSafety.Escape(RelativeUnderRoot(contentRoot, f)))));
            assemblies = [.. assemblies, .. bundles.Assemblies];
            IReadOnlyList<NativeBinary> nativeBinaries = [.. topNativeBinaries, .. bundles.NativeBinaries];

            // Manifest for content scanning only — the top-level *.nuspec, already validated by the same
            // containment gate as every other file. Kept out of the script inventory (ADR 0012). It must be the entry
            // NuGet read the identity from, by NAME (ADR 0035 S5 review W-1): NuGet unescapes entry names, so a root entry
            // "A%2Fx.nuspec" is NOT a root manifest to NuGet, yet the extractor writes it verbatim at the root, where it
            // sorts before the real one and a first-match pick would scan the decoy instead. Matched ordinally on the
            // extracted relative path, or on its unescaped form when it carries a '%' (an old OPC-packed name such as
            // "My%20Pkg.nuspec", which NuGet reads as "My Pkg.nuspec"); that stays unambiguous, because NuGet throws when
            // two root entries unescape to manifests. Any other disagreement gives null, which PackageScanner reports as an
            // unscanned manifest rather than scanning the wrong file. That the BYTES on disk are that entry's — not an
            // aliasing entry's written over them — is UninventoriedEntries' job (tasks/entry-aliasing-coverage.md).
            var nuspecPath = files
                .Where(x => IsNuspec(x.rel) && IsManifestName(x.rel, manifestName))
                .Select(x => x.full)
                .FirstOrDefault();

            // identity.Id is nuspec content, i.e. attacker-authored: escaped like every other package-supplied
            // string that reaches a log line (ADR 0031 decision 4).
            Info("Opened package {0}: {1} assemblies, {2} scripts, {3} native binar(ies), {4} declared entr(ies) NOT inventoried.",
                YaraPathSafety.Escape(identity.Id), assemblies.Length, scripts.Length, nativeBinaries.Count, uninventoried.Count);
            op.Complete();
            return Result.Success(new NuGetPackage(
                identity, assemblies, scripts, nuspecPath, extractionDir, contentRoot, declaredEntryNames, uninventoried, yaraInventory,
                nativeBinaries, nativeUnread, bundles.Unextracted, bundles.Files));
        }
        catch (Exception ex)
        {
            TryDeleteDir(extractionDir);
            TryDeleteDir(BundleRootOf(extractionDir));
            return Result.FailureWithError<NuGetPackage>($"Failed to open NuGet package {nupkgPath}.", ex);
        }
    }

    /// <summary>Deletes the extraction directory and the bundle unpack root. Idempotent; IO failures are swallowed and warned.</summary>
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        TryDeleteDir(ExtractionDir);
        TryDeleteDir(BundleRootOf(ExtractionDir));
    }

    // Where single-file bundles unpack: a SIBLING of the extraction directory, so no walk of ExtractionDir (the yara CLI
    // backend's `yara -r`, any inventory) ever sees unpacked files, and no package entry name can collide with them.
    private static string BundleRootOf(string extractionDir) => extractionDir + "-bundles";

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
            dependencies,
            // Additive project-health repo hints (ADR 0015) — read straight from the nuspec, offline.
            NullIfEmpty(nuspec.GetRepositoryMetadata()?.Url),
            NullIfEmpty(nuspec.GetProjectUrl()));
    }

    // One pass over the zip central directory — names only, no decompression, so bomb-safe — yielding:
    //   Declared: every declared entry name verbatim and unfiltered, in archive order (see DeclaredEntryNames);
    //   Contained: the extracted-file path (see ContainmentKey) of every file entry that stays under the content
    //              root — the key set the inventory gate matches files on, forward-slash normalized.
    // Untrusted names are validated here as the zip-slip containment layer; RecursiveExtractor is the primary
    // guard (ADR 0008). An escaping entry is dropped from Contained (and so never inventoried) but is KEPT in
    // Declared, so PackageEntryNameAnalyzer can report it instead of the detection being silently discarded —
    // the defect ADR 0031 exists to fix.
    private static (IReadOnlyList<string> Declared, HashSet<string> Contained) ReadEntryNames(string nupkgPath)
    {
        using var zip = ZipFile.OpenRead(nupkgPath);
        var declared = zip.Entries.Select(e => e.FullName).ToArray();

        var contained = ContainedEntries(declared)
            .Select(x => x.Key)
            .ToHashSet(StringComparer.Ordinal);

        return (declared, contained);
    }

    // ADR 0036: whether the extracted file an entry claimed holds NuGet's bytes for that entry. RecursiveExtractor reads
    // through SharpCompress, which takes a record's name, compression method and sizes from its LOCAL header (and honours
    // the Info-ZIP Unicode Path field), while NuGet and ZipArchive read the CENTRAL directory — so a crafted package can
    // make the file we analyse differ from the one NuGet installs: a second "X.targets" record whose local name is
    // "W.targets" is written over W; a local header saying "stored" or a shorter size writes other bytes (review 7, C1/C2).
    //   * NuGet's bytes are the decompressed stream of ZipArchive's FIRST central-directory entry of that name (NuGet is
    //     first-wins); compared by SHA-256 with the file on disk. Never the CRC32 or sizes: the author writes those.
    //   * Bounded: zip-side and disk-side reads each share a budget of MaxExtractedBytes, the cap extraction just
    //     succeeded under (ZipArchive stops inflating at the central directory's size). An overrun, a read error or a
    //     missing entry is a mismatch — the entry is lost: fail-closed.
    // The returned check reads `zip`, so it must be called while `zip` is open.
    private static Func<string, string, bool> ContentMatchesNuGet(
        ZipArchive zip, IReadOnlyDictionary<string, string> filesByRel)
    {
        var firstByName = new Dictionary<string, ZipArchiveEntry>(StringComparer.Ordinal);
        foreach (var entry in zip.Entries)
            firstByName.TryAdd(entry.FullName, entry);

        var zipBudget = MaxExtractedBytes;
        var diskBudget = MaxExtractedBytes;
        var buffer = new byte[81920];
        return (name, key) =>
        {
            try
            {
                if (!firstByName.TryGetValue(name, out var entry) || !filesByRel.TryGetValue(key, out var full))
                    return false;

                using var nuget = entry.Open();
                using var disk = File.OpenRead(full);
                return HashBounded(nuget, buffer, ref zipBudget) is { } expected
                    && HashBounded(disk, buffer, ref diskBudget) is { } actual
                    && expected.AsSpan().SequenceEqual(actual);
            }
            catch (Exception ex)
            {
                // Unreadable on either side: not provably NuGet's bytes. The entry is reported lost either way; the
                // cause is kept for triage (escaped: the name and the message are package-derived).
                Debug("Content check for package entry {0} failed: {1}", YaraPathSafety.Escape(name),
                    YaraPathSafety.Escape($"{ex.GetType().Name}: {ex.Message}"));
                return false;
            }
        };
    }

    // SHA-256 of `stream`, or null once more than `remaining` bytes have been read across every call sharing it.
    private static byte[]? HashBounded(Stream stream, byte[] buffer, ref long remaining)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        for (int read; (read = stream.Read(buffer)) > 0;)
        {
            if ((remaining -= read) < 0)
                return null;
            sha.AppendData(buffer, 0, read);
        }
        return sha.GetHashAndReset();
    }

    // The declared FILE entries that stay inside the content root, in archive order, each paired with the path an
    // extracted file must have for that entry to claim it. Directory entries ending in '/' (the extractor drops their
    // bytes, and NuGet installs nothing for them) and escaping entries (ADR 0008) drop out. A name ending in '\' does
    // NOT: some old Windows zip tools write directories that way, but the extractor writes a NON-empty one as a FILE
    // under the name minus the '\' — over a real file of that name, while Linux NuGet installs the real one (measured,
    // entry-aliasing review 3) — and combined with any rename (case, 8.3, trailing dot, ':', a dropped drive) it lands
    // on a path its own key does not name (review 4), so no name- or inventory-based test can tell it from a directory.
    // It is therefore an ordinary entry: one that claims no file is lost. An empty "content\" from an old zip tool is
    // then a false "lost" — fail-closed, and none occurs in the benign corpus. Escaping entries are never inventoried
    // (ADR 0008), but they still WRITE: see UninventoriedEntries, which reports every one of them lost.
    private static IEnumerable<(string Name, string Key)> ContainedEntries(IReadOnlyList<string> declared) =>
        FileEntries(declared)
            .Where(name => !EscapesContentRoot(name))
            .Select(name => (name, ContainmentKey(name)));

    // Every declared entry that can carry bytes: non-empty, and not a '/'-terminated directory entry (measured with
    // every rename class: the extractor writes no bytes for those, and NuGet installs nothing for them or throws).
    private static IEnumerable<string> FileEntries(IReadOnlyList<string> declared) => declared.Where(IsFileEntryName);

    private static bool IsFileEntryName(string name) => !string.IsNullOrEmpty(name) && !name.EndsWith('/');

    // Declared FILE entries of ANY kind that were never written as an extracted file of their own, or whose extracted
    // file does not hold NuGet's bytes for them (ADR 0036) — see UninventoriedEntryNames. What is REPORTED is the name
    // the package author wrote, not the folded key — escaped,
    // because these are attacker-authored strings (ADR 0031 decision 4).
    //
    // An ESCAPING entry ("/x", "C:/x", "\x", "..") is lost unconditionally (entry-aliasing review 5, C1-r5). It is
    // never inventoried (ADR 0008), but the extractor clamps it onto a path INSIDE the root — over a real file of that
    // name, last-wins — while NuGet installs the FIRST copy (its CopyToFile skips an existing file), or refuses the
    // package. Measured on both platforms: "build/Some.Package.targets" (hook) followed by
    // "/build/Some.Package.targets" (decoy) scanned [OK] Clean, exit 0 under --strict, with NuGet installing the hook;
    // on Linux "C:/…" and "\…" decoys did the same. Its bytes land somewhere inside the root either way, so it never
    // counts as claiming a file.
    //
    // A CONTAINED entry is matched on the same key the inventory gate uses, so for it "not inventoried" means exactly
    // "IsContained never let a file through for this entry".
    //
    // Each extracted file is CLAIMED BY AT MOST ONE ENTRY, walking the entries in archive order. Asking each entry
    // independently "does my key exist on disk?" is unsound, because DIFFERENT declared names fold to the SAME key:
    // "content/../X.dll" and "content/X.dll" (also "content//X.dll", "content/./X.dll") all key to "content/X.dll",
    // the extractor writes both there, one silently overwrites the other, and under the independent test BOTH match
    // the single surviving file and NEITHER is reported. That is CaseOnlyCollision's failure mode — the file scanned
    // is not the file shipped — with the collision hidden from every check we have, so the attacker chooses the
    // archive order that leaves the benign bytes on disk and the package reads complete (ADR 0030).
    //
    // An entry that DOES claim a file must also hold NuGet's bytes for it (contentMatches, ADR 0036); otherwise it is
    // lost. That one check covers every case where the two readers disagree — a record's local-header name, method or
    // size differing from the central directory (review 7, C1/C2) — and DUPLICATE names: zip permits two entries with
    // the same name and different bytes; the extractor leaves the LAST on disk while NuGet installs the FIRST (measured,
    // both platforms), so the first occurrence's check fails when a later copy overwrote it, and passes when the copies
    // are byte-identical (39 Microsoft 3.1.0-era packages ship packageIcon.png twice). A later occurrence of a name is
    // therefore not weighed on its own. Naming the PAIR (a DuplicateEntryName anomaly, sibling of the
    // PathFoldingCollision category for the folding case above) stays a recorded follow-up.
    //
    // Every contained entry that claimed no file is lost, WHATEVER its kind (tasks/entry-aliasing-coverage.md). An entry
    // that claimed nothing was never written as its own file: it was dropped, renamed, or — the case that hid analysis —
    // written OVER another entry's file, whose bytes then never reached any scanner while that entry still claimed the
    // file and the package read complete. Measured 2026-10-25 / 2026-11-01, each with no report before this rule:
    //   * Windows name aliases: an 8.3 short name ("build/SOMEPA~1.TAR" over "build/Some.Package.targets": two script
    //     findings went to none) or a trailing dot/space ("Real.nuspec." over "Real.nuspec");
    //   * the extractor's own renames: on every platform it drops a leading drive segment ("./C:/Real.nuspec" is written
    //     to "Real.nuspec"); on Windows it also maps '<' '?' '|' ':' to '_' ("content/a:b.bin" over "content/a_b.bin";
    //     that mapping does NOT cover a ':' NuGet unescapes from "%3A", which NamesAStream makes lost outright);
    //   * a device name on Windows ("content/CON.txt"), whose bytes never reach disk at all.
    // A kind filter (assemblies and scripts only) missed every non-binary of these — the manifest and YARA's whole
    // scope — and 8.3 truncates the extension anyway (".TAR", ".NUS"). The rule needs NO filesystem access: an earlier
    // "does the name still resolve on disk?" test let an entry like "./C:/Windows/win.ini" probe the scanning host
    // (Path.Combine discards the root for a drive-qualified key) and still missed the extractor's renames (review C1/C2).
    // The cost is that an entry renamed onto a NEW file (Windows trimming "readme.txt " to "readme.txt") reads lost though
    // its bytes were scanned under the new name: fail-closed, and such names are already TrailingSpaceOrDot anomalies.
    private static IReadOnlyList<(string Declared, string Reported)> UninventoriedEntries(
        IReadOnlyList<string> declared, IEnumerable<string> inventoried, Func<string, string, bool> contentMatches)
    {
        var unclaimed = inventoried.ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var losses = new List<string>();

        foreach (var name in FileEntries(declared))
        {
            if (!seen.Add(name))
                continue;   // a later copy of a name: its first occurrence's content check decides (see above)

            // Lost when: an escaping name (clamped onto a path in the root, never allowed to claim one); a name NuGet
            // reads with a ':' (an NTFS stream, see NamesAStream); a contained name that claimed nothing (dropped,
            // renamed, or written over another entry's file); or one that claimed a file not holding NuGet's bytes. No
            // exemption by any name shape. The first two are tested before they could remove a key from `unclaimed` —
            // otherwise they would take a real entry's claim and that entry would be the one reported (still a loss,
            // but the wrong name).
            var key = ContainmentKey(name);
            if (EscapesContentRoot(name) || NamesAStream(name) || !unclaimed.Remove(key) || !contentMatches(name, key))
                losses.Add(name);
        }

        // Each lost name once, in archive order (`seen` weighs each raw name once). Deduplicated on the RAW name and
        // escaped only afterwards: Escape is not injective — a name containing a literal backslash-n and one containing
        // a real LF both render "\n" — so collapsing on the escaped text would undercount the very list whose job is
        // counting lost coverage. Both forms are kept: the escaped one is what may be published, the raw one is what
        // role/TFM must be derived from (see UninventoriedDeclaredEntries).
        var pairs = losses
            .Select(name => (Declared: name, Reported: YaraPathSafety.Escape(name)))
            .ToArray();

        foreach (var (_, reported) in pairs)
            Warn("Declared package entry {0} was NOT inventoried: it was never written as an extracted file of its own — " +
                 "dropped, renamed, clamped back inside the content root, written over another entry's file, or written " +
                 "with bytes other than those NuGet installs, or under a name NuGet installs as a different file (an " +
                 "NTFS stream) — so its content, or the content it replaced, was never " +
                 "analysed. This is analysis coverage NOT delivered — not a clean result.", reported);

        return pairs;
    }

    /// <summary>
    /// <c>true</c> when the declared zip entry <paramref name="entryName"/> does NOT name a file strictly inside the
    /// package content root — the classic zip-slip test, and the single definition of "escapes the content root" in
    /// this codebase: the extraction inventory uses it to drop such entries (ADR 0008), and
    /// <see cref="PackageEntryNameAnalyzer"/> reuses it to REPORT them (ADR 0031), rather than keeping a second copy
    /// that could drift. Both separators are honoured because entry names may use either.
    ///
    /// <para>The decision is <b>lexical</b>, on the name alone: an entry escapes iff it is empty, rooted, drive-
    /// qualified, or its <c>..</c> segments walk to or above the root. It is therefore total (never throws), pure,
    /// and gives the SAME answer on every platform. It deliberately does not consult
    /// <see cref="Path.GetFullPath(string)"/>, which is not a containment oracle on Windows: measured 2026-08-22,
    /// <c>Path.GetFullPath(@"C:\root\content\COM1.dll")</c> is <c>\\.\COM1</c>, because the Windows normalizer
    /// redirects DOS device names — so the old probe judged a perfectly contained <c>COM1.dll</c> to escape, dropped
    /// it from the inventory, and a payload under that name evaded the entire IL analysis on Windows while
    /// analysing normally on Linux (ADR 0030, sixth instance). Re-adding the normalizer as a second opinion is not
    /// defense in depth here: it can only subtract entries, and subtracting is exactly the failure mode.</para>
    ///
    /// <para>Note "to OR above the root": a name that resolves to the root itself (<c>"."</c>, <c>"content/.."</c>)
    /// names no file under it and so cannot be inventoried either. That is malformed rather than hostile, and
    /// <see cref="PackageEntryNameAnalyzer"/> does not REPORT it as an attack — it carves the case out explicitly by
    /// asking <see cref="ResolvedDepth"/>, since this predicate deliberately does not distinguish the two.</para>
    /// </summary>
    internal static bool EscapesContentRoot(string entryName)
    {
        if (string.IsNullOrEmpty(entryName)) return true;
        // Rooted ("/etc/x", "\\server\share\x") and drive-qualified ("C:\x", "D:x") names target an absolute
        // location. Tested structurally, on every platform: on Unix "C:\evil.dll" is a legal relative filename, so a
        // platform normalizer would happily call it contained.
        if (entryName[0] is '/' or '\\') return true;
        if (entryName.Length >= 2 && char.IsAsciiLetter(entryName[0]) && entryName[1] == ':') return true;

        return ResolvedDepth(entryName) <= 0;
    }

    /// <summary>
    /// How many path segments deep under the content root <paramref name="entryName"/> resolves — empty and
    /// <c>"."</c> segments are no-ops, <c>".."</c> steps back up — or <c>-1</c> as soon as it walks ABOVE the root.
    /// Purely lexical and total, like <see cref="EscapesContentRoot"/>, which is defined in terms of it.
    ///
    /// <para>Zero is the degenerate middle case the containment predicate cannot express: the name resolves to the
    /// root ITSELF (<c>"."</c>, <c>"content/.."</c>). It names no file in the package, so it is uninventoriable, but
    /// it escapes nothing — which is why <see cref="PackageEntryNameAnalyzer"/> must not report it as zip slip.
    /// Rooted and drive-qualified names are NOT considered here; they are handled by the caller.</para>
    /// </summary>
    internal static int ResolvedDepth(string entryName)
    {
        var depth = 0;
        foreach (var segment in Segments(entryName))
        {
            if (segment.Length == 0 || segment == ".") continue;      // empty ("a//b") and "." are no-ops
            if (segment != "..") { depth++; continue; }
            if (--depth < 0) return -1;                               // walked above the root
        }

        return depth;
    }

    // The path an extracted file must have for a contained entry to claim it, keyed the way the inventory compares:
    // separators folded to '/', empty, "." and ".." segments dropped, everything LEXICAL — never through the
    // platform normalizer, for the reason EscapesContentRoot gives.
    //
    // The ".." segments are STRIPPED, not resolved, because that is what the extractor does: measured 2026-08-22,
    // RecursiveExtractor writes "content/../Folded.dll" to "content/Folded.dll", where resolving would give
    // "Folded.dll". The resolved reading was also accepted as a second key for a while, and that was a hole rather
    // than tolerance: it put "X.dll" in the contained set on account of "content/../X.dll", so a SEPARATE escaping
    // entry "../X.dll" — correctly dropped by EscapesContentRoot — was clamped by the extractor into the archive
    // root as "X.dll", matched that key, and got INVENTORIED, breaking "escaping entries are never inventoried" to
    // buy nothing that was ever observed on disk. One key, the measured one.
    private static string ContainmentKey(string entryName) =>
        string.Join('/', Segments(entryName).Where(s => s.Length > 0 && s != "." && s != ".."));

    // The content root (see ContentRoot), spelled as Directory.GetFiles spells it: the top-level directories of
    // extractionDir are listed, so each comes back joined onto extractionDir exactly as the inventory's paths are. In order:
    //   1. the directory named Path.GetFileName(nupkgPath), matched ORDINALLY among them — the ordinary case, and the
    //      exact string the old Path.Combine produced, so ordinary output is unchanged;
    //   2. otherwise, the ONE top-level directory when there is exactly one — the extractor's directory under the name
    //      the filesystem actually gave it. Win32 trims a trailing dot or space when it creates a directory, so for
    //      "x.nupkg." it is "x.nupkg" (measured 2026-10-24). Directory.Exists could not catch that: it normalizes
    //      "x.nupkg." the same way and says true, and the misspelled root then matched no inventory path by prefix —
    //      every YARA hit path rendered absolute, carrying the user's temp layout into the report. Nothing in the
    //      package can create a sibling of that directory (a zip-slip entry is clamped inside it, measured);
    //   3. otherwise extractionDir, as before.
    private static string ContentRootOf(string extractionDir, string nupkgPath)
    {
        var expected = Path.Combine(extractionDir, Path.GetFileName(nupkgPath));
        var directories = Directory.GetDirectories(extractionDir);
        return directories.Contains(expected, StringComparer.Ordinal) ? expected
            : directories.Length == 1 ? directories[0]
            : extractionDir;
    }

    // Path of an extracted file relative to the content root, normalized to forward slashes. Computed by STRING
    // PREFIX, not by Path.GetRelativePath: that helper resolves both operands through the platform normalizer, so on
    // Windows it answers "\\.\COM1" for a file named COM1.dll under the root (measured) — a value that matches no
    // declared entry and silently costs the file its inventory slot. Every path here comes from an enumeration under
    // contentRoot, so the prefix always matches; a path that is somehow NOT under the root is returned unchanged,
    // which matches no containment key and is skipped with a warning rather than mis-attributed. Total by
    // construction — the normalizer can throw on a pathological name, and a throw here would sink the whole package.
    // Internal so PackageScanner derives the YARA hit path exactly the same way instead of keeping a second copy.
    internal static string RelativeUnderRoot(string contentRoot, string fullPath) =>
        (IsUnderRoot(contentRoot, fullPath) ? fullPath[RootPrefix(contentRoot).Length..] : fullPath).Replace('\\', '/');

    // The containment half of RelativeUnderRoot, on its own: fullPath lies under contentRoot by that same ordinal prefix.
    private static bool IsUnderRoot(string contentRoot, string fullPath) =>
        fullPath.StartsWith(RootPrefix(contentRoot), StringComparison.Ordinal);

    private static string RootPrefix(string contentRoot) =>
        contentRoot.EndsWith(Path.DirectorySeparatorChar) ? contentRoot : contentRoot + Path.DirectorySeparatorChar;

    // Inventory gate: the file must correspond to a contained declared entry (zip-slip containment). The containment
    // decision is the lexical one above, taken when `contained` was built — nothing here re-derives it through the
    // platform's path normalizer, which is what used to drop device-named entries. A file that reaches this gate
    // without a matching entry is not a zip-slip drop: the extractor clamped or renamed some declared name into it
    // (a "../../evil.dll" written into the archive root), and the entry it came from is reported separately.
    private static bool IsContained(string rel, HashSet<string> contained)
    {
        if (contained.Contains(rel)) return true;

        Warn("Skipping extracted file {0}: no contained package entry declares this path — the extractor clamped or " +
             "renamed a declared name into it (e.g. a zip-slip entry written to the archive root).",
             YaraPathSafety.Escape(rel));
        return false;
    }

    // The report boundary for an inventoried binary (ADR 0031 decision 4): RelativePath derives from an
    // attacker-authored entry name and is escaped HERE, where the DTO is built, not at render — on Linux the
    // extractor writes control characters verbatim, and a renderer that only Markup-escapes would let
    // "tools/pay<LF>load.dll" split a table row and forge report lines. FullPath stays raw: it is used to open the
    // file, so it must remain a real path and is never rendered.
    private static PackageAssembly MakeAssembly(string relativePath, string fullPath)
    {
        var role = RoleOf(relativePath);
        using var fs = File.OpenRead(fullPath);
        var sha = Convert.ToHexStringLower(SHA256.HashData(fs));
        return new PackageAssembly(
            YaraPathSafety.Escape(relativePath), fullPath, TargetFrameworkOf(relativePath, role), role, sha);
    }

    // Native binaries among the contained files (NativeBinaryDetector), escaped and hashed at the DTO boundary like
    // MakeAssembly's. A file that cannot be read is recorded rather than failing Open: unlike an assembly, ANY file is
    // probed here, so one locked or vanished file must not sink the package.
    // Also returns the single-file bundles found (header offset known and plausible), for UnpackBundles.
    private static (IReadOnlyList<NativeBinary> Found, IReadOnlyList<string> Unread, IReadOnlyList<BundleHost> Bundles) InventoryNativeBinaries(
        IEnumerable<(string full, string rel)> files)
    {
        var (found, unread, bundles) = (new List<NativeBinary>(), new List<string>(), new List<BundleHost>());
        foreach (var (full, rel) in files)
        {
            try
            {
                using var fs = File.OpenRead(full);
                // An IL-only PE is dropped only when the CIL inventory takes it (IsAssembly): under any other name
                // nothing else would analyse or name it.
                if (NativeBinaryDetector.Detect(fs) is not { } h || (h.Code == NativeBinaryCode.ILOnly && IsAssembly(rel)))
                    continue;
                var (binary, headerOffset) = MakeNativeBinary(fs, h, YaraPathSafety.Escape(rel), RoleOf(rel));
                found.Add(binary);
                // Every native bundle, including one whose header failed its checks (offset -1): UnpackBundles reports
                // that one as a gap rather than letting a labelled, unanalysed bundle read complete.
                if (binary.DotNetHost == DotNetHost.SingleFileBundle)
                    bundles.Add(new(full, binary.RelativePath, binary.Role, headerOffset));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                unread.Add($"{YaraPathSafety.Escape(rel)} ({ex.GetType().Name})");
            }
        }
        if (unread.Count > 0)
            Warn("Native binary scan INCOMPLETE: {0} file(s) could not be read: {1}", unread.Count, string.Join(", ", unread.Take(5)));
        return (found, unread, bundles);
    }

    // `path` if no reported path has it yet, else the first free "path#index", "path#index-2", ... Every result is
    // recorded, so a manifest name that is itself shaped like a suffixed path cannot collide with one.
    private static string Unique(string path, int index, HashSet<string> reported)
    {
        if (reported.Add(path))
            return path;
        for (var k = 1; ; k++)
            if ($"{path}#{index}{(k == 1 ? string.Empty : $"-{k}")}" is var candidate && reported.Add(candidate))
                return candidate;
    }

    // The DTO for a detected binary and, for an unpackable bundle, its header offset (else -1). A real apphost/bundle is a
    // native image with no CLR header; managed files that merely hold the signature as data (Microsoft.NET.HostModel.dll,
    // R2R in SDK 8+) are not hosts.
    private static (NativeBinary Binary, long BundleHeaderOffset) MakeNativeBinary(Stream fs, NativeBinaryHeader h, string reported, PackageItemRole role)
    {
        var scan = DotNetHostScanner.Scan(fs);
        var native = h.Code == NativeBinaryCode.Native;
        return (new NativeBinary(reported, h.Format, h.Kind, h.Architecture, h.Code, role, fs.Length, scan.Sha256,
                native ? scan.Host : DotNetHost.None, native ? scan.BundledFiles : null),
            native ? scan.BundleHeaderOffset : -1);
    }

    // Unpacks each single-file bundle under bundleRoot/<n> (a sibling of ExtractionDir, see BundleRootOf) and classifies
    // every extracted entry by CONTENT, never by the manifest's type byte or name: readable metadata (IL-only, R2R, mixed)
    // => an assembly for the CIL analysis; native code, R2R or mixed => a native binary. Reported paths are "host!/entry",
    // both halves escaped, made unique against every other reported path (Unique: "#<index>" on a clash) because
    // consumers key on them; role is the host's. Coverage gaps, each a skipped result downstream: every entry not
    // extracted, a bundle whose header failed its checks, a bundle nested in a bundle (labelled, not unpacked), and
    // everything past the limits: MaxBundles bundles, MaxBundleBytes charged on ATTEMPT, MaxBundleEntries attempted.
    // Files: every extracted entry, binary or not, with its reported path, for the YARA pass over the bundle root.
    private static (IReadOnlyList<PackageAssembly> Assemblies, IReadOnlyList<NativeBinary> NativeBinaries, IReadOnlyList<UnextractedBundleRow> Unextracted, IReadOnlyList<BundleFile> Files) UnpackBundles(
        IReadOnlyList<BundleHost> hosts, string bundleRoot, IEnumerable<string> topLevelPaths)
    {
        var (assemblies, natives, gaps, files) = (new List<PackageAssembly>(), new List<NativeBinary>(), new List<UnextractedBundleRow>(), new List<BundleFile>());
        var (budget, entriesLeft, reported) = (MaxBundleBytes, MaxBundleEntries, new HashSet<string>(topLevelPaths, StringComparer.Ordinal));
        for (var n = 0; n < hosts.Count; n++)
        {
            var host = hosts[n];
            string Inner(string name, int index) => Unique($"{host.Reported}!/{YaraPathSafety.Escape(name)}", index, reported);
            UnextractedBundleRow Gap(string name, int index, string why) => new(Inner(name, index), host.Role, host.FullPath,
                $"single-file bundle entry was NOT extracted: {why} (its content was never analysed - coverage not delivered, not a clean result)");
            if (n >= MaxBundles || host.HeaderOffset < 0)
            {
                gaps.Add(Gap(string.Empty, -1, n >= MaxBundles
                    ? $"more than {MaxBundles} bundles in the package"
                    : "the bundle header could not be located or failed its checks"));
                continue;
            }
            try
            {
                var (extracted, failed, charged, attempted) = SingleFileBundle.Extract(host.FullPath, host.HeaderOffset,
                    Path.Combine(bundleRoot, n.ToString(System.Globalization.CultureInfo.InvariantCulture)), budget, entriesLeft);
                budget -= charged;
                entriesLeft -= attempted;
                gaps.AddRange(failed.Select(f => Gap(f.Name, f.Index, f.Reason)));
                foreach (var e in extracted)
                {
                    var file = new BundleFile(e.FullPath, Inner(e.Name, e.Index));
                    files.Add(file);
                    using var fs = File.OpenRead(e.FullPath);
                    if (NativeBinaryDetector.Detect(fs) is not { } h)
                        continue;
                    var (binary, _) = MakeNativeBinary(fs, h, file.Reported, host.Role);
                    if (h.Code != NativeBinaryCode.Native)
                        assemblies.Add(new PackageAssembly(binary.RelativePath, e.FullPath, null, host.Role, binary.Sha256));
                    if (h.Code != NativeBinaryCode.ILOnly)
                        natives.Add(binary);
                    if (binary.DotNetHost == DotNetHost.SingleFileBundle)
                        gaps.Add(new(binary.RelativePath, host.Role, host.FullPath,
                            "single-file bundle entry was NOT extracted: it is itself a single-file bundle, and nested bundles are " +
                            "not unpacked (its content was never analysed - coverage not delivered, not a clean result)"));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                gaps.Add(Gap(string.Empty, -1, $"{ex.GetType().Name} while unpacking"));
            }
        }
        if (gaps.Count > 0)
            Warn("Single-file bundle unpacking INCOMPLETE: {0} entr(ies) not extracted, e.g. {1}", gaps.Count, gaps[0].Reported);
        return (assemblies, natives, gaps, files);
    }

    // THE kind test, and there is deliberately only one: it decides what the inventory gate picks up off disk (and so
    // what the CIL and script analyses see). It no longer decides what is lost — UninventoriedEntries counts every kind —
    // but a second copy of it once trimmed differently and a file fell between the two; see KindKey.
    private static bool IsAssembly(string entry) =>
        HasExtension(KindKey(entry), ".dll", ".exe");

    private static bool IsScript(string entry) =>
        HasExtension(KindKey(entry), ".ps1", ".psm1", ".targets", ".props");

    // The package manifest lives at the archive root (no path segments), e.g. "Foo.nuspec". Deliberately NOT
    // trimmed: unlike the kinds above this picks ONE file rather than filtering many. Being a root *.nuspec is not
    // enough to be THE manifest — a decoy can be one too (see Open, which also requires the name NuGet itself read
    // the identity from, ADR 0035 S5 review W-1); this only narrows the candidates. Like every entry, a manifest entry
    // that was never written as its own file is reported by UninventoriedEntries; and when no manifest reaches disk
    // (NuspecPath null), PackageScanner also reports it as an unscanned script/manifest file (ADR 0035).
    private static bool IsNuspec(string entry) =>
        NuGetName(entry) is var name && HasExtension(name, ".nuspec") && Segments(name).Length == 1;

    // Whether the extracted root file `rel` is the manifest NuGet read, named `manifestName` (see Open). The ordinal arm
    // is subsumed by the second wherever it could matter (two root nuspecs make NuGet refuse the package, measured in
    // entry-aliasing review 9); it is kept as the plain reading of "the file NuGet named".
    private static bool IsManifestName(string rel, string manifestName) =>
        string.Equals(rel, manifestName, StringComparison.Ordinal)
        || string.Equals(NuGetName(rel), manifestName, StringComparison.Ordinal);

    // An entry's name as NuGet reads it: NuGet unescapes '%xx' (NuGet.Packaging.ZipArchiveExtensions.UnescapePath, which
    // is exactly Uri.UnescapeDataString behind the same '%' test — read from its IL; CopyFiles unescapes the raw name
    // once, so "%252E" installs as "%2E"), and installs and acts on THAT name, while the extractor writes the raw one to
    // disk (entry-aliasing review 8). So every decision about what an entry IS — its kind, role, TFM, whether it is the
    // manifest — is made on this name: a "build/Some.Package%2Etargets" is installed by NuGet as
    // "build/Some.Package.targets", and must be script-scanned as one, though it sits on disk under its raw name
    // (measured: a %2E-named .targets, .ps1, .props or .dll was installed by NuGet and never analysed). The paths we
    // read and report stay raw: they are the files on disk. Where several raw names unescape to one STRING, every one
    // of them is analysed, a superset of the one NuGet installs. Names the FILESYSTEM aliases: when the extractor makes
    // the alias (case, 8.3, a trimmed dot), the claim walk and content check catch it; when NuGet's own write makes it
    // from an escaped name ("BUILDT%7E1/", "build%2E/", "%5C%5C.%5C"), the raw name is written verbatim and is covered
    // because every raw name is analysed under its NuGet kind and NuGet keeps the first copy of a path (measured,
    // entry-aliasing review 10); NTFS streams are lost outright (NamesAStream).
    internal static string NuGetName(string entry) => entry.Contains('%') ? Uri.UnescapeDataString(entry) : entry;

    // Whether NuGet's name for an entry holds a ':' — any ':', so a "C%3A/…" NuGet would unescape to a drive is lost
    // too (Windows NuGet refuses such a package anyway; a RAW drive-qualified name already escapes, ADR 0008). On Windows ':'
    // is the NTFS stream separator, so NuGet's "build/X.targets::$DATA" — unescaped from "…targets%3A%3A%24DATA" — IS
    // build\X.targets (entry-aliasing review 9, C1: a real restore installed it and imported it into the build), while
    // the extractor writes the raw "%3A" name, a file of no kind, and the package read clean. A RAW ':' is renamed to
    // '_' by the extractor on Windows (so it claims nothing and is lost) but written verbatim on Linux, where the same
    // package read clean for a Windows consumer. So any ':' is lost, on every platform, whatever follows it: no package
    // in the 6,563-package local cache has one, raw or escaped.
    internal static bool NamesAStream(string entry) => NuGetName(entry).Contains(':');

    // The file name a script's LANGUAGE is decided on (ScriptRuleScanner): the last segment of its kind name, so
    // "tools/install%2Eps1" — and on Linux "install.ps1 " — is PowerShell, as NuGet installs it, and gets the
    // PowerShell-only rules (entry-aliasing review 9, C2: chosen from the raw name, such a script lost two of them).
    internal static string KindFileName(string entry) => Segments(KindKey(entry))[^1];

    // What a path's KIND is decided on: the path with trailing spaces and dots trimmed, because Windows drops them
    // when it creates the file (measured 2026-08-22: File.Create("X.dll ") and File.Create("Y.dll.") silently
    // produce "X.dll" and "Y.dll", no exception), while Linux writes such a name to disk verbatim. So a declared
    // "lib/net8.0/evil.dll " reaches this test from BOTH sides and must get the same answer from each:
    //   Windows — no file is extracted under the declared name, so the entry claims nothing and UninventoriedEntries
    //     reports it lost (it now counts every kind; when it counted only assemblies and scripts, this trim was what
    //     kept "evil.dll " from being judged uninteresting and the package from reading complete).
    //   Linux — the file IS extracted verbatim, so the entry claims it and nothing is reported lost; untrimmed the
    //     inventory gate then declines to inventory it, and the payload is contained, extracted, never
    //     IL-analysed, and never mentioned. Same silent hole, opposite platform (both ADR 0030).
    // Trimming can only ADD a path to a kind (it strips a suffix that is not part of any extension we match), and
    // it cannot turn a non-assembly into one: "content/readme.txt " and "content/evil.dll.txt " trim to
    // "…readme.txt" and "…evil.dll.txt" and are still excluded. Only the kind DECISION uses this form — the
    // inventoried RelativePath and the reported lost-entry name both stay the real, escaped name, since that is
    // the name the package declares and (on Linux) the name on disk. The kind is decided on the name NuGet installs
    // (NuGetName, '%xx' unescaped), so a "%2Etargets" is a script exactly as NuGet treats it.
    private static string KindKey(string entry) => NuGetName(entry).TrimEnd(' ', '.');

    private static bool HasExtension(string entry, params ReadOnlySpan<string> extensions)
    {
        foreach (var ext in extensions)
            if (entry.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) return true;

        return false;
    }

    // Internal (not private) so PackageScanner can label a declared entry that never reached the inventory with the
    // same role/TFM every inventoried file gets — both are pure functions of the entry name and need no file. Both read
    // the name NuGet installs (NuGetPackage.NuGetName): "lib%2Fnet8.0%2FA.dll" is NuGet's lib/net8.0/A.dll.
    internal static PackageItemRole RoleOf(string entry) => Segments(NuGetName(entry))[0].ToLowerInvariant() switch
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
    internal static string? TargetFrameworkOf(string entry, PackageItemRole role)
    {
        var segments = Segments(NuGetName(entry));
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

    // The absolute cap on extracted bytes (ADR 0008), shared by the extractor's options and each side of the content
    // check in ContentMatchesNuGet (ADR 0036), which reads no more than the extraction already accepted.
    private const long MaxExtractedBytes = 2L * 1024 * 1024 * 1024;   // 2 GiB

    // Single-file bundle unpacking limits, per package: bytes charged (on attempt) across all bundles, bundles unpacked,
    // and entries attempted across all bundles (each becomes CIL work, so this bounds analysis amplification).
    private const long MaxBundleBytes = 1L * 1024 * 1024 * 1024;     // 1 GiB
    private const int MaxBundles = 32, MaxBundleEntries = 4096;
    #endregion
}
