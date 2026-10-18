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
        IReadOnlyList<string> declaredEntryNames,
        IReadOnlyList<(string Declared, string Reported)> uninventoried)
    {
        Identity = identity;
        Assemblies = assemblies;
        Scripts = scripts;
        NuspecPath = nuspecPath;
        ExtractionDir = extractionDir;
        DeclaredEntryNames = declaredEntryNames;
        UninventoriedDeclaredEntries = uninventoried;
        UninventoriedEntryNames = uninventoried.Select(x => x.Reported).ToArray();
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
    /// Declared entries that this package DECLARES, that are CONTAINED (so not zip-slip exclusions), that are of a
    /// kind we inventory (<c>.dll</c>/<c>.exe</c>/<c>.ps1</c>/<c>.psm1</c>/<c>.targets</c>/<c>.props</c>) — and for
    /// which no extracted file exists, so they were never inventoried and can never be analysed. In archive order,
    /// deduplicated, already escaped with <see cref="YaraPathSafety.Escape"/> (safe to log and render).
    ///
    /// This is <b>coverage we did not deliver</b>, and it is deliberately NOT the same thing as an entry dropped for
    /// escaping the content root: a zip-slip drop is containment working, this is analysis that did not happen
    /// (ADR 0030). The known causes are all extractor/OS-side: Windows cannot create a file whose name is a reserved
    /// DOS device (measured 2026-08-22 — RecursiveExtractor silently skips <c>lib/net8.0/COM1.dll</c> and still
    /// returns <c>Ok</c>), a case-only collision overwrites one of two entries, a name the filesystem refuses,
    /// a trailing space or dot that Windows silently drops when it creates the file (so the bytes land under a name
    /// no entry declares), or two DIFFERENT declared names that fold to the SAME extracted path, where one entry's
    /// bytes overwrite the other's. <see cref="PackageScanner"/> turns each of these into a skipped
    /// <see cref="AssemblyScanResult"/> so the package cannot report as complete.
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
            // One pass over the central directory yields both: the contained set (the inventory gate below) and the
            // full, unfiltered declared-name list that PackageEntryNameAnalyzer reports on (ADR 0031). The archive is
            // deliberately not opened twice.
            var (declaredEntryNames, contained) = ReadEntryNames(nupkgPath);

            var files = Directory.EnumerateFiles(contentRoot, "*", SearchOption.AllDirectories)
                .Select(full => (full, rel: RelativeUnderRoot(contentRoot, full)))
                .Where(x => IsContained(x.rel, contained))
                .ToArray();

            // The other half of containment (ADR 0030): an entry we DECLARED, judged contained, and then never
            // inventoried is not a file that analysed clean — it is a file nothing looked at. Computed here, warned
            // distinctly from the zip-slip drops above, and carried on the package so PackageScanner can make the
            // report say so.
            var uninventoried = UninventoriedEntries(declaredEntryNames, files.Select(x => x.rel));

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

            // Manifest for content scanning only — the top-level *.nuspec, already validated by the same
            // containment gate as every other file. Kept out of the script inventory (ADR 0012). Null when absent.
            var nuspecPath = files
                .Where(x => IsNuspec(x.rel))
                .Select(x => x.full)
                .FirstOrDefault();

            // identity.Id is nuspec content, i.e. attacker-authored: escaped like every other package-supplied
            // string that reaches a log line (ADR 0031 decision 4).
            Info("Opened package {0}: {1} assemblies, {2} scripts, {3} declared entr(ies) NOT inventoried.",
                YaraPathSafety.Escape(identity.Id), assemblies.Length, scripts.Length, uninventoried.Count);
            op.Complete();
            return Result.Success(new NuGetPackage(
                identity, assemblies, scripts, nuspecPath, extractionDir, declaredEntryNames, uninventoried));
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

    // The declared FILE entries that stay inside the content root, in archive order, each paired with the path an
    // extracted file must have for that entry to claim it. Directory entries and escaping entries (ADR 0008) drop
    // out here.
    private static IEnumerable<(string Name, string Key)> ContainedEntries(IReadOnlyList<string> declared) =>
        declared
            .Where(name => !string.IsNullOrEmpty(name) && !name.EndsWith('/') && !EscapesContentRoot(name))
            .Select(name => (name, ContainmentKey(name)));

    // Declared, contained, inventoriable entries with no extracted file behind them — see UninventoriedEntryNames.
    // Matched on the same key the inventory gate uses, so "not inventoried" means exactly "IsContained never let a
    // file through for this entry". Only assemblies and scripts count: they are the file kinds the inventory
    // carries, and a missing readme is not lost analysis. What is REPORTED is the name the package author wrote,
    // not the folded key — escaped, because these are attacker-authored strings (ADR 0031 decision 4).
    //
    // Each extracted file is CLAIMED BY AT MOST ONE ENTRY, walking the entries in archive order. Asking each entry
    // independently "does my key exist on disk?" is unsound, because DIFFERENT declared names fold to the SAME key:
    // "content/../X.dll" and "content/X.dll" (also "content//X.dll", "content/./X.dll") all key to "content/X.dll",
    // the extractor writes both there, one silently overwrites the other, and under the independent test BOTH match
    // the single surviving file and NEITHER is reported. That is CaseOnlyCollision's failure mode — the file scanned
    // is not the file shipped — with the collision hidden from every check we have, so the attacker chooses the
    // archive order that leaves the benign bytes on disk and the package reads complete (ADR 0030).
    //
    // Duplicate declared NAMES are out of scope here — they claim once, and the second occurrence is not counted as
    // coverage lost — but NOT because they are "one entry declared twice": zip permits two entries with the same name
    // and DIFFERENT bytes, and they resolve differently: measured on .NET 10 on both platforms 2026-08-22,
    // ZipArchive.GetEntry returns the FIRST while a sequential extract-all (RecursiveExtractor included) leaves the
    // LAST on disk — so a consumer reading by name and Silvergun reading the extraction see different bytes. That is a
    // real instance of "the file scanned is not the file shipped", and it belongs to the PAIR rather than to either
    // name on its own, so neither entry is the right thing to call lost. Both follow-ups are recorded, not built: a
    // DuplicateEntryName anomaly category owns this pair, as the sibling of the PathFoldingCollision category that
    // will own the folding case above. PackageEntryNameAnalyzer likewise rules exact ordinal duplicates out of
    // CaseOnlyCollision's scope, and the two must agree until those categories exist.
    private static IReadOnlyList<(string Declared, string Reported)> UninventoriedEntries(
        IReadOnlyList<string> declared, IEnumerable<string> inventoried)
    {
        var unclaimed = inventoried.ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var lost = new List<string>();

        foreach (var (name, key) in ContainedEntries(declared))
        {
            if (!seen.Add(name)) continue;              // the same name declared twice: one entry, one claim
            if (unclaimed.Remove(key)) continue;        // claimed the extracted file; no other entry may claim it

            // Exactly the kind test the inventory gate applies, trailing-space/dot trim included (see KindKey) —
            // the same predicate, not a second copy that agrees today. The two DID diverge once, and a file fell
            // between them: this side trimmed and the gate did not, so on Linux "lib/net8.0/evil.dll " claimed its
            // own extracted file (nothing reported lost) and then failed the gate's untrimmed IsAssembly (never
            // inventoried, never analysed) — contained, on disk, and absent from the report, exit 0 (ADR 0030).
            // What is REPORTED stays the declared name; only the kind decision sees the trimmed form.
            if (IsAssembly(key) || IsScript(key)) lost.Add(name);
        }

        // Deduplicated on the RAW name (by `seen`) and escaped only afterwards: Escape is not injective — a name
        // containing a literal backslash-n and one containing a real LF both render "\n" — so collapsing on the
        // escaped text would undercount the very list whose job is counting lost coverage. Both forms are kept: the
        // escaped one is what may be published, the raw one is what role/TFM must be derived from (see
        // UninventoriedDeclaredEntries).
        var pairs = lost.Select(name => (Declared: name, Reported: YaraPathSafety.Escape(name))).ToArray();

        foreach (var (_, reported) in pairs)
            Warn("Declared package entry {0} was NOT inventoried: it stays inside the content root, but no extracted " +
                 "file corresponds to it, so it was never analysed. This is analysis coverage NOT delivered — not a " +
                 "zip-slip exclusion, and not a clean result.", reported);

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

    // Path of an extracted file relative to the content root, normalized to forward slashes. Computed by STRING
    // PREFIX, not by Path.GetRelativePath: that helper resolves both operands through the platform normalizer, so on
    // Windows it answers "\\.\COM1" for a file named COM1.dll under the root (measured) — a value that matches no
    // declared entry and silently costs the file its inventory slot. Every path here comes from an enumeration under
    // contentRoot, so the prefix always matches; a path that is somehow NOT under the root is returned unchanged,
    // which matches no containment key and is skipped with a warning rather than mis-attributed. Total by
    // construction — the normalizer can throw on a pathological name, and a throw here would sink the whole package.
    // Internal so PackageScanner derives the YARA hit path exactly the same way instead of keeping a second copy.
    internal static string RelativeUnderRoot(string contentRoot, string fullPath)
    {
        var root = contentRoot.EndsWith(Path.DirectorySeparatorChar) ? contentRoot : contentRoot + Path.DirectorySeparatorChar;
        var rel = fullPath.StartsWith(root, StringComparison.Ordinal) ? fullPath[root.Length..] : fullPath;
        return rel.Replace('\\', '/');
    }

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

    // THE kind test, and there is deliberately only one: it decides both what the inventory gate picks up off disk
    // and what UninventoriedEntries counts as coverage lost. Those two used to trim differently and a file fell
    // between them — see KindKey.
    private static bool IsAssembly(string entry) =>
        HasExtension(KindKey(entry), ".dll", ".exe");

    private static bool IsScript(string entry) =>
        HasExtension(KindKey(entry), ".ps1", ".psm1", ".targets", ".props");

    // The package manifest lives at the archive root (no path segments), e.g. "Foo.nuspec". Deliberately NOT
    // trimmed: unlike the kinds above this picks ONE file rather than filtering many, so accepting "Foo.nuspec "
    // could only let a decoy win the FirstOrDefault against the real manifest. Nothing is lost by excluding it —
    // the nuspec is not part of the inventory and so is not analysis coverage UninventoriedEntries can report.
    private static bool IsNuspec(string entry) =>
        HasExtension(entry, ".nuspec") && Segments(entry).Length == 1;

    // What a path's KIND is decided on: the path with trailing spaces and dots trimmed, because Windows drops them
    // when it creates the file (measured 2026-08-22: File.Create("X.dll ") and File.Create("Y.dll.") silently
    // produce "X.dll" and "Y.dll", no exception), while Linux writes such a name to disk verbatim. So a declared
    // "lib/net8.0/evil.dll " reaches this test from BOTH sides and must get the same answer from each:
    //   Windows — no file is extracted under the declared name, so the entry claims nothing and reaches
    //     UninventoriedEntries, where the raw key does not end in ".dll"; untrimmed it would be judged
    //     uninteresting and the package would read complete, exit 0 even under --strict, with a payload on disk
    //     under the folded name and never analysed.
    //   Linux — the file IS extracted verbatim, so the entry claims it and nothing is reported lost; untrimmed the
    //     inventory gate then declines to inventory it, and the payload is contained, extracted, never
    //     IL-analysed, and never mentioned. Same silent hole, opposite platform (both ADR 0030).
    // Trimming can only ADD a path to a kind (it strips a suffix that is not part of any extension we match), and
    // it cannot turn a non-assembly into one: "content/readme.txt " and "content/evil.dll.txt " trim to
    // "…readme.txt" and "…evil.dll.txt" and are still excluded. Only the kind DECISION uses this form — the
    // inventoried RelativePath and the reported lost-entry name both stay the real, escaped name, since that is
    // the name the package declares and (on Linux) the name on disk.
    private static string KindKey(string entry) => entry.TrimEnd(' ', '.');

    private static bool HasExtension(string entry, params ReadOnlySpan<string> extensions)
    {
        foreach (var ext in extensions)
            if (entry.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) return true;

        return false;
    }

    // Internal (not private) so PackageScanner can label a declared entry that never reached the inventory with the
    // same role/TFM every inventoried file gets — both are pure functions of the entry name and need no file.
    internal static PackageItemRole RoleOf(string entry) => Segments(entry)[0].ToLowerInvariant() switch
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
