namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// Finds packaging anomalies in a package's DECLARED entry names (ADR 0031) — names read from the zip central
/// directory, which is the ground truth for what the package author wrote, as opposed to what an extractor
/// happened to write to disk (extraction may clamp, rename, refuse or silently overwrite).
///
/// <see cref="Analyze"/> is a PURE function over strings: no filesystem, no I/O, no ambient state, deterministic
/// and order-stable, and it never throws. That is deliberate — ADR 0031's consequences push detection into name
/// analysis rather than filesystem behaviour precisely so these tests run on every platform, unlike ADR 0029's
/// Linux-only ones. The only path-shaped call it makes is the shared zip-slip containment predicate
/// (<see cref="NuGetPackage.EscapesContentRoot"/>), which is itself a lexical, platform-independent, total function
/// over the name — it touches no disk and consults no path normalizer.
///
/// Every entry name and every fragment of a detail string that leaves this analyzer is escaped with
/// <see cref="YaraPathSafety.Escape"/> (ADR 0031 decision 4): these names are attacker-authored, and none of them
/// is ever allowed to reach a log line, a terminal or the JSON raw. Nothing here gates <c>--strict</c> or any
/// exit code (ADR 0031 decision 3).
/// </summary>
public static class PackageEntryNameAnalyzer
{
    #region Methods
    /// <summary>
    /// Analyzes <paramref name="declaredEntryNames"/> (verbatim zip central-directory names, in archive order) and
    /// returns every anomaly found, in a stable order: entries in input order, and within one entry the categories
    /// in <see cref="PackagingAnomalyCategory"/> declaration order. One entry may yield several anomalies; a
    /// <see cref="PackagingAnomalyCategory.CaseOnlyCollision"/> is reported once per colliding group, on the group's
    /// first member. Null/empty names are ignored. Never throws; a null list yields an empty result.
    /// </summary>
    public static IReadOnlyList<PackagingAnomaly> Analyze(IReadOnlyList<string>? declaredEntryNames)
    {
        if (declaredEntryNames is null || declaredEntryNames.Count == 0)
            return Array.Empty<PackagingAnomaly>();

        var names = declaredEntryNames.Where(n => !string.IsNullOrEmpty(n)).ToArray();
        var collisions = CollisionGroups(names);
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        return names
            .SelectMany(name => AnalyzeOne(name, collisions, reported))
            .ToArray();
    }

    // Every anomaly for a single entry name, in PackagingAnomalyCategory declaration order. The collision group is
    // consumed here rather than in a second pass so the group's anomaly lands at its first member's position,
    // keeping the whole result in input order.
    //
    // The per-name checks also judge the name as NuGet reads it ('%xx' unescaped, NuGetPackage.NuGetName): NuGet
    // installs "content/invoice%E2%80%AEfdp.exe" with a real U+202E, and refuses "%2E%2E/…" as traversal (entry-aliasing
    // review 9, W1). The REPORTED name stays the raw one the package declares.
    private static IEnumerable<PackagingAnomaly> AnalyzeOne(
        string name, IReadOnlyDictionary<string, IReadOnlyList<string>> collisions, HashSet<string> reported)
    {
        var nugetName = NuGetPackage.NuGetName(name);
        string? Judge(Func<string, string?> detail) =>
            detail(name) ?? (nugetName == name ? null : detail(nugetName) is { } d ? $"{d}, as NuGet unescapes it" : null);

        var details = new (PackagingAnomalyCategory Category, string? Detail)[]
        {
            (PackagingAnomalyCategory.ControlCharacter, Judge(n => CodePointDetail(n, IsControlPoint, "control"))),
            (PackagingAnomalyCategory.BidiControl, Judge(n => CodePointDetail(n, IsBidiPoint, "bidirectional control"))),
            (PackagingAnomalyCategory.InvisibleCharacter, Judge(n => CodePointDetail(n, IsInvisiblePoint, "invisible"))),
            (PackagingAnomalyCategory.PathTraversal, Judge(TraversalDetail)),
            (PackagingAnomalyCategory.CaseOnlyCollision, CollisionDetail(name, collisions, reported)),
            (PackagingAnomalyCategory.TrailingSpaceOrDot, Judge(TrailingSpaceOrDotDetail)),
            (PackagingAnomalyCategory.ReservedDeviceName, Judge(ReservedDeviceNameDetail)),
        };

        var escapedName = YaraPathSafety.Escape(name);
        return details
            .Where(d => d.Detail is not null)
            .Select(d => new PackagingAnomaly(d.Category, escapedName, d.Detail!));
    }

    // "contains N character(s) U+xxxx, U+yyyy" for the code points of the name matching <paramref name="predicate"/>,
    // or null when there are none. Enumerated as RUNES, not chars: the Unicode Tag block (U+E0000-U+E007F) is astral,
    // so a per-char scan would only ever see its surrogate halves and miss it entirely. A LONE surrogate decodes to
    // U+FFFD here, which matches no predicate — a malformed name is not, by itself, one of these anomalies.
    private static string? CodePointDetail(string name, Func<int, bool> predicate, string what)
    {
        var points = name.EnumerateRunes()
            .Select(r => r.Value)
            .Where(predicate)
            .Distinct()
            .Take(MaxReportedCodePoints + 1)
            .ToArray();

        if (points.Length == 0)
            return null;

        var shown = string.Join(", ", points.Take(MaxReportedCodePoints).Select(cp => $"U+{cp:X4}"));
        return points.Length > MaxReportedCodePoints
            ? $"contains {what} character(s) {shown}, ..."
            : $"contains {what} character(s) {shown}";
    }

    // Why this entry's target does not stay inside the package content root, or null when it does.
    //
    // The escape test itself is NOT reimplemented here: it is NuGetPackage.EscapesContentRoot, the very predicate the
    // extraction inventory uses to drop zip-slip entries (ADR 0008) — which is the detection ADR 0031 exists to stop
    // throwing away. Since the dos-device-name fix it is lexical and total, so this method needs no try/catch: there
    // is no platform normalizer left to refuse a pathological name.
    //
    // Rooted and drive-qualified names are tested FIRST, before the shared predicate, only because they earn their own
    // wording — the predicate rejects them too, and on every platform (on Unix "C:\evil.dll" is a legal relative
    // filename, so a normalizer-based probe would have found it contained).
    private static string? TraversalDetail(string name)
    {
        if (IsDriveQualified(name))
            return "drive-qualified entry name (targets an absolute location outside the package)";
        if (name[0] is '/' or '\\')
            return "rooted (absolute) entry name (targets a location outside the package)";

        // A relative, non-rooted, non-drive-qualified name can only LEAVE the root through a ".." segment, so its
        // presence is a necessary condition and costs no true positives. This guard was originally load-bearing: it
        // hid the Windows normalizer's DOS-device redirect (Path.GetFullPath(@"C:\root\content\CON.txt") == @"\\.\CON"),
        // which otherwise reported every reserved-device entry as traversal on Windows only. That redirect is gone —
        // containment is lexical now, and "content/CON.txt" and "content/../CON.txt" are both contained on both
        // platforms, which is what fixes the second, narrower divergence. The guard is KEPT as a cheap short-circuit;
        // the degenerate names it used to be relied on for ("." — malformed, but not an attack) are now excluded by
        // the resolved-depth test below, which also covers the "content/.." that this pre-test never caught.
        if (!Segments(name).Contains(".."))
            return null;

        // "content/.." resolves to the content root ITSELF. EscapesContentRoot says true — correctly, for its own
        // purpose: such a name points at no file under the root, so it can never be inventoried. But it escapes
        // nothing, and this category is defined as "the entry's target escapes the content root" (ADR 0031
        // decision 2), so reporting it as zip slip is a false positive on a category chosen for precision. Carved
        // out here rather than inside the shared predicate, which containment still needs to reject.
        if (NuGetPackage.ResolvedDepth(name) == 0)
            return null;

        return NuGetPackage.EscapesContentRoot(name)
            ? "entry target escapes the package content root (zip slip)"
            : null;
    }

    // "collides case-insensitively with: a, b" the first time a member of a colliding group is seen, else null.
    //
    // At most MaxReportedPartners names are listed and the rest collapse to ", and N more", for the same reason
    // CodePointDetail caps its code points: the group size is attacker-chosen (a package may declare a thousand case
    // variants of one name), every partner is an attacker-chosen string, and this detail lands in one log line, one
    // JSON field and one table cell. Detail strings stay bounded.
    private static string? CollisionDetail(
        string name, IReadOnlyDictionary<string, IReadOnlyList<string>> collisions, HashSet<string> reported)
    {
        if (!collisions.TryGetValue(name, out var group) || !reported.Add(name))
            return null;

        var partners = group.Where(n => !string.Equals(n, name, StringComparison.Ordinal)).ToArray();
        var shown = string.Join(", ", partners.Take(MaxReportedPartners).Select(YaraPathSafety.Escape));
        return partners.Length > MaxReportedPartners
            ? $"collides case-insensitively with: {shown}, and {partners.Length - MaxReportedPartners} more"
            : $"collides case-insensitively with: {shown}";
    }

    // Groups of two or more DISTINCT names equal under OrdinalIgnoreCase, keyed by every member so a lookup by name
    // is O(1). Exact (ordinal) duplicates are deliberately NOT a collision — that is a different defect, out of scope.
    private static IReadOnlyDictionary<string, IReadOnlyList<string>> CollisionGroups(IReadOnlyList<string> names)
    {
        var groups = names
            .Distinct(StringComparer.Ordinal)
            .GroupBy(n => n, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => (IReadOnlyList<string>)g.ToArray())
            .ToArray();

        return groups
            .SelectMany(g => g.Select(n => (Name: n, Group: g)))
            .ToDictionary(x => x.Name, x => x.Group, StringComparer.Ordinal);
    }

    // The first path segment ending in a space or a '.', or null when there is none. The '.' and '..' segments are
    // navigation, not names, and are excluded — flagging them would make every "content/./a.bin" an anomaly and
    // duplicate what PathTraversal already reasons about.
    private static string? TrailingSpaceOrDotDetail(string name) =>
        Segments(name)
            .Where(s => s.Length > 0 && s is not ("." or "..") && (s[^1] is ' ' or '.'))
            .Select(s => $"path segment '{YaraPathSafety.Escape(s)}' ends with a space or '.'")
            .FirstOrDefault();

    // The first path segment whose stem (the text before its first '.') is a reserved Windows device name, or null.
    private static string? ReservedDeviceNameDetail(string name) =>
        Segments(name)
            .Where(s => reservedDeviceNames.Contains(Stem(s)))
            .Select(s => $"path segment '{YaraPathSafety.Escape(s)}' is the reserved Windows device name {Stem(s).ToUpperInvariant()}")
            .FirstOrDefault();

    // Entry names may use '/' or '\' separators (see NuGetPackage.Segments — some packing tools and most malformed
    // packages emit backslashes, and ZipArchive preserves them verbatim), so both are separators here too.
    private static string[] Segments(string name) => name.Split('/', '\\');

    private static string Stem(string segment)
    {
        var dot = segment.IndexOf('.');
        return dot < 0 ? segment : segment[..dot];
    }

    // "C:..." / "c:..." — an absolute or drive-relative Windows path, whatever platform we happen to be analyzing on.
    private static bool IsDriveQualified(string name) =>
        name.Length >= 2 && char.IsAsciiLetter(name[0]) && name[1] == ':';

    // C0 plus DEL (ADR 0031 decision 2). Deliberately the same range YaraPathSafety.IsUnsafeName treats as parser-
    // hostile, widened by DEL: the ADR 0029 attack and this category describe the same characters.
    private static bool IsControlPoint(int cp) => cp <= 0x1F || cp == 0x7F;

    // The bidi embeddings/overrides and isolates — "Trojan Source" display reordering.
    private static bool IsBidiPoint(int cp) => cp is (>= 0x202A and <= 0x202E) or (>= 0x2066 and <= 0x2069);

    // Zero-width characters, the soft hyphen, and the astral Unicode Tag block (a full ASCII alphabet that renders
    // as nothing at all).
    private static bool IsInvisiblePoint(int cp) =>
        cp is (>= 0x200B and <= 0x200D) or 0xFEFF or 0x00AD or (>= 0xE0000 and <= 0xE007F);
    #endregion

    #region Fields
    // At most this many distinct code points are named per category per entry; the rest collapse to ", ...". Detail
    // strings are read by a human and built from attacker-chosen input, so their length stays bounded.
    private const int MaxReportedCodePoints = 4;

    // At most this many colliding partner names are listed per group; the rest collapse to ", and N more".
    private const int MaxReportedPartners = 4;

    private static readonly HashSet<string> reservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };
    #endregion
}
