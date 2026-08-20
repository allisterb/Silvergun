namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// One capability whose call-site count differs between a matched assembly's baseline and candidate manifest,
/// while the capability itself is present on <b>both</b> sides — a lower-confidence signal than an outright
/// addition/removal (capability-diff-versions task): "3 to 40" is interesting, "3 to 4" probably is not.
/// </summary>
public sealed record CapabilityCountChange(Capability Capability, int BaselineCount, int CandidateCount);

/// <summary>
/// The capability delta for one (<see cref="AssemblyName"/>, <see cref="TargetFramework"/>) pair matched between a
/// baseline and a candidate <see cref="CapabilitySnapshot"/> (capability-diff-versions task, trap 3: this type
/// only ever describes a pair present on <b>both</b> sides — added/removed assemblies and added/dropped target
/// frameworks are <see cref="CapabilityDiffReport.AssembliesAdded"/>/<see cref="CapabilityDiffReport.AssembliesRemoved"/>/
/// <see cref="CapabilityDiffReport.TargetFrameworksAdded"/>/<see cref="CapabilityDiffReport.TargetFrameworksDropped"/>,
/// never folded in here, so a structural change can never be misattributed as a capability change).
/// </summary>
public sealed record AssemblyCapabilityDiff(
    string AssemblyName,
    string? TargetFramework,                   // the TFM both sides agreed on for this pair — null matches null (see Compare)
    IReadOnlyList<Capability> Added,           // present in candidate, absent in baseline — the headline
    IReadOnlyList<Capability> Removed,         // present in baseline, absent in candidate
    IReadOnlyList<CapabilityCountChange> CountChanges)
{
    #region Properties
    /// <summary>Whether this pair has any capability delta at all (added, removed, or a count change).</summary>
    public bool HasChanges => Added.Count > 0 || Removed.Count > 0 || CountChanges.Count > 0;
    #endregion
}

/// <summary>
/// The structural comparison of two <see cref="CapabilitySnapshot"/> arrays, matched by the composite key
/// (<see cref="CapabilitySnapshot.AssemblyName"/>, <see cref="CapabilitySnapshot.TargetFramework"/>) — see
/// <see cref="Compare"/> for why the key must be composite, not name alone.
/// <para>
/// <b>Deliberately pure and total — never refuses.</b> The refusal judgments (an incomplete scan on either side, an
/// unrecognized <see cref="CapabilitySnapshot.SchemaVersion"/>, an empty snapshot array, or a matched-pair set that
/// comes back empty — the vacuous-diff trap) need the CLI's <c>--allow-*</c> flags and exit-code contract to
/// resolve, so they live in the <c>capability-diff</c> verb, not here. This type only ever answers "what differs,
/// given two arrays the caller already decided are safe to compare" — <see cref="MatchedPairCount"/> is reported so
/// the verb can detect the vacuous case, but computing it is not itself a refusal.
/// </para>
/// <para>
/// <b>The baseline is trusted by construction (2026-08-20 code review).</b> This comparison has no way to tell a
/// baseline snapshot that honestly describes an old scan apart from one an attacker hand-edited to already claim a
/// capability the package never had — e.g. a crafted baseline asserting <c>ProcessExecution</c> was already
/// <c>Present</c> makes a genuine addition in the candidate invisible, reported as no change. This is largely
/// inherent to baselining (the same is true of any diff against a stored prior state) and is not, on its own, a
/// reason to abandon the feature. But it is a real trust boundary: whoever can write the baseline file controls
/// what this type can see change. The mitigation is process, not analysis — review baseline changes like code, and
/// regenerate a baseline from a trusted scan rather than hand-editing one — see the <c>capability-diff</c> verb
/// description in <c>Silvergun.CLI/Program.cs</c> for the same statement aimed at users.
/// </para>
/// </summary>
public sealed record CapabilityDiffReport(
    IReadOnlyList<AssemblyCapabilityDiff> AssemblyDiffs,          // only (name, TFM) pairs WITH a change; ordinal-sorted by name, then TFM
    IReadOnlyList<string> AssembliesAdded,                        // AssemblyName present in candidate only; ordinal-sorted
    IReadOnlyList<string> AssembliesRemoved,                      // AssemblyName present in baseline only; ordinal-sorted
    IReadOnlyList<string> TargetFrameworksAdded,                  // "AssemblyName (tfm)" — name on both sides, this TFM only in candidate
    IReadOnlyList<string> TargetFrameworksDropped,                // "AssemblyName (tfm)" — name on both sides, this TFM only in baseline
    int MatchedPairCount)                                         // total (name, TFM) pairs present on BOTH sides — 0 is the vacuous-diff trap
{
    #region Properties
    /// <summary>
    /// Whether ANY (assembly, TFM) pair gained a capability it did not have on the baseline side. The exit-code
    /// seam (<c>Program.CapabilityDiffExitCode</c>) gates <c>--strict</c> on exactly this — never on bare capability
    /// presence — see the comment there for why that distinction matters.
    /// </summary>
    public bool HasAddedCapabilities => AssemblyDiffs.Any(d => d.Added.Count > 0);

    /// <summary>Whether any matched pair has a capability delta (added, removed, or count change).</summary>
    public bool HasAnyCapabilityChange => AssemblyDiffs.Count > 0;

    /// <summary>Whether the set of target frameworks shipped for a shared assembly name changed — never counted as a capability change.</summary>
    public bool HasTargetFrameworkChange => TargetFrameworksAdded.Count > 0 || TargetFrameworksDropped.Count > 0;

    /// <summary>Whether the assembly SET itself changed (trap 3) or a TFM was added/dropped — never counted as a capability change.</summary>
    public bool HasStructuralChange => AssembliesAdded.Count > 0 || AssembliesRemoved.Count > 0 || HasTargetFrameworkChange;

    /// <summary>Whether there is anything at all to report: a capability delta or a structural change.</summary>
    public bool HasAnyChange => HasAnyCapabilityChange || HasStructuralChange;
    #endregion

    #region Methods
    /// <summary>
    /// Compares two snapshot arrays, matching elements by the composite key (<c>AssemblyName</c>,
    /// <c>TargetFramework</c>). All output lists are ordinal-sorted (and, within a pair, in
    /// <see cref="Capability"/> enum-declaration order — same posture <see cref="CapabilityManifest"/> takes) so two
    /// runs over the same inputs are byte-identical.
    /// <para>
    /// <b>WHY THE KEY IS COMPOSITE, NOT NAME ALONE</b> (architect correction, capability-diff-versions task,
    /// 2026-08-20): a multi-targeted package's <c>--snapshot</c> run writes ONE array element per
    /// <c>lib/&lt;tfm&gt;</c> folder, all sharing <c>AssemblyName</c> — verified against
    /// BouncyCastle.Cryptography 2.5.1's own .nupkg (3 elements, 1 name). Matching on name alone collapses those to
    /// whichever element the array happened to enumerate first, silently hiding capability changes in every OTHER
    /// TFM variant — a false negative, not a cosmetic ordering quirk. Worse, if the two snapshot files enumerate
    /// their TFM folders in a different order, a name-only match can compare DIFFERENT frameworks on the two sides
    /// and report the difference as a capability change that never happened. Multi-targeting is the norm on
    /// nuget.org, so this was the common case, not an edge case. Do NOT "simplify" this back to matching by
    /// <c>AssemblyName</c> alone.
    /// </para>
    /// <para>
    /// <c>TargetFramework</c> participates as a plain value comparison, <b>null included</b>: <c>analyze --snapshot</c>
    /// always writes null (a bare assembly carries no TFM), so null-to-null must match like any other value — it is
    /// simply another framework, not a "missing" marker.
    /// </para>
    /// </summary>
    public static CapabilityDiffReport Compare(IReadOnlyList<CapabilitySnapshot> baseline, IReadOnlyList<CapabilitySnapshot> candidate)
    {
        var baselineByKey = ByAssemblyNameAndFramework(baseline);
        var candidateByKey = ByAssemblyNameAndFramework(candidate);

        var baselineNames = baselineByKey.Keys.Select(k => k.AssemblyName).Distinct(StringComparer.Ordinal).ToArray();
        var candidateNames = candidateByKey.Keys.Select(k => k.AssemblyName).Distinct(StringComparer.Ordinal).ToArray();
        var sharedNames = baselineNames.Intersect(candidateNames, StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        var assemblyDiffs = new List<AssemblyCapabilityDiff>();
        var tfmAdded = new List<string>();
        var tfmDropped = new List<string>();
        var matchedPairCount = 0;

        foreach (var name in sharedNames)
        {
            // TFMs are compared with the DEFAULT equality comparer, not StringComparer.Ordinal, because a TFM here
            // is `string?` and must stay null-tolerant end to end — see ByAssemblyNameAndFramework for why.
            var baselineTfms = baselineByKey.Keys.Where(k => k.AssemblyName == name).Select(k => k.TargetFramework).ToArray();
            var candidateTfms = candidateByKey.Keys.Where(k => k.AssemblyName == name).Select(k => k.TargetFramework).ToArray();

            var sharedTfms = baselineTfms.Intersect(candidateTfms)
                .OrderBy(t => t, StringComparer.Ordinal)
                .ToArray();
            matchedPairCount += sharedTfms.Length;

            assemblyDiffs.AddRange(sharedTfms
                .Select(tfm => CompareAssembly(name, tfm, baselineByKey[(name, tfm)], candidateByKey[(name, tfm)]))
                .Where(d => d.HasChanges));

            tfmAdded.AddRange(candidateTfms.Except(baselineTfms)
                .OrderBy(t => t, StringComparer.Ordinal)
                .Select(tfm => FormatTfmEntry(name, tfm)));
            tfmDropped.AddRange(baselineTfms.Except(candidateTfms)
                .OrderBy(t => t, StringComparer.Ordinal)
                .Select(tfm => FormatTfmEntry(name, tfm)));
        }

        var added = candidateNames.Except(baselineNames, StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var removed = baselineNames.Except(candidateNames, StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal).ToArray();

        return new CapabilityDiffReport(assemblyDiffs, added, removed, tfmAdded, tfmDropped, matchedPairCount);
    }

    // Per-capability delta for one (assembly, TFM) pair present on both sides, walked in Capability
    // enum-declaration order (Enum.GetValues, never a literal list — same posture as CapabilityManifest.From).
    private static AssemblyCapabilityDiff CompareAssembly(string assemblyName, string? targetFramework, CapabilitySnapshot baseline, CapabilitySnapshot candidate)
    {
        var baselineEntries = baseline.Manifest.Entries.ToDictionary(e => e.Capability);
        var candidateEntries = candidate.Manifest.Entries.ToDictionary(e => e.Capability);

        var added = new List<Capability>();
        var removed = new List<Capability>();
        var countChanges = new List<CapabilityCountChange>();

        foreach (var capability in Enum.GetValues<Capability>())
        {
            // A manifest predating a Capability value (or otherwise missing an entry) reads as absent/0 — matches
            // CapabilityManifest.From's own "always record every value" contract, defensively for any manifest that
            // somehow doesn't.
            var b = baselineEntries.GetValueOrDefault(capability, new CapabilityManifestEntry(capability, false, 0));
            var c = candidateEntries.GetValueOrDefault(capability, new CapabilityManifestEntry(capability, false, 0));

            if (!b.Present && c.Present)
                added.Add(capability);
            else if (b.Present && !c.Present)
                removed.Add(capability);
            else if (b.Present && c.Present && b.CallSiteCount != c.CallSiteCount)
                countChanges.Add(new CapabilityCountChange(capability, b.CallSiteCount, c.CallSiteCount));
        }

        return new AssemblyCapabilityDiff(assemblyName, targetFramework, added, removed, countChanges);
    }

    // Renders a (name, TFM) entry for the TargetFrameworksAdded/Dropped lists — "unknown" for a null TFM, so a
    // bare-assembly analyze --snapshot still reads sensibly.
    private static string FormatTfmEntry(string assemblyName, string? targetFramework) =>
        $"{assemblyName} ({targetFramework ?? "unknown"})";

    // A null TargetFramework (every bare `analyze --snapshot`, and a `scan-package` assembly sitting directly
    // under lib/ with no TFM subfolder — see PackageModel.cs) is a real value to key on, not an error condition.
    // But Dictionary<TKey, TValue> throws ArgumentNullException on a null key at EVERY entry point — Add, the
    // indexer, TryGetValue, ContainsKey — for any reference-type TKey, unconditionally, regardless of the `TKey?`
    // annotation used here; CS8714/CS8621 exist precisely to flag that this compiles but crashes at runtime, and
    // suppressing them papers over a real bug rather than fixing it.
    //
    // 2026-08-20 CODE-REVIEW CRITICAL — do NOT "fix" the null-key throw by encoding null as an IN-BAND sentinel
    // string (a previous version of this code used the single NUL character, on the reasoning that a NUL can never
    // appear in a real TFM moniker WE generate from a lib/<tfm>/ folder name) and decoding it back later. A
    // snapshot file is UNTRUSTED input read from disk, and in the CI baseline workflow it is
    // attacker-influenceable through a pull request, so that reasoning does not hold: ANY string value the
    // encoding picks can be forged verbatim by a crafted TargetFramework. Encode(null) and Encode(<the sentinel
    // string>) collapsed to the same key, making a hostile snapshot's sentinel-valued TFM indistinguishable from a
    // genuinely null one — and a single file carrying BOTH a null and a sentinel-valued TFM for one assembly name
    // collided on one key (an unhandled ArgumentException on duplicate insert, or a silent collapse). That is the
    // same class of mistake, from the other side, as the null-key throw it was "fixing": encoding a distinguished
    // value IN BAND with the data it must stay distinguishable from.
    //
    // THE KEY IS THEREFORE A ValueTuple, not an encoded string: a null TargetFramework must remain distinct from
    // EVERY possible string value, and no future scheme may represent null AS a string. ValueTuple is a struct, so
    // the key itself is never null (no null-key throw), and its default equality compares each component with
    // EqualityComparer<string>.Default — ordinal, and null-tolerant (GetHashCode/Equals never throw on null, and
    // null is equal only to null, never to any string). No sentinel, no encode/decode pair, no value that can be
    // forged into meaning something else.
    //
    // Groups snapshots by the composite key, collapsing an accidental duplicate (name, TFM) pair to its FIRST
    // occurrence — defensive against a hostile/hand-edited snapshot file, not something a legitimate --snapshot
    // run produces (one element per TFM folder, never two for the same folder).
    private static Dictionary<(string AssemblyName, string? TargetFramework), CapabilitySnapshot> ByAssemblyNameAndFramework(
        IReadOnlyList<CapabilitySnapshot> snapshots) =>
        snapshots
            .GroupBy(s => (s.AssemblyName, s.TargetFramework))
            .ToDictionary(g => g.Key, g => g.First());
    #endregion
}
