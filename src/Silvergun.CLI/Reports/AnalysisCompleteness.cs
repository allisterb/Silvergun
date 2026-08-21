namespace Silvergun.CLI.Reports;

using System.Text.Json;

using Spectre.Console;

using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using static Silvergun.CLI.Reports.ReportTheme;

/// <summary>
/// The single "did we fully analyse this?" predicate (ADR 0024). The report footer and the process exit code are
/// two <b>projections of one question</b>: the renderers call <see cref="ForAssembly"/>/<see cref="ForPackage"/>
/// for the Findings / <b>Not verified</b> / Clean headline, and <c>Program</c> calls the same factories for the
/// <c>isIncomplete</c> input to <c>ScanExitCode</c>. Two independent predicates is precisely the bug ADR 0024
/// exists to remove — exit 0 must mean the footer says "Clean".
/// <para>
/// This is a <b>projection</b> of signals the model already carries, not new analysis:
/// <see cref="CapabilityReport.MethodsSkipped"/> (methods that could not be analyzed — the per-method guard in
/// <c>CapabilityAnalysis.ScanMethod</c> counts a skip for <b>any</b> throw, whether from the body read it does
/// first or from the metadata reads that follow it, so no single cause may be named here), a null
/// <see cref="ObfuscationReport"/> (best-effort analysis that failed), a null
/// <see cref="AssemblyMetadataInfo"/> (best-effort metadata read that failed), a non-null
/// <see cref="AssemblyScanResult.SkipReason"/> (an inventoried file that could not be analysed at all),
/// <see cref="DependencyResolutionStatus.Partial"/> (ADR 0018),
/// <see cref="VulnerabilityScanStatus.Unavailable"/>/<see cref="VulnerabilityScanStatus.NotChecked"/>
/// (ADR 0017), and <see cref="YaraScanStatus.Unavailable"/> (ADR 0027 decision 4 — a YARA scan that was
/// requested but could not actually run, e.g. the native <c>libyara</c> backend failing to initialize).
/// Every <see cref="Caveats"/> entry names its specific gap in prose.
/// </para>
/// <para>
/// <see cref="Caveats"/> can embed untrusted package/assembly content (paths), so it is escaped where it is
/// rendered — see <see cref="CompletenessFooter"/>.
/// </para>
/// </summary>
internal readonly record struct CompletenessAssessment(
    bool IsComplete,
    IReadOnlyList<string> Caveats,
    int MethodsTotal = 0,
    int MethodsAnalyzed = 0,
    int MethodsSkipped = 0)
{
    #region Properties
    /// <summary>
    /// The specific gaps, one human-readable string each. <b>Never null</b> — a null argument and a
    /// <c>default(CompletenessAssessment)</c> both read as empty, so <see cref="CompletenessFooter.WriteHeadline"/>
    /// cannot dereference null on either. Same posture as <see cref="PackageCapabilityReport.YaraFindings"/>, except
    /// that the coalescing has to live in the <b>getter</b>: this is a struct, so <c>default</c> runs no constructor
    /// and a property initializer would never see it.
    /// </summary>
    public IReadOnlyList<string> Caveats
    {
        get => _caveats ?? Array.Empty<string>();
        init => _caveats = value;
    }
    #endregion

    #region Methods
    /// <summary>
    /// Completeness of an <c>analyze</c> (single-assembly) report: methods that could not be analyzed, plus the
    /// best-effort side analyses that left <see cref="AssemblyAnalysisReport.Obfuscation"/> or
    /// <see cref="AssemblyAnalysisReport.Metadata"/> null.
    /// </summary>
    internal static CompletenessAssessment ForAssembly(AssemblyAnalysisReport report)
    {
        var caps = report.Capabilities;
        var caveats = new List<string>();

        if (caps.MethodsSkipped > 0)
            caveats.Add(SkippedMethodsCaveat(caps.MethodsSkipped, caps.MethodsTotal, location: null));
        if (report.Obfuscation is null)
            caveats.Add(ObfuscationCaveat);
        // Same class of gap as the obfuscation caveat: an analysis that was ATTEMPTED and failed, leaving the field
        // null (Program.RunAnalyze). Exempting it would let a report whose identity facts (strong-name signature,
        // public key token, entry point) were never read still claim "Clean".
        if (report.Metadata is null)
            caveats.Add(MetadataCaveat);

        return new CompletenessAssessment(
            caveats.Count == 0, caveats, caps.MethodsTotal, caps.MethodsAnalyzed, caps.MethodsSkipped);
    }

    /// <summary>
    /// Completeness of a <c>scan-package</c> report: IL coverage aggregated over the packaged assemblies, a failed
    /// obfuscation analysis or metadata read on any of them, an inventoried file that could not be analysed at all,
    /// an incomplete resolver-lite transitive walk, vulnerability data that was not obtained, and a YARA
    /// malware-signature scan that did not actually run (ADR 0027 decision 4).
    /// <para>
    /// A file with a <see cref="AssemblyScanResult.SkipReason"/> (⇒ no <see cref="CapabilityReport"/>) is a
    /// <b>whole binary that produced no analysis</b> — a larger blind spot than a few methods that could not be
    /// analyzed, and native payloads are a known malware vector — so it is its own caveat and makes the package
    /// incomplete: without it a package of only native DLLs would read "Clean". It is deliberately excluded from the
    /// coverage aggregate and from the obfuscation/metadata caveats, which count only assemblies that actually
    /// produced a report; including it there would double-report the same gap and skew the coverage ratio.
    /// </para>
    /// </summary>
    internal static CompletenessAssessment ForPackage(PackageCapabilityReport report)
    {
        var analyzed = report.Assemblies.Where(a => a.Report is not null).ToList();
        var total = analyzed.Sum(a => a.Report!.MethodsTotal);
        var analyzedMethods = analyzed.Sum(a => a.Report!.MethodsAnalyzed);
        var skipped = analyzed.Sum(a => a.Report!.MethodsSkipped);
        var caveats = new List<string>();

        if (skipped > 0)
            caveats.Add(SkippedMethodsCaveat(
                skipped, total, Locations(analyzed.Where(a => a.Report!.MethodsSkipped > 0))));

        // A skipped file is a whole binary that produced no analysis. The caveat states only that — for native runtime
        // DLLs it is a permanent property, for a managed assembly whose analysis failed it is a real malfunction, and
        // we cannot tell which from here, so we do not guess.
        var notAnalyzed = report.Assemblies.Where(a => a.SkipReason is not null).ToList();
        if (notAnalyzed.Count > 0)
            caveats.Add(NotAnalyzedFilesCaveat(notAnalyzed.Count, report.Assemblies.Count, Locations(notAnalyzed)));

        var obfuscationFailed = analyzed.Count(a => a.Obfuscation is null);
        if (obfuscationFailed > 0)
            caveats.Add($"{ObfuscationCaveat} for {obfuscationFailed} {Plural(obfuscationFailed, "assembly", "assemblies")}");

        // Counted over `analyzed` only, exactly like the obfuscation caveat: for a file with a SkipReason the metadata
        // is null BECAUSE nothing was analysed, and that gap is already reported above — counting it twice would
        // overstate the number of distinct blind spots.
        var metadataFailed = analyzed.Count(a => a.Metadata is null);
        if (metadataFailed > 0)
            caveats.Add($"{MetadataCaveat} for {metadataFailed} {Plural(metadataFailed, "assembly", "assemblies")}");

        if (report.DependencyResolution == DependencyResolutionStatus.Partial)
            caveats.Add(TransitiveCaveat);

        if (VulnerabilityCaveat(report.VulnerabilitiesStatus) is { } vulnCaveat)
            caveats.Add(vulnCaveat);

        if (YaraCaveat(report.YaraScanStatus) is { } yaraCaveat)
            caveats.Add(yaraCaveat);

        return new CompletenessAssessment(caveats.Count == 0, caveats, total, analyzedMethods, skipped);
    }

    /// <summary>The completeness fields as a JSON fragment, added additively to a report's <c>--json</c> output.</summary>
    internal string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    // "3 of 120 method(s) could not be analyzed", optionally naming where they live.
    // States only the fact, never a diagnosis: CapabilityAnalysis.ScanMethod counts a skip for ANY throw in its
    // per-method guard. ScanMethod reads the BODY first, via AssemblyAnalyzer.TryReadBody, BEFORE entering that
    // guard (a bodiless candidate has to drop out before a failed NAME read could turn it into a spurious skip and
    // inflate MethodsTotal); the metadata reads (TypeName, method.Name.Value) follow inside it. A failure of either
    // is counted identically, so a crafted module with an unreadable TYPE NAME and one with an unreadable BODY are
    // indistinguishable at this counter — which is exactly why the text must not name one. On hostile input the
    // metadata failure is the MORE suspicious case (an unreadable body reads as mundane corruption), so naming the
    // mundane cause here would steer a reviewer away from it. The body case reaches this counter at all only
    // because AssemblyAnalyzer.Methods is a candidate set built from metadata alone: the dereference happens per
    // method, inside TryReadBody's own guard, before the consumer's try — so an unreadable body is skipped like any
    // other throw instead of failing the whole assembly. Measured 2026-07-30 on Newtonsoft.Json 13.0.3,
    // lib/net6.0: an out-of-range fat-header CodeSize on one method yields 4087/4086/1 with every other method's
    // findings unchanged, where it previously produced no report at all. The denominator is version- and
    // TFM-specific (13.0.4 gives 4107; netstandard2.0 gives 4064). This caveat is reachable, and it still must not
    // name which of those causes fired.
    private static string SkippedMethodsCaveat(int skipped, int total, string? location) =>
        location is null
            ? $"{skipped} of {total} method(s) could not be analyzed"
            : $"{skipped} of {total} method(s) could not be analyzed in {location}";

    // "1 of 4 file(s) could not be analysed: native/win-x64/foo.dll".
    // States only the fact, never a diagnosis: SkipReason covers both a file nothing could be read out of (a native
    // DLL) and a valid managed assembly whose capability analysis failed (PackageScanner.ScanAssembly) — the more
    // security-relevant case. Naming a cause we have not established here would invite a reviewer to dismiss the
    // second case as benign packaging. The per-assembly tree node prints the verbatim SkipReason.
    private static string NotAnalyzedFilesCaveat(int skipped, int total, string location) =>
        $"{skipped} of {total} file(s) could not be analysed: {location}";

    // Up to three assembly paths (untrusted package content — escaped at render), then "and N more".
    private static string Locations(IEnumerable<AssemblyScanResult> results)
    {
        var paths = results.Select(r => r.Assembly.RelativePath).ToList();
        var shown = string.Join(", ", paths.Take(MaxNamedAssemblies));
        return paths.Count <= MaxNamedAssemblies ? shown : $"{shown} and {paths.Count - MaxNamedAssemblies} more";
    }

    // Unavailable (ADR 0017: an outage is NOT a clean result) and NotChecked are both "not obtained".
    // NotChecked names no cause on purpose: it is the DEFAULT of PackageCapabilityReport.VulnerabilitiesStatus, so
    // legacy JSON written before the field existed deserializes to it — blaming --no-vulns would tell a reviewer an
    // operator opted out when nobody did.
    private static string? VulnerabilityCaveat(VulnerabilityScanStatus status) => status switch
    {
        VulnerabilityScanStatus.Unavailable => "the known-vulnerability check did not complete",
        VulnerabilityScanStatus.NotChecked => "the known-vulnerability check did not run",
        _ => null,
    };

    // Mirrors VulnerabilityCaveat's shape, but names only one status (ADR 0027 decision 4): Unavailable means YARA
    // was REQUESTED and ATTEMPTED but could not actually run (no backend selected, or a selected backend threw
    // during initialization/scanning — the native libyara defect this caveat exists to surface), so an empty
    // YaraFindings list is NOT evidence of a clean package and must not read as "Clean". NotRun (an explicit
    // --no-yara opt-out) is deliberately NOT a caveat here — the caller chose to skip the scan, unlike an outage.
    private static string? YaraCaveat(YaraScanStatus status) => status switch
    {
        YaraScanStatus.Unavailable => "the YARA malware-signature scan did not complete",
        _ => null,
    };

    private static string Plural(int count, string one, string many) => count == 1 ? one : many;
    #endregion

    #region Fields
    private const string ObfuscationCaveat = "the obfuscation analysis did not complete";

    // States only what was not done, never why: AssemblyMetadata.Read is best-effort and leaves the field null on any
    // failure (a malformed/hostile module, an unreadable file), and the identity facts it carries — strong-name
    // signature, public key token, entry point — are things a reviewer would reasonably assume were checked.
    private const string MetadataCaveat = "the assembly metadata could not be read";

    private const string TransitiveCaveat = "transitive dependencies were not fully resolved (coverage incomplete)";

    // Cap on how many assembly paths a coverage caveat names, so one pathological package can't produce a
    // multi-kilobyte footer line.
    private const int MaxNamedAssemblies = 3;

    // Backing field for Caveats; nullable so the getter can normalize both a null argument and default(struct).
    private readonly IReadOnlyList<string>? _caveats = Caveats;

    private static readonly JsonSerializerOptions jsonOptions = new() { WriteIndented = true };
    #endregion
}

/// <summary>
/// The shared footer projection of <see cref="CompletenessAssessment"/> (ADR 0024). Both verb renderers call these
/// so the coverage line and the three-tier headline are literally the same code — a change cannot make one
/// renderer say "Clean" where the other would not.
/// </summary>
internal static class CompletenessFooter
{
    #region Methods
    /// <summary>The IL coverage line: analysed/total methods, with the skipped count called out when non-zero.</summary>
    internal static void WriteCoverage(IAnsiConsole console, CompletenessAssessment assessment) =>
        console.MarkupLine(assessment.MethodsSkipped == 0
            ? $"[grey]Methods analyzed:[/] {assessment.MethodsAnalyzed}/{assessment.MethodsTotal}"
            : $"[grey]Methods analyzed:[/] [yellow]{assessment.MethodsAnalyzed}/{assessment.MethodsTotal} " +
              $"({assessment.MethodsSkipped} not analyzed)[/]");

    /// <summary>
    /// The three-tier assessment headline: <b>Findings present</b> (a gate tripped) / <b>Not verified</b> (no
    /// findings, but the analysis was incomplete) / <b>Clean</b>. Findings win the headline — that verdict is
    /// accurate and actionable — but the caveats are still disclosed on their own line, because incompleteness is
    /// never suppressed, only ever un-gated (<c>--allow-incomplete</c>).
    /// <para><paramref name="cleanDetail"/> is the verb-specific "no ... findings" tail of the Clean line.</para>
    /// </summary>
    internal static void WriteHeadline(
        IAnsiConsole console, bool rich, bool attention, CompletenessAssessment assessment, string cleanDetail)
    {
        // Caveats can embed untrusted package/assembly paths, so every one passes through Esc before reaching markup.
        var caveats = assessment.IsComplete ? null : string.Join("; ", assessment.Caveats.Select(Esc));

        if (attention)
        {
            console.MarkupLine($"[bold red]{Esc(AlertGlyph(rich))} Findings present[/] [grey]{Dash(rich)} review recommended.[/]");
            if (caveats is not null)
                console.MarkupLine($"[yellow]{Esc(AlertGlyph(rich))} Analysis incomplete[/] [grey]{Dash(rich)} {caveats}; there may be more.[/]");
        }
        else if (caveats is not null)
            console.MarkupLine($"[yellow]{Esc(AlertGlyph(rich))} Not verified[/] [grey]{Dash(rich)} no findings, but {caveats}.[/]");
        else
            console.MarkupLine($"[bold green]{Esc(CleanGlyph(rich))} Clean[/] [grey]{Dash(rich)} {cleanDetail}[/]");
    }
    #endregion
}
