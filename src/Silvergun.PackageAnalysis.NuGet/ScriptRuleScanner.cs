namespace Silvergun.PackageAnalysis.NuGet;

using System.Reflection;
using System.Text;

using Microsoft.ApplicationInspector.RulesEngine;
using Microsoft.CST.RecursiveExtractor;

/// <summary>
/// Runs the AppInspector <see cref="RuleProcessor">RulesEngine</see> over a package's on-disk script/build files
/// using the embedded OSSGadget MIT backdoor rulesets (ADR 0012), mapping each <see cref="MatchRecord"/> to a
/// serializable <see cref="ScriptFinding"/>. This is the sole point of coupling to the low-level RulesEngine.
///
/// Contract: <b>never throws</b>. All package content is hostile (threat model). The ruleset is compiled once and
/// shared across files and scans; a bad ruleset, an unreadable/oversized script, or an engine failure logs a warning
/// and yields no findings for that unit — the scan always continues and returns a (possibly empty) list.
/// </summary>
public sealed class ScriptRuleScanner : Runtime
{
    #region Methods
    /// <summary>
    /// Analyzes each script's <see cref="PackageScript.FullPath"/> content and returns the collected findings.
    /// Returns an empty list when the ruleset failed to compile or no script matched. Never throws.
    /// </summary>
    public IReadOnlyList<ScriptFinding> Scan(IEnumerable<PackageScript> scripts)
    {
        var processor = sharedProcessor.Value;
        if (processor is null)
            return Array.Empty<ScriptFinding>();

        return scripts.SelectMany(s => AnalyzeFile(processor, s.FullPath, s.RelativePath)).ToArray();
    }

    /// <summary>
    /// Analyzes a single arbitrary file on disk (e.g. the package manifest <c>.nuspec</c>, which is intentionally
    /// not part of the script inventory — ADR 0012) with the shared, already-compiled ruleset. <paramref name="relativePath"/>
    /// is the package-relative path recorded on each resulting <see cref="ScriptFinding.RelativePath"/>. Never throws.
    /// </summary>
    public IReadOnlyList<ScriptFinding> ScanFile(string fullPath, string relativePath)
    {
        var processor = sharedProcessor.Value;
        if (processor is null)
            return Array.Empty<ScriptFinding>();

        return AnalyzeFile(processor, fullPath, relativePath);
    }

    // Reads and analyzes one file; any failure (missing/oversized/unreadable file, engine error) warns and
    // yields no findings for that file. The content is passed both as text and wrapped in a FileEntry, as the API
    // requires. Unknown file languages (e.g. XML/.nuspec) fall back to a default LanguageInfo so the file is still
    // analyzed by the language-agnostic backdoor patterns.
    private static IReadOnlyList<ScriptFinding> AnalyzeFile(RuleProcessor processor, string fullPath, string relativePath)
    {
        try
        {
            if (string.IsNullOrEmpty(fullPath) || !File.Exists(fullPath))
            {
                Warn("Skipping rule scan for {0}: file not found on disk.", relativePath);
                return Array.Empty<ScriptFinding>();
            }

            var length = new FileInfo(fullPath).Length;
            if (length > MaxScriptBytes)
            {
                Warn("Skipping rule scan for {0}: {1} bytes exceeds the {2}-byte cap.",
                    relativePath, length, MaxScriptBytes);
                return Array.Empty<ScriptFinding>();
            }

            var content = File.ReadAllText(fullPath);
            var name = Path.GetFileName(fullPath);
            if (!languages.FromFileNameOut(name, out var language))
                language = new LanguageInfo();   // language-agnostic backdoor patterns still apply

            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(content));
            var entry = new FileEntry(name, stream);
            var matches = processor.AnalyzeFile(content, entry, language);
            return matches.Select(m => MapFinding(m, relativePath)).ToArray();
        }
        catch (Exception ex)
        {
            Warn("Rule scan failed for {0}: {1}", relativePath, ex.Message);
            return Array.Empty<ScriptFinding>();
        }
    }

    // Reads MatchRecord fields defensively — the engine populates a subset per match.
    private static ScriptFinding MapFinding(MatchRecord match, string relativePath) => new(
        RuleId: match.RuleId ?? match.Rule?.Id ?? string.Empty,
        RuleName: match.RuleName ?? match.Rule?.Name ?? string.Empty,
        Severity: match.Severity.ToString(),
        Confidence: match.Confidence.ToString(),
        RelativePath: relativePath,
        StartLine: match.StartLocationLine,
        Excerpt: NullIfEmpty(match.Excerpt) ?? NullIfEmpty(match.Sample),
        Tags: match.Tags?.ToArray() ?? Array.Empty<string>());

    // Compiles the embedded rulesets into a reusable RuleProcessor once. A per-file bad ruleset is skipped with a
    // warning; if nothing loads the scanner degrades to "no findings" (null) rather than throwing.
    private static RuleProcessor? BuildProcessor()
    {
        try
        {
            var rules = new RuleSet();
            var assembly = typeof(ScriptRuleScanner).Assembly;
            var resourceNames = assembly.GetManifestResourceNames()
                .Where(n => n.Contains(RuleResourceMarker) && n.EndsWith(".json", StringComparison.OrdinalIgnoreCase));

            var loaded = 0;
            foreach (var resource in resourceNames)
            {
                try
                {
                    using var stream = assembly.GetManifestResourceStream(resource);
                    if (stream is null) continue;
                    using var reader = new StreamReader(stream);
                    rules.AddString(reader.ReadToEnd(), SourceName(resource));
                    loaded++;
                }
                catch (Exception ex)
                {
                    Warn("Failed to load embedded ruleset {0}: {1}", resource, ex.Message);
                }
            }

            if (loaded == 0)
            {
                Warn("No backdoor rulesets loaded; script content scanning is disabled.");
                return null;
            }

            var options = new RuleProcessorOptions
            {
                Parallel = false,                       // deterministic; we already iterate files sequentially
                AllowAllTagsInBuildFiles = true,        // do not skip .targets/.props content
                ConfidenceFilter = ConfidenceFloor,
                SeverityFilter = SeverityFloor,
            };
            Info("Compiled {0} embedded backdoor ruleset file(s) for script content scanning.", loaded);
            return new RuleProcessor(rules, options);
        }
        catch (Exception ex)
        {
            Warn("Failed to build the script rule processor: {0}", ex.Message);
            return null;
        }
    }

    // "Silvergun.PackageAnalysis.NuGet.Resources.BackdoorRules.lolbas.json" -> "lolbas".
    private static string SourceName(string resourceName)
    {
        var parts = resourceName.Split('.');
        return parts.Length >= 2 ? parts[^2] : resourceName;
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;
    #endregion

    #region Fields
    // Guard against absurdly large hostile scripts; real install/build scripts are tiny.
    private const long MaxScriptBytes = 5L * 1024 * 1024;   // 5 MiB

    // The OSSGadget backdoor rules emit low-confidence matches by design, so all confidences are retained (a
    // Medium+ floor would suppress every finding). Noise is instead bounded by the severity floor: Moderate and
    // above (Critical/Important/Moderate), dropping BestPractice/ManualReview informational tags.
    private const Confidence ConfidenceFloor = Confidence.Low | Confidence.Medium | Confidence.High;
    private const Severity SeverityFloor = Severity.Critical | Severity.Important | Severity.Moderate;

    // Substring identifying the embedded backdoor ruleset resources under Resources/BackdoorRules.
    private const string RuleResourceMarker = ".Resources.BackdoorRules.";

    private static readonly Languages languages = new();

    // Compiled once, reused across files and packages (ADR 0012); null when compilation produced no rules.
    private static readonly Lazy<RuleProcessor?> sharedProcessor = new(BuildProcessor);
    #endregion
}
