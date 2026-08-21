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
    /// Analyzes each script's <see cref="PackageScript.FullPath"/> content and returns the collected findings,
    /// aggregated to one finding per (rule, file) carrying an <see cref="ScriptFinding.Occurrences"/> count.
    /// Returns an empty list when the ruleset failed to compile or no script matched. Never throws.
    /// </summary>
    public IReadOnlyList<ScriptFinding> Scan(IEnumerable<PackageScript> scripts)
    {
        var processor = sharedProcessor.Value;
        if (processor is null)
            return Array.Empty<ScriptFinding>();

        return Aggregate(scripts.SelectMany(s => AnalyzeFile(processor, s.FullPath, s.RelativePath)));
    }

    /// <summary>
    /// Analyzes a single arbitrary file on disk with the shared, already-compiled ruleset, aggregated to one finding
    /// per (rule, file) exactly like <see cref="Scan"/> — all three entry points behave identically and differ only in
    /// <see cref="ScriptFinding.Source"/> and redaction. This is the generic arbitrary-file path, so the content is
    /// scanned <b>as-is</b> (no redaction) and findings are <see cref="ScriptFindingSource.Script"/>;
    /// <paramref name="relativePath"/> is the package-relative path recorded on each finding. Never throws.
    /// For the package manifest use <see cref="ScanPackageMetadata"/>, which redacts prose first.
    /// <para>Not called from <c>src/</c> today: it is the unredacted control in the redaction tests and is reserved for
    /// future non-package inputs (a loose script or manifest handed straight to the scanner) — not dead code.</para>
    /// </summary>
    public IReadOnlyList<ScriptFinding> ScanFile(string fullPath, string relativePath)
    {
        var processor = sharedProcessor.Value;
        if (processor is null)
            return Array.Empty<ScriptFinding>();

        return Aggregate(AnalyzeFile(processor, fullPath, relativePath));
    }

    /// <summary>
    /// Analyzes declarative package metadata (the manifest <c>.nuspec</c>, intentionally not part of the script
    /// inventory — ADR 0012) with the prose elements and the <c>&lt;repository commit&gt;</c> SHA redacted first
    /// (see <see cref="RedactProse"/>), so code-oriented backdoor/LOLBAS rules never run over human
    /// changelog/description text or a fixed-format hash (<c>docs/agent/tasks/script-rule-precision.md</c>). The
    /// genuine nuspec signal — URLs (<c>&lt;repository url&gt;</c> included), dependency ids, file targets — lives
    /// outside the redacted spans and stays fully scannable.
    /// Findings are aggregated per (rule, file) and tagged <see cref="ScriptFindingSource.PackageMetadata"/>, which
    /// the CLI reports but excludes from the <c>--strict</c> gate. Never throws; a redaction failure yields no findings.
    /// </summary>
    public IReadOnlyList<ScriptFinding> ScanPackageMetadata(string fullPath, string relativePath)
    {
        var processor = sharedProcessor.Value;
        if (processor is null)
            return Array.Empty<ScriptFinding>();

        return Aggregate(AnalyzeFile(processor, fullPath, relativePath, RedactProse, ScriptFindingSource.PackageMetadata));
    }

    /// <summary>
    /// Returns <paramref name="content"/> with the security-signal-free character content of a nuspec replaced by
    /// spaces: the prose elements (<c>description</c>, <c>releaseNotes</c>, <c>summary</c>, <c>title</c>,
    /// <c>tags</c>, <c>copyright</c>, <c>authors</c>, <c>owners</c>) and the <c>commit</c> attribute value of
    /// <c>&lt;repository&gt;</c> — a fixed-format git hash carrying no security signal, yet long enough to trip
    /// BD000804 ("Long Strings") on most real nuspecs. The sibling <c>url</c> attribute is deliberately left
    /// untouched: that IS the genuine <c>&lt;repository&gt;</c> signal, which the pastebin/IOC/URL rules must see.
    /// <para><b>Invariant:</b> the total length and every <c>\r</c>/<c>\n</c> are preserved (all other redacted
    /// characters become <c>' '</c>), so line/column numbers reported against the redacted text remain valid for the
    /// real file.</para>
    /// <para>Elements are matched on their <b>local</b> name, exactly as NuGet's own <c>NuspecReader</c> reads the
    /// manifest, so a namespace-qualified <c>&lt;nu:description&gt;</c>/<c>&lt;nu:repository commit&gt;</c> — valid in
    /// an installable package — is redacted just like the unqualified form (see <see cref="LocalName"/>).</para>
    /// <para>Comments, CDATA sections and processing instructions <b>outside</b> a redacted prose body are passed
    /// through <b>byte-identically</b>: each is skipped whole, to its own terminator, and its text is never read as
    /// attributes. One sitting <i>inside</i> a prose body is blanked with the body — a prose body is redacted as raw
    /// characters, with no markup exemptions, which is intended.</para>
    /// <para>This is a purely lexical redaction for scanning only — no XML semantics are parsed — implemented as a
    /// <b>single forward pass</b> whose index advances monotonically: no rescans, no backtracking, linear in the input.
    /// It replaced an equivalent pair of regexes because hostile-but-under-cap input (e.g.
    /// <c>"&lt;description&gt;"</c> repeated until 4 MB, never closed) could force a match timeout, and a timeout
    /// <i>skipped the file</i> — letting a package suppress its own metadata scan. Malformed input (unclosed element,
    /// missing <c>&gt;</c>, unterminated quote, EOF mid-tag) simply stops the scan or leaves that element alone;
    /// never throws.</para>
    /// </summary>
    internal static string RedactProse(string content)
    {
        var buffer = content.ToCharArray();
        var unclosed = 0u;                      // bit per prose element: its closing tag is known absent from here on
        var i = 0;
        while (i < content.Length)
        {
            if (content[i] != '<')
            {
                i++;
                continue;
            }

            // Comments, CDATA sections, processing instructions and <!…> declarations are not elements, so they are
            // skipped whole — to their own terminator — before any attribute logic can look at their text. Their bytes
            // are left exactly as they are; only the scan position moves. Reading them as a start tag is what let a
            // single apostrophe in "<!-- Author's notes -->" pass for the opening quote of an attribute value, find no
            // closing quote, and abort the whole pass — leaving every prose element after the comment unredacted.
            if (SkipNonElement(content, i) is { } skipped)
            {
                if (skipped < 0)
                    break;                      // terminator absent (truncated/hostile): keep what has been redacted

                i = skipped;
                continue;
            }

            // Matched on the LOCAL name: a package may qualify its metadata (<nu:description>) and stay valid, so the
            // qualified form must redact identically — otherwise its prose is scanned raw (the BD000600 noise this
            // exists to remove). FindCloseTag likewise ends the body at </description> or </nu:description> alike.
            var nameEnd = NameEnd(content, i + 1);
            var local = LocalName(content.AsSpan(i + 1, nameEnd - i - 1));
            var prose = ProseIndex(local);
            var tagEnd = ScanStartTag(content, buffer, nameEnd, Matches(local, RepositoryElement));
            if (tagEnd < 0)
                break;                          // EOF inside a start tag or an unterminated quote: stop where we are

            // A prose body runs from just after the start tag's '>' to its closing tag; a self-closing tag has none.
            var body = prose >= 0 && content[tagEnd - 1] != '/' ? tagEnd + 1 : -1;
            var close = body < 0 || (unclosed & 1u << prose) != 0 ? -1 : FindCloseTag(content, body, prose);
            if (close < 0)
            {
                // Nothing to blank; an unterminated element stays scannable (recall). Because the scan position only
                // ever advances, a closing tag missing from here on is missing for every later start tag of the same
                // element too — memoizing that is what keeps repeated unclosed prose tags linear instead of O(k*n).
                // The memoized fact is prefix-independent — FindCloseTag accepts ANY prefix, so its failure means no
                // qualified or unqualified closing tag for this element remains — which is what keeps one bit per
                // element sound (and linear) however a document, hostile or not, qualifies its closing tags.
                if (body >= 0)
                    unclosed |= 1u << prose;

                i = tagEnd + 1;
                continue;
            }

            Blank(buffer, body, close);
            i = close;                          // resume at the closing tag — strictly ahead of where this tag began
        }

        return new string(buffer);
    }

    // Classifies the '<' at `start`: for the non-element constructs — comment, CDATA section, processing instruction,
    // or any other <!…> declaration (DOCTYPE) — returns the index just past that construct's own terminator, or -1 when
    // the terminator never occurs (the caller then stops). Returns null when `start` begins an ordinary tag. Quotes are
    // deliberately not honoured: a declaration ends at its terminator, not at a matched quote (see RedactProse).
    private static int? SkipNonElement(string content, int start) =>
        StartsWith(content, start, "<!--") ? TerminatorEnd(content, start + 4, "-->")
        : StartsWith(content, start, "<![CDATA[") ? TerminatorEnd(content, start + 9, "]]>")
        : StartsWith(content, start, "<?") ? TerminatorEnd(content, start + 2, "?>")
        : StartsWith(content, start, "<!") ? TerminatorEnd(content, start + 2, ">")
        : null;

    private static bool StartsWith(string content, int start, string token) =>
        content.AsSpan(start).StartsWith(token, StringComparison.Ordinal);

    // Index just past the first `terminator` at or after `start` (always > start, so the scan stays monotonic), or -1.
    private static int TerminatorEnd(string content, int start, string terminator) =>
        content.IndexOf(terminator, start, StringComparison.Ordinal) is var end && end < 0 ? -1 : end + terminator.Length;

    // Walks a start tag from just past its element name to the '>' that closes it, skipping quoted attribute values so
    // that a '>' inside a value cannot end the tag early. On <repository> only, the value of a `commit` attribute is
    // blanked in place as it is passed. Returns the index of the '>', or -1 on EOF/an unterminated quoted value.
    private static int ScanStartTag(string content, char[] buffer, int start, bool repository)
    {
        var i = start;
        while (i < content.Length)
        {
            var c = content[i];
            if (c == '>')
                return i;

            if (c is '"' or '\'')
            {
                var close = content.IndexOf(c, i + 1);
                if (close < 0)
                    return -1;

                i = close + 1;
            }
            else if (repository && IsNameStart(c))
            {
                var nameEnd = NameEnd(content, i);      // always > i, so the index still advances monotonically
                i = Matches(content.AsSpan(i, nameEnd - i), CommitAttribute)
                    ? BlankAttributeValue(content, buffer, nameEnd)
                    : nameEnd;
                if (i < 0)
                    return -1;
            }
            else
                i++;
        }

        return -1;
    }

    // Blanks the quoted value of `= "..."` / `= '...'` starting at `start` (just past the attribute name) and returns
    // the index past its closing quote. Returns `start` when the attribute has no quoted value (nothing to blank, keep
    // scanning) and -1 when the quote is never closed (the caller then stops).
    private static int BlankAttributeValue(string content, char[] buffer, int start)
    {
        var equals = SkipWhitespace(content, start);
        if (equals >= content.Length || content[equals] != '=')
            return start;

        var quote = SkipWhitespace(content, equals + 1);
        if (quote >= content.Length || content[quote] is not ('"' or '\''))
            return start;

        var close = content.IndexOf(content[quote], quote + 1);
        if (close < 0)
            return -1;

        Blank(buffer, quote + 1, close);
        return close + 1;
    }

    // Replaces buffer[start..end) with spaces, preserving \r/\n so reported line numbers stay valid for the real file.
    private static void Blank(char[] buffer, int start, int end)
    {
        for (var i = start; i < end; i++)
            if (buffer[i] is not ('\r' or '\n'))
                buffer[i] = ' ';
    }

    // Index of the (case-insensitive) prose element name, or -1. A linear walk over eight names beats any allocation.
    private static int ProseIndex(ReadOnlySpan<char> name)
    {
        for (var i = 0; i < proseElements.Length; i++)
            if (Matches(name, proseElements[i]))
                return i;

        return -1;
    }

    private static bool Matches(ReadOnlySpan<char> name, string element) =>
        name.Equals(element, StringComparison.OrdinalIgnoreCase);

    // The local part of an XML name: everything after the last ':'. NuGet's NuspecReader matches metadata elements by
    // local name, so <nu:description xmlns:nu="…/nuspec.xsd"> is a perfectly installable package whose prose must be
    // redacted too. A name with no prefix comes back unchanged; the degenerate "nu:" yields an empty span, which
    // matches no element (that tag is then left alone) — a precision loss at worst, never a missed detection.
    private static ReadOnlySpan<char> LocalName(ReadOnlySpan<char> name) =>
        name.LastIndexOf(':') is var colon && colon >= 0 ? name[(colon + 1)..] : name;

    // Index of the '<' of the next closing tag for prose element `prose` at or after `from`, or -1 when none occurs
    // from there on. Candidates are the occurrences of the element's local name (a fixed needle — no per-tag "</"+name
    // allocation, and independent of how this document qualifies the tag), each accepted only when CloseTagStart finds
    // "</" or "</prefix:" immediately before it. Because failure therefore rules out EVERY qualified form of that
    // element's closing tag, and later start tags can only search a suffix of what was searched here, RedactProse can
    // memoize the failure in one bit per element and still be sound for prefixed and unprefixed documents alike.
    // Cost: one forward pass per call — a rejected candidate advances the search by a character, never rescans.
    private static int FindCloseTag(string content, int from, int prose)
    {
        for (var i = from; (i = content.IndexOf(proseElements[prose], i, StringComparison.OrdinalIgnoreCase)) >= 0; i++)
            if (CloseTagStart(content, i) is var start && start >= 0)
                return start;

        return -1;
    }

    // Given an occurrence of a prose element's local name at `name`, the index of the '<' when that occurrence really
    // begins a closing tag — "</local" or "</prefix:local" — and -1 otherwise (ordinary text such as "mydescription"
    // or "see:description"). What FOLLOWS the local name is deliberately not checked, so the body ends at "</description"
    // however it continues: that is what makes "</description >" (whitespace before '>') work, at the price of letting
    // "</descriptionx" end a <description> body early — harmless, as it can only under-redact. Do not "tighten" it.
    private static int CloseTagStart(string content, int name)
    {
        var slash = name - 1;
        if (slash > 0 && content[slash] == ':')     // qualified closing tag: step back over the namespace prefix
        {
            slash--;
            while (slash > 0 && IsNameChar(content[slash]))
                slash--;
        }

        return slash >= 1 && content[slash] == '/' && content[slash - 1] == '<' ? slash - 1 : -1;
    }

    // End of the XML name starting at `start` (== `start` when there is none, e.g. "</", "<!--", "<?xml").
    private static int NameEnd(string content, int start)
    {
        var i = start;
        while (i < content.Length && IsNameChar(content[i]))
            i++;

        return i;
    }

    private static int SkipWhitespace(string content, int start)
    {
        var i = start;
        while (i < content.Length && char.IsWhiteSpace(content[i]))
            i++;

        return i;
    }

    private static bool IsNameStart(char c) => char.IsLetter(c) || c is '_' or ':';

    private static bool IsNameChar(char c) => char.IsLetterOrDigit(c) || c is '_' or '-' or '.' or ':';

    // Collapses matches to one finding per (RuleId, RelativePath) — RuleId case-insensitive, path ordinal — keeping the
    // first match's line/excerpt/severity/confidence/tags and recording the total match count as Occurrences. A single
    // alternation rule matching a file N times previously produced N findings, inflating the report (and, at the time,
    // the --strict gate — since ADR-0027, Source=Script findings no longer gate) (docs/agent/tasks/script-rule-precision.md).
    // Ordering is deterministic: path, line, then rule id.
    // "First" is taken as the lowest StartLine rather than the engine's emission order, which is not contractually
    // source order within a multi-pattern rule.
    private static IReadOnlyList<ScriptFinding> Aggregate(IEnumerable<ScriptFinding> findings) => findings
        .GroupBy(f => (RuleId: f.RuleId.ToUpperInvariant(), f.RelativePath))
        .Select(g => g.MinBy(f => f.StartLine)! with { Occurrences = g.Count() })
        .OrderBy(f => f.RelativePath, StringComparer.Ordinal)
        .ThenBy(f => f.StartLine)
        .ThenBy(f => f.RuleId, StringComparer.Ordinal)
        .ToArray();

    // Reads and analyzes one file; any failure (missing/oversized/unreadable file, engine error) warns and
    // yields no findings for that file. The content is passed both as text and wrapped in a FileEntry, as the API
    // requires. Unknown file languages (e.g. XML/.nuspec) fall back to a default LanguageInfo so the file is still
    // analyzed by the language-agnostic backdoor patterns. An optional transform (prose redaction for package
    // metadata) rewrites the content before analysis; a transform failure skips the file entirely.
    private static IReadOnlyList<ScriptFinding> AnalyzeFile(
        RuleProcessor processor,
        string fullPath,
        string relativePath,
        Func<string, string>? transform = null,
        ScriptFindingSource source = ScriptFindingSource.Script)
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

            var raw = File.ReadAllText(fullPath);
            if (!TryTransform(transform, raw, relativePath, out var content))
                return Array.Empty<ScriptFinding>();

            var name = Path.GetFileName(fullPath);
            if (!languages.FromFileNameOut(name, out var language))
                language = new LanguageInfo();   // language-agnostic backdoor patterns still apply

            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(content));
            var entry = new FileEntry(name, stream);
            var matches = processor.AnalyzeFile(content, entry, language);
            return matches.Select(m => MapFinding(m, relativePath, source)).ToArray();
        }
        catch (Exception ex)
        {
            Warn("Rule scan failed for {0}: {1}", relativePath, ex.Message);
            return Array.Empty<ScriptFinding>();
        }
    }

    // Applies the optional content transform. A failure skips the file: we deliberately do NOT fall back to scanning
    // the unredacted text, which is the false-positive source. Belt and braces only — RedactProse is a bounded linear
    // scan that never throws, so this path should now be unreachable (it guarded a regex timeout before).
    private static bool TryTransform(Func<string, string>? transform, string raw, string relativePath, out string content)
    {
        try
        {
            content = transform is null ? raw : transform(raw);
            return true;
        }
        catch (Exception ex)
        {
            Warn("Skipping rule scan for {0}: content redaction failed ({1}).", relativePath, ex.Message);
            content = string.Empty;
            return false;
        }
    }

    // Reads MatchRecord fields defensively — the engine populates a subset per match.
    private static ScriptFinding MapFinding(MatchRecord match, string relativePath, ScriptFindingSource source) => new(
        RuleId: match.RuleId ?? match.Rule?.Id ?? string.Empty,
        RuleName: match.RuleName ?? match.Rule?.Name ?? string.Empty,
        Severity: match.Severity.ToString(),
        Confidence: match.Confidence.ToString(),
        RelativePath: relativePath,
        StartLine: match.StartLocationLine,
        Excerpt: NullIfEmpty(match.Excerpt) ?? NullIfEmpty(match.Sample),
        Tags: match.Tags?.ToArray() ?? Array.Empty<string>(),
        Source: source);

    // Compiles the embedded rulesets into a reusable RuleProcessor once. A per-file bad ruleset is skipped with a
    // warning; if nothing loads the scanner degrades to "no findings" (null) rather than throwing.
    private static RuleProcessor? BuildProcessor()
    {
        try
        {
            var rules = new RuleSet();
            var assembly = typeof(ScriptRuleScanner).Assembly;
            var resourceNames = assembly.GetManifestResourceNames()
                .Where(n => RuleResourceMarkers.Any(n.Contains) && n.EndsWith(".json", StringComparison.OrdinalIgnoreCase));

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

    // Substrings identifying the embedded ruleset resources: the OSSGadget MIT rules under
    // Resources/BackdoorRules (ADR 0012) and the Silvergun-owned rules under Resources/SilvergunRules
    // (docs/agent/tasks/silvergun-script-ruleset.md). A resource matching any marker is loaded.
    private static readonly string[] RuleResourceMarkers = [".Resources.BackdoorRules.", ".Resources.SilvergunRules."];

    // The one element and attribute whose value is blanked inside a start tag; the rationale is on RedactProse.
    private const string RepositoryElement = "repository";
    private const string CommitAttribute = "commit";

    private static readonly Languages languages = new();

    // The nuspec elements whose content is free-form human prose: running code-oriented backdoor/LOLBAS rules over them
    // is noise by construction (BD000600's alternation includes bare English words like "at"/"control"/"update"), so
    // their character content is blanked before scanning (see RedactProse). Non-prose elements (projectUrl/licenseUrl/
    // iconUrl/repository url/dependency/files) are untouched — that is where the real nuspec signal lives.
    // These local names are also the needles FindCloseTag scans for, so a body ends at the matching closing tag
    // whatever namespace prefix it carries. At most 32 entries: RedactProse tracks "closing tag absent from here on"
    // per element in a uint bitmask.
    private static readonly string[] proseElements =
        ["description", "releaseNotes", "summary", "title", "tags", "copyright", "authors", "owners"];

    // Compiled once, reused across files and packages (ADR 0012); null when compilation produced no rules.
    private static readonly Lazy<RuleProcessor?> sharedProcessor = new(BuildProcessor);
    #endregion
}
