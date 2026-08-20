namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

/// <summary>
/// Classifies an assembly's IL string constants into network / sensitive-target indicators — URLs, hosts, bare
/// IP literals, autorun registry paths, credential file paths, and reflection-mediated type names — the
/// <em>target</em> half of RL's "collect and exfiltrate to &lt;named target&gt;" taxonomy (ObfuscationAnalysis
/// covers the "collect", by finding hidden/encoded payloads; this covers the "to").
/// <para>
/// Reads via <see cref="AssemblyAnalyzer.StringConstants"/> — the shared <c>ldstr</c>-extraction seam factored
/// out of <see cref="ObfuscationAnalysis"/> for exactly this purpose (see that method's docs) — rather than
/// walking <see cref="Microsoft.Cci.IMethodBody.Operations"/> itself, so the per-method guard semantics live in
/// one place. Never throws: per-constant failures are skipped, not fatal (ADR 0005 threat model).
/// </para>
/// <para>
/// <b>Differs from <see cref="ObfuscationAnalysis"/> in three deliberate ways</b> (each a lesson already paid
/// for — see the task spec): matching is <em>substring-anywhere</em>, not whole-constant anchored, because a
/// URL is usually embedded in a larger format string; there is <em>no minimum-length floor</em> (a bare IPv4
/// literal is 7 characters, well under <see cref="ObfuscationAnalysis.MinEncodedLength"/>); and this class never
/// base64/hex-decodes anything — that stays <see cref="ObfuscationAnalysis"/>'s job, so the two do not drift
/// into doing each other's work.
/// </para>
/// </summary>
/// <param name="maxDistinctIndicators">
/// Overrides <see cref="MaxDistinctIndicators"/> for this instance; <c>null</c> (the default) uses the documented
/// 10,000 cap unchanged. Exists solely so the bounded-resource limit is <em>injectable</em>: without it, the only
/// way to exercise <see cref="IndicatorReport.Truncated"/> is a fixture with more than 10,000 distinct string
/// constants, which is a permanent, generated-file cost for a branch that should be a dozen-constant unit test.
/// <see cref="MaxDistinctIndicators"/> itself stays a get-only public constant — the documented default — this
/// parameter is the seam, not a setter on that property. Out-of-range values are clamped, never thrown
/// (<see cref="ClampMaxDistinctIndicators"/>): non-positive becomes 1 (a cap of zero would make every indicator
/// truncated, which is not a meaningful bound), and a value above the documented default is clamped back down to
/// it — this parameter can only tighten the resource limit for testing, not loosen it beyond what the class
/// otherwise guarantees.
/// </param>
public sealed class IndicatorAnalysis(AssemblyAnalyzer assembly, int? maxDistinctIndicators = null)
{
    #region Properties
    /// <summary>
    /// Cap on distinct (Category, Value, CallerType, CallerMethod) indicators retained per assembly. String
    /// constants are attacker-authored and can be megabytes or arrive in the tens of thousands; once the cap is
    /// reached, further <em>new</em> distinct indicators are dropped (already-tracked ones keep accumulating
    /// <see cref="IndicatorFinding.Occurrences"/>) and <see cref="IndicatorReport.Truncated"/> is set.
    /// </summary>
    public static int MaxDistinctIndicators { get; } = 10_000;

    /// <summary>Hard cap on <see cref="IndicatorFinding.Excerpt"/> length — a constant can be megabytes;
    /// the excerpt is supporting context only, never the full text.</summary>
    public static int MaxExcerptLength { get; } = 200;
    #endregion

    #region Methods
    /// <summary>
    /// Classifies every <c>ldstr</c> constant reachable from <paramref name="assembly"/> and produces a
    /// serializable, bounded <see cref="IndicatorReport"/>. Findings are aggregated (constraint 5) one per
    /// (Category, Value, CallerType, CallerMethod) with an <see cref="IndicatorFinding.Occurrences"/> count, and
    /// ordered deterministically by (Category, Value, CallerType, CallerMethod) with
    /// <see cref="StringComparer.Ordinal"/> for the string components — the same ordering discipline
    /// <see cref="ObfuscationAnalysis"/> and <c>ScriptRuleScanner.Aggregate</c> already use. Never throws.
    /// </summary>
    public Result<IndicatorReport> Analyze()
    {
        try
        {
            // Bounded, INCREMENTAL aggregation (constraint 4): counts is a Dictionary capped at
            // MaxDistinctIndicators entries, so memory stays bounded even against an assembly with far more
            // distinct indicators than that (a hostile 100,000-distinct-URL assembly completes and sets
            // Truncated rather than growing without limit). Classify's own per-constant bound protects the
            // complementary case: a single multi-megabyte constant packed with repeated indicator-looking
            // substrings cannot blow up memory before this cap even applies. An already-tracked key keeps
            // accumulating Occurrences after the cap is reached; only genuinely new distinct keys are refused.
            var counts = new Dictionary<(IndicatorCategory Category, string Value, string CallerType, string CallerMethod), (string Excerpt, int Occurrences)>();
            var truncated = false;

            // assembly.StringConstants() streams from assembly.Methods (lazy) and already isolates one
            // unreadable method body to that method's constants under its own guard (see
            // AssemblyAnalyzer.StringConstants) — an unreadable body costs one method, never the assembly. Only
            // a genuinely assembly-wide failure (advancing CCI's lazy type resolution during enumeration) reaches
            // this catch.
            foreach (var constant in assembly.StringConstants())
            {
                foreach (var raw in Classify(constant.Text, constant.CallerType, constant.CallerMethod))
                {
                    var key = (raw.Category, raw.Value, raw.CallerType, raw.CallerMethod);
                    if (counts.TryGetValue(key, out var existing))
                        counts[key] = (existing.Excerpt, existing.Occurrences + 1);
                    else if (counts.Count < effectiveMaxDistinctIndicators)
                        counts[key] = (raw.Excerpt, 1);
                    else
                        truncated = true;
                }
            }

            if (truncated)
                Runtime.Warn("Indicator analysis of {0} truncated: distinct-indicator cap ({1}) reached.",
                    assembly.AssemblyName, effectiveMaxDistinctIndicators);

            var findings = counts
                .Select(kv => new IndicatorFinding(kv.Key.Category, kv.Key.Value, kv.Value.Excerpt, kv.Key.CallerType, kv.Key.CallerMethod, kv.Value.Occurrences))
                .OrderBy(f => f.Category)
                .ThenBy(f => f.Value, StringComparer.Ordinal)
                .ThenBy(f => f.CallerType, StringComparer.Ordinal)
                .ThenBy(f => f.CallerMethod, StringComparer.Ordinal)
                .ToArray();

            var report = new IndicatorReport(assembly.AssemblyName, assembly.AssemblyPath, DateTimeOffset.UtcNow, findings, truncated);
            return Result.Success(report);
        }
        catch (Exception ex)
        {
            return Result.FailureWithError<IndicatorReport>($"Failed to analyze {assembly.AssemblyName}.", ex);
        }
    }

    // Classifies a single string constant against every category. Materializes into a List (rather than
    // yield-returning) because a try/catch with a catch clause cannot wrap a yield return — the per-constant
    // failure guard below requires eager evaluation here, so each match loop below self-limits at
    // MaxIndicatorsPerConstant: Regex.Matches enumerates lazily (confirmed against a 160MB adversarial constant:
    // breaking after 10 of ~20,000,000 possible matches took 11ms), so breaking early genuinely avoids asking the
    // regex engine for more matches, not just avoids storing them.
    private static IReadOnlyList<RawIndicator> Classify(string text, string callerType, string callerMethod)
    {
        try
        {
            if (string.IsNullOrEmpty(text))
                return [];

            var excerpt = Excerpt(text);
            var found = new List<RawIndicator>();
            var claimedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Named domain/path categories (CallbackDomain, ExfilSink, DynamicDns, RawCodeHost): substring
            // matched ANYWHERE in the constant (constraint 1), independent of any URL scheme, so a bare domain
            // reference is caught the same as one wrapped in a URL. Each pattern's match IS the normalised host
            // (constraint 6) — see DomainHostRegex/PathPrefixRegex.
            foreach (var (category, pattern) in domainPatterns)
            {
                foreach (Match m in pattern.Matches(text))
                {
                    if (found.Count >= MaxIndicatorsPerConstant) break;
                    var host = HostValue(m.Value);
                    claimedHosts.Add(host);
                    found.Add(new RawIndicator(category, host, excerpt, callerType, callerMethod));
                }
            }

            // IPv4 / IPv6 literals, bare or inside a URL, with or without a trailing port — no minimum length
            // floor (constraint 2). IPAddress.TryParse/ToString is used only to VALIDATE and canonicalise the
            // literal the regex already located (e.g. so "2001:0DB8::1" and "2001:db8::1" aggregate together);
            // this is not the base64/hex "decoding" constraint 7 forbids.
            foreach (Match m in ipv4Regex.Matches(text))
            {
                if (found.Count >= MaxIndicatorsPerConstant) break;
                if (IsVersionAssignment(text, m.Index)) continue;
                if (!IPAddress.TryParse(m.Value, out var ip)) continue;
                var value = ip.ToString();
                claimedHosts.Add(value);
                found.Add(new RawIndicator(IsPrivate(ip) ? IndicatorCategory.PrivateIpLiteral : IndicatorCategory.PublicIpLiteral, value, excerpt, callerType, callerMethod));
            }
            foreach (Match m in ipv6Regex.Matches(text))
            {
                if (found.Count >= MaxIndicatorsPerConstant) break;
                if (!IPAddress.TryParse(m.Value, out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6) continue;
                var value = ip.ToString();
                claimedHosts.Add(value);
                found.Add(new RawIndicator(IsPrivate(ip) ? IndicatorCategory.PrivateIpLiteral : IndicatorCategory.PublicIpLiteral, value, excerpt, callerType, callerMethod));
            }

            // Generic URL fallback: any http(s)/ftp URL whose host was not already claimed by a category above.
            // Uri.TryCreate does the credential/port/path/query stripping for free (constraint 6) — Uri.Host
            // never includes userinfo, port, path, or query.
            foreach (Match m in urlRegex.Matches(text))
            {
                if (found.Count >= MaxIndicatorsPerConstant) break;
                if (!Uri.TryCreate(m.Value, UriKind.Absolute, out var uri)) continue;
                var host = uri.Host.ToLowerInvariant();
                if (host.Length == 0 || !claimedHosts.Add(host)) continue;
                found.Add(new RawIndicator(IndicatorCategory.GenericUrl, host, excerpt, callerType, callerMethod));
            }

            // Autorun registry paths and well-known credential file paths. Lowercased on the way in: Windows
            // paths and registry keys are case-insensitive, so two constants differing only by case must
            // aggregate into one finding, the same reasoning constraint 6 applies to hosts.
            foreach (Match m in autorunRegistryRegex.Matches(text))
            {
                if (found.Count >= MaxIndicatorsPerConstant) break;
                found.Add(new RawIndicator(IndicatorCategory.AutorunRegistry, m.Value.ToLowerInvariant(), excerpt, callerType, callerMethod));
            }
            foreach (Match m in credentialPathRegex.Matches(text))
            {
                if (found.Count >= MaxIndicatorsPerConstant) break;
                found.Add(new RawIndicator(IndicatorCategory.CredentialPath, m.Value.ToLowerInvariant(), excerpt, callerType, callerMethod));
            }

            // Reflection-mediated type names (Type.GetType("...")): the assembly-qualified form is unambiguous
            // and takes precedence; the looser namespace-qualified heuristic only runs when no assembly-qualified
            // name was found in this constant, so one AQN string does not also produce a second, redundant
            // finding for its own type-name prefix. Case is preserved throughout — CLR type names are
            // case-sensitive, unlike a DNS host.
            var hasAssemblyQualifiedName = false;
            foreach (Match m in assemblyQualifiedTypeNameRegex.Matches(text))
            {
                if (found.Count >= MaxIndicatorsPerConstant) break;
                hasAssemblyQualifiedName = true;
                found.Add(new RawIndicator(IndicatorCategory.ReflectionTypeName, m.Value.Trim(), excerpt, callerType, callerMethod));
            }
            if (!hasAssemblyQualifiedName)
            {
                foreach (Match m in namespaceQualifiedTypeNameRegex.Matches(text))
                {
                    if (found.Count >= MaxIndicatorsPerConstant) break;
                    found.Add(new RawIndicator(IndicatorCategory.ReflectionTypeName, m.Value.Trim(), excerpt, callerType, callerMethod));
                }
            }

            return found;
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping indicator constant in {0}.{1}: {2}", callerType, callerMethod, ex.Message);
            return [];
        }
    }

    // Resolves the constructor's optional maxDistinctIndicators override to the cap this instance actually
    // enforces. Never throws (class-wide contract): null keeps the documented MaxDistinctIndicators default;
    // non-positive is clamped up to 1 rather than accepted (a cap of zero or below is not a meaningful bound —
    // every indicator would truncate immediately); a value above the documented default is clamped back down to
    // it, so the parameter can only tighten this bounded-resource limit for testing, never loosen it further than
    // the class otherwise guarantees.
    private static int ClampMaxDistinctIndicators(int? requested) => requested switch
    {
        null => MaxDistinctIndicators,
        <= 0 => 1,
        int v when v > MaxDistinctIndicators => MaxDistinctIndicators,
        _ => requested.Value,
    };

    // Bounded excerpt of the containing constant (constraint 4) — supporting context only, never the full text.
    private static string Excerpt(string text) =>
        text.Length <= MaxExcerptLength ? text : string.Concat(text.AsSpan(0, MaxExcerptLength), "…");

    // Normalises a domainPatterns match to its host: for a plain host match (DomainHostRegex) this is the match
    // itself; for a host+path-prefix match (PathPrefixRegex, e.g. "hooks.slack.com/services") this takes
    // everything before the first '/'. Lowercased per constraint 6.
    private static string HostValue(string matched) => matched.Split('/')[0].ToLowerInvariant();

    // True when the ipv4Regex match starting at matchIndex is the version part of an assembly-qualified type
    // name ("Version=4.0.0.0") rather than an address — a known, mechanical .NET metadata artifact (ARCHITECT
    // DECISIONS #2), not an unknown-distribution false positive, so it is excluded at the source rather than
    // left for measure-do-not-tune. Implemented as a manual backward scan over the characters immediately
    // preceding the match, NOT a regex lookbehind: RegexOptions.NonBacktracking (required on every pattern in
    // this file) does not support lookaround at all, so this check cannot live in the regex itself. Walks past
    // an optional '=' with surrounding whitespace, then the word immediately before it, and accepts only an
    // EXACT (case-insensitive) match against one of the four known version-assignment tokens — not merely a
    // suffix match — so "MyVersion=4.0.0.0" is a word-boundary miss, not a false exclusion.
    private static bool IsVersionAssignment(string text, int matchIndex)
    {
        var i = matchIndex - 1;
        while (i >= 0 && char.IsWhiteSpace(text[i])) i--;
        if (i < 0 || text[i] != '=') return false;
        i--;
        while (i >= 0 && char.IsWhiteSpace(text[i])) i--;

        var tokenEnd = i + 1;
        while (i >= 0 && char.IsLetter(text[i])) i--;
        var tokenStart = i + 1;
        if (tokenStart == tokenEnd) return false;

        // Word boundary: the character immediately before the candidate token (if any) must not itself be a
        // word character, otherwise "MyVersion" would match as a false suffix of "Version".
        if (i >= 0 && (char.IsLetterOrDigit(text[i]) || text[i] == '_')) return false;

        var token = text.AsSpan(tokenStart, tokenEnd - tokenStart);
        foreach (var candidate in versionAssignmentTokens)
        {
            if (token.Equals(candidate, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    // RFC1918 (10/8, 172.16/12, 192.168/16) + loopback + link-local for IPv4; unique-local (fc00::/7) + loopback
    // + link-local for IPv6 — exactly the three classes the PrivateIpLiteral category names, nothing broader
    // (e.g. CGNAT 100.64.0.0/10 is deliberately excluded — the spec calls out RFC1918/loopback/link-local only).
    private static bool IsPrivate(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip))
            return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254);
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal)
                return true;
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC;
        }

        return false;
    }

    // Builds a substring-anywhere, RegexOptions.NonBacktracking pattern (constraint 3 — see the class doc's
    // rationale) matching any of `domains` together with its full leading subdomain chain, e.g.
    // "x.pipedream.net" for domain "pipedream.net". The match IS the normalised host (constraint 6): a leading
    // credential ("user:pass@") cannot be consumed by the subdomain-label loop ('@' is not a label character),
    // and a trailing port/path/query cannot follow it either (':' and '/' are not label or domain characters),
    // so both are excluded from the match by construction, not by a separate stripping step.
    // RegexOptions.Compiled is deliberately not added: NonBacktracking is its own (symbolic-derivative) engine
    // and does not use the compiled-IL code path Compiled controls.
    private static Regex DomainHostRegex(IEnumerable<string> domains) =>
        new(@"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*(?:" +
            string.Join('|', domains.Select(Regex.Escape)) + @")\b",
            RegexOptions.NonBacktracking | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    // Builds a substring-anywhere, NonBacktracking pattern for host+path-prefix entries (e.g.
    // "hooks.slack.com/services") where the path, not just the host, is what makes the reference
    // exfiltration-shaped — a bare "pastebin.com" or "slack.com" reference is ordinary and must not be flagged.
    // Deliberately has no trailing \b: Telegram's bot API embeds the token immediately after "bot" with no
    // separator ("api.telegram.org/bot<TOKEN>/sendMessage"), so a trailing boundary would miss it.
    private static Regex PathPrefixRegex(IEnumerable<string> hostPaths) =>
        new(@"\b(?:" + string.Join('|', hostPaths.Select(Regex.Escape)) + @")",
            RegexOptions.NonBacktracking | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    #endregion

    #region Fields
    // The distinct-indicator cap this instance actually enforces — resolved once from the constructor's optional
    // maxDistinctIndicators override (see the class doc's <param> and ClampMaxDistinctIndicators). Analyze reads
    // this instead of the static MaxDistinctIndicators property so a test can construct an instance with a small
    // cap without touching the documented public default.
    private readonly int effectiveMaxDistinctIndicators = ClampMaxDistinctIndicators(maxDistinctIndicators);

    // Safety bound on raw indicators derived from a SINGLE constant, independent of the assembly-wide
    // MaxDistinctIndicators cap — see Classify's doc comment for why this is necessary even though
    // Regex.Matches is lazily enumerated.
    private const int MaxIndicatorsPerConstant = 5_000;

    // OOB interaction / request-catcher hosts. Cross-reference:
    // src/Silvergun.PackageAnalysis.NuGet/Resources/SilvergunRules/callback_domains.json (rule SG0001) carries
    // the same list for the NuGet package scanner, as a JSON regex rather than a C# list — the two projects do
    // not reference each other, so update BOTH when this list changes (see the task spec's
    // "domain-list drift hazard"; this list is the source of truth for the concept).
    private static readonly string[] callbackDomains =
    [
        "pipedream.net", "pipedream.com", "ceye.io", "burpcollaborator.net", "interact.sh", "oastify.com",
        "requestbin.net", "requestbin.com", "webhook.site", "dnslog.cn", "canarytokens.com",
        "requestcatcher.com", "beeceptor.com", "hookbin.com",
    ];

    // Paste / anonymous file-drop hosts that are sinks regardless of path. Cross-reference: same
    // callback_domains.json (rule SG0002) as callbackDomains above — update both.
    private static readonly string[] exfilSinkDomains = ["hastebin.com", "transfer.sh", "file.io", "anonfiles.com"];

    // Chat-webhook / paste sinks that are only exfiltration-shaped at a specific path — matched host+path-prefix
    // (PathPrefixRegex), not bare domain, so an ordinary pastebin.com/slack.com/telegram.org reference is not
    // flagged. Same callback_domains.json (rule SG0002) source as exfilSinkDomains.
    private static readonly string[] exfilSinkPaths =
    [
        "pastebin.com/raw", "discord.com/api/webhooks", "discordapp.com/api/webhooks",
        "hooks.slack.com/services", "api.telegram.org/bot",
    ];

    // Dynamic-DNS providers named in the task spec (ngrok, duckdns, no-ip, trycloudflare, localtunnel) and their
    // common domain variants.
    private static readonly string[] dynamicDnsDomains =
    [
        "ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok.dev",
        "duckdns.org",
        "no-ip.org", "no-ip.com", "noip.com",
        "trycloudflare.com",
        "loca.lt", "localtunnel.me",
    ];

    // Raw-content code hosts commonly used to stage a second-stage payload. Gitee's raw route is a path on the
    // general gitee.com host, not a distinct subdomain, so it is handled separately by giteeRawRegex below.
    private static readonly string[] rawCodeHostDomains =
        ["raw.githubusercontent.com", "gist.githubusercontent.com", "gist.github.com"];

    private static readonly Regex callbackDomainRegex = DomainHostRegex(callbackDomains);
    private static readonly Regex exfilSinkDomainRegex = DomainHostRegex(exfilSinkDomains);
    private static readonly Regex exfilSinkPathRegex = PathPrefixRegex(exfilSinkPaths);
    private static readonly Regex dynamicDnsRegex = DomainHostRegex(dynamicDnsDomains);
    private static readonly Regex rawCodeHostRegex = DomainHostRegex(rawCodeHostDomains);

    // gitee.com is only a RawCodeHost reference on its raw-content route ("gitee.com/<owner>/<repo>/raw/...");
    // an ordinary gitee.com URL is not.
    private static readonly Regex giteeRawRegex = new(
        @"\bgitee\.com/[^\s""'<>]*?/raw/",
        RegexOptions.NonBacktracking | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    // Every named domain/path category, matched in this order per constant (order does not affect correctness —
    // the categories' domain lists are disjoint by construction — only the order findings are discovered in).
    private static readonly (IndicatorCategory Category, Regex Pattern)[] domainPatterns =
    [
        (IndicatorCategory.CallbackDomain, callbackDomainRegex),
        (IndicatorCategory.ExfilSink, exfilSinkDomainRegex),
        (IndicatorCategory.ExfilSink, exfilSinkPathRegex),
        (IndicatorCategory.DynamicDns, dynamicDnsRegex),
        (IndicatorCategory.RawCodeHost, rawCodeHostRegex),
        (IndicatorCategory.RawCodeHost, giteeRawRegex),
    ];

    // IPv4: each octet individually bounded to 0-255 by the alternation (rather than \d{1,3} + a post-hoc range
    // check) so the match itself is already a syntactically valid dotted-quad — NonBacktracking rejects the
    // lookaround this pattern would otherwise be tempted to use for a trailing-port exclusion, so the port is
    // instead simply not part of the pattern (":" is not a digit or ".") and is excluded by construction.
    private static readonly Regex ipv4Regex = new(
        @"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b",
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    // Version-assignment tokens whose dotted-quad-shaped value (e.g. "Version=4.0.0.0") is a .NET metadata
    // version, not a routable address — see IsVersionAssignment. Matched as a whole word only, case-insensitive.
    private static readonly string[] versionAssignmentTokens = ["version", "assemblyversion", "fileversion", "productversion"];

    // IPv6: deliberately loose (any run of 2-7 groups of 0-4 hex digits separated by colons, optionally followed
    // by one more group) — full RFC 4291 validity (correct "::" compression, valid group count) is left to the
    // IPAddress.TryParse validation step in Classify, not to the regex, since a fully precise IPv6 grammar needs
    // backreference-like repetition counting that NonBacktracking does not support anyway. False candidates from
    // this loose match are simply rejected by TryParse and produce no finding.
    // No \b anchors (unlike every other pattern here): a compressed address routinely starts or ends with ":"
    // itself ("::1", "2001:db8::"), a non-word character, so \b's word/non-word-transition test can never
    // succeed there and would silently make the commonest IPv6 literal — loopback — unmatchable. The character
    // class already cannot extend into an adjacent non-hex/non-colon character, so it self-bounds without \b;
    // confirmed against "[::1]:8080" (matches "::1", brackets and port excluded) and against non-IPv6 text
    // containing colons ("id:1234:5678:9012") producing no finding once TryParse rejects the candidate.
    private static readonly Regex ipv6Regex = new(
        @"(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}",
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    // Any http(s)/ftp URL, bounded by whitespace or a quoting/angle-bracket character — the generic fallback
    // used only for GenericUrl once every named category and IP-literal check above has had a chance to claim
    // the host (see Classify's claimedHosts set).
    private static readonly Regex urlRegex = new(
        @"\b(?:https?|ftp)://[^\s""'<>]+",
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    // Autorun persistence registry paths: Run/RunOnce under ...CurrentVersion, Winlogon\Shell, and Image File
    // Execution Options (IFEO, matched both spelled out and as the "IFEO" abbreviation).
    private static readonly Regex autorunRegistryRegex = new(
        @"(?:CurrentVersion\\Run(?:Once)?|Winlogon\\Shell|Image File Execution Options|\bIFEO\b)",
        RegexOptions.NonBacktracking | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    // Well-known credential file/store paths: AWS CLI credentials, SSH private keys (id_rsa/dsa/ecdsa/ed25519),
    // a browser's "Login Data" SQLite store (Chrome/Edge/Brave), npm's .npmrc (can carry an auth token), and
    // git's plaintext .git-credentials store.
    private static readonly Regex credentialPathRegex = new(
        @"(?:\.aws[/\\]credentials|\.ssh[/\\]id_(?:rsa|dsa|ecdsa|ed25519)|Login Data|\.npmrc|\.git-credentials)",
        RegexOptions.NonBacktracking | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    // Assembly-qualified CLR type name: "Namespace.Type, AssemblyName, Version=x.x.x.x, Culture=..,
    // PublicKeyToken=..|null" — the form Type.GetType/Activator.CreateInstance need to load a type from another
    // assembly, and unambiguous enough to be high-confidence (backtick-escaped for open generics, e.g. `1).
    private static readonly Regex assemblyQualifiedTypeNameRegex = new(
        @"\b[A-Za-z_][A-Za-z0-9_.]*(?:`\d+)?(?:\[[^\]]*\])?,\s*[A-Za-z0-9_.]+,\s*Version=\d+\.\d+\.\d+\.\d+,\s*Culture=(?:neutral|[a-z]{2}(?:-[A-Za-z]{2})?),\s*PublicKeyToken=(?:null|[0-9a-fA-F]{16})",
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    // Namespace-qualified CLR type name with no assembly qualification, e.g. "System.Net.WebClient" — the form
    // Type.GetType accepts for a same-assembly/mscorlib type. Heuristic, not a grammar: requires >= 2
    // dot-separated PascalCase-looking segments and nothing more, so it WILL also match ordinary capitalised
    // dotted text that is not a type name. Deliberately kept broad rather than tuned against a hand-picked
    // corpus (the task spec's stated hazard for detection rules); benign-rate measurement is the explicit
    // follow-up task before this feeds any gate.
    private static readonly Regex namespaceQualifiedTypeNameRegex = new(
        @"\b(?:[A-Z][A-Za-z0-9]*\.){1,}[A-Z][A-Za-z0-9]*\b",
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);
    #endregion

    #region Child types
    // One unaggregated indicator match from Classify, fully populated (mirrors ObfuscationFinding's shape) so
    // Analyze's aggregation loop only needs to key and count it, not re-derive caller info.
    private readonly record struct RawIndicator(IndicatorCategory Category, string Value, string Excerpt, string CallerType, string CallerMethod);
    #endregion
}
