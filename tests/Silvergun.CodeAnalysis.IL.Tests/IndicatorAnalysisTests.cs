namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// The ldstr indicator classifier (<c>docs/agent/tasks/ldstr-indicator-classifier.md</c>): every category
/// in <see cref="IndicatorCategory"/>, the eight acceptance criteria, the <c>Version=</c> quad exclusion
/// added per ARCHITECT DECISIONS #2, aggregation/normalisation semantics, and the report's bounds and JSON
/// round-trip. Item C (behavioural equivalence between <see cref="AssemblyAnalyzer.StringConstants"/> and
/// <see cref="ObfuscationAnalysis"/>'s own duplicate walk) lives in
/// <see cref="StringConstantsSharedSeamTests"/>, alongside the guard-semantics coverage, since both need
/// <see cref="UnreadableMethodBodyFixture"/> rather than the plain fixture assembly this class uses.
/// </summary>
public sealed class IndicatorAnalysisTests : IClassFixture<AssemblyAnalyzerFixture>
{
    public IndicatorAnalysisTests(AssemblyAnalyzerFixture fixture) => this.fixture = fixture;

    #region Acceptance criteria
    // AC1 — a callback-domain host embedded in a URL yields one CallbackDomain finding, host normalised
    // (no scheme, no path).
    [Fact]
    public void Analyze_CallbackDomainUrl_YieldsOneCallbackDomainFinding()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetCallbackDomainUrl));

        var finding = Assert.Single(findings);
        Assert.Equal(IndicatorCategory.CallbackDomain, finding.Category);
        Assert.Equal("x.pipedream.net", finding.Value);
    }

    // AC2 — a URL embedded in a larger sentence is found (constraint 1: substring, not whole-constant
    // anchored).
    [Fact]
    public void Analyze_ExfilSinkEmbeddedInSentence_IsFound()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetExfilSinkEmbeddedInSentence));

        var finding = Assert.Single(findings);
        Assert.Equal(IndicatorCategory.ExfilSink, finding.Category);
        Assert.Equal("hooks.slack.com", finding.Value);
    }

    // AC3 — neither a private bare literal nor a public literal-with-port is dropped by a length floor
    // (constraint 2: a bare IPv4 literal is 7 characters, well under ObfuscationAnalysis.MinEncodedLength).
    [Fact]
    public void Analyze_PrivateIpBare_YieldsPrivateIpLiteral()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetPrivateIpBare)));
        Assert.Equal(IndicatorCategory.PrivateIpLiteral, finding.Category);
        Assert.Equal("10.0.0.5", finding.Value);
    }

    [Fact]
    public void Analyze_PublicIpWithPort_YieldsPublicIpLiteralWithPortStripped()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetPublicIpWithPort)));
        Assert.Equal(IndicatorCategory.PublicIpLiteral, finding.Category);
        Assert.Equal("203.0.113.5", finding.Value);
    }

    // AC4 — autorun registry path and credential path.
    [Fact]
    public void Analyze_AutorunRegistryPath_YieldsAutorunRegistryFinding()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetAutorunRegistryPath)));
        Assert.Equal(IndicatorCategory.AutorunRegistry, finding.Category);
    }

    [Fact]
    public void Analyze_CredentialPathAwsCredentials_YieldsCredentialPathFinding()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetCredentialPathAwsCredentials)));
        Assert.Equal(IndicatorCategory.CredentialPath, finding.Category);
        Assert.Equal(".aws/credentials", finding.Value);
    }

    // AC5 — the same host in 5 constants in one method yields ONE finding with Occurrences == 5.
    [Fact]
    public void Analyze_SameHostInFiveConstantsOneMethod_AggregatesToOneFindingWithFiveOccurrences()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetFiveCallbackConstants)));
        Assert.Equal(IndicatorCategory.CallbackDomain, finding.Category);
        Assert.Equal("x.pipedream.net", finding.Value);
        Assert.Equal(5, finding.Occurrences);
    }

    // AC6 is the ObfuscationAnalysis-findings-unchanged guarantee — covered by
    // StringConstantsSharedSeamTests (Clean vs Patched equality) and by the pre-existing
    // ObfuscationAnalysisTests suite staying green with this change in place (no fixture/production edit
    // was needed here to keep it byte-identical, since ObfuscationAnalysis kept its own walk per ARCHITECT
    // DECISIONS #1).

    // AC7 (hostile-input half) is covered by StringConstantsSharedSeamTests; the bulk/Truncated half is
    // covered below (H).

    // AC8 (build/test green) is the overall result of this run, not a single test.
    #endregion

    #region D — per-category bare / URL-embedded / path-qualified forms
    [Fact]
    public void Analyze_CallbackDomainBare_IsFound()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetCallbackDomainBare)));
        Assert.Equal(IndicatorCategory.CallbackDomain, finding.Category);
        Assert.Equal("x.pipedream.net", finding.Value);
    }

    [Fact]
    public void Analyze_DynamicDnsBare_IsFound()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetDynamicDnsBare)));
        Assert.Equal(IndicatorCategory.DynamicDns, finding.Category);
        Assert.Equal("myhost.ngrok.io", finding.Value);
    }

    [Fact]
    public void Analyze_DynamicDnsUrl_IsFoundAndNotAlsoGenericUrl()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetDynamicDnsUrl));
        var finding = Assert.Single(findings);
        Assert.Equal(IndicatorCategory.DynamicDns, finding.Category);
        Assert.Equal("myhost.ngrok.io", finding.Value);
    }

    [Fact]
    public void Analyze_RawCodeHostBare_IsFound()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetRawCodeHostBare)));
        Assert.Equal(IndicatorCategory.RawCodeHost, finding.Category);
        Assert.Equal("raw.githubusercontent.com", finding.Value);
    }

    [Fact]
    public void Analyze_RawCodeHostUrl_IsFound()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetRawCodeHostUrl)));
        Assert.Equal(IndicatorCategory.RawCodeHost, finding.Category);
        Assert.Equal("raw.githubusercontent.com", finding.Value);
    }

    [Theory]
    [InlineData(nameof(IndicatorPayloads.GetExfilSinkPastebinRaw), "pastebin.com")]
    [InlineData(nameof(IndicatorPayloads.GetExfilSinkDiscordWebhook), "discord.com")]
    [InlineData(nameof(IndicatorPayloads.GetExfilSinkSlackWebhook), "hooks.slack.com")]
    [InlineData(nameof(IndicatorPayloads.GetExfilSinkTelegramBot), "api.telegram.org")]
    public void Analyze_ExfilSinkPathQualifiedForms_AreFound(string caller, string expectedHost)
    {
        var finding = Assert.Single(FindingsFor(caller));
        Assert.Equal(IndicatorCategory.ExfilSink, finding.Category);
        Assert.Equal(expectedHost, finding.Value);
    }

    // The gitee.com/.../raw/ vs ordinary gitee.com distinction (D).
    [Fact]
    public void Analyze_GiteeRawUrl_YieldsRawCodeHost()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetGiteeRawUrl)));
        Assert.Equal(IndicatorCategory.RawCodeHost, finding.Category);
        Assert.Equal("gitee.com", finding.Value);
    }

    [Fact]
    public void Analyze_GiteeOrdinaryUrl_DoesNotYieldRawCodeHost()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetGiteeOrdinaryUrl));
        Assert.DoesNotContain(findings, f => f.Category == IndicatorCategory.RawCodeHost);
        // An ordinary URL to an unclaimed-category host still surfaces as GenericUrl.
        Assert.Contains(findings, f => f.Category == IndicatorCategory.GenericUrl && f.Value == "gitee.com");
    }

    [Fact]
    public void Analyze_AutorunRegistryWinlogonShell_IsFound()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetAutorunRegistryWinlogonShell)));
        Assert.Equal(IndicatorCategory.AutorunRegistry, finding.Category);
    }

    [Fact]
    public void Analyze_CredentialPathSshKey_IsFound()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetCredentialPathSshKey)));
        Assert.Equal(IndicatorCategory.CredentialPath, finding.Category);
        Assert.Equal(".ssh/id_rsa", finding.Value);
    }
    #endregion

    #region E — IP literals
    [Theory]
    [InlineData(nameof(IndicatorPayloads.GetPrivateIpLoopback), "127.0.0.1")]
    [InlineData(nameof(IndicatorPayloads.GetPrivateIpLinkLocal), "169.254.1.1")]
    [InlineData(nameof(IndicatorPayloads.GetPrivateIp172Range), "172.16.5.4")]
    [InlineData(nameof(IndicatorPayloads.GetPrivateIp192Range), "192.168.1.10")]
    public void Analyze_PrivateIpv4Ranges_AreClassifiedPrivate(string caller, string expectedValue)
    {
        var finding = Assert.Single(FindingsFor(caller));
        Assert.Equal(IndicatorCategory.PrivateIpLiteral, finding.Category);
        Assert.Equal(expectedValue, finding.Value);
    }

    [Fact]
    public void Analyze_PublicIpv4EmbeddedInSentence_IsClassifiedPublic()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetPublicIpv4EmbeddedInSentence)));
        Assert.Equal(IndicatorCategory.PublicIpLiteral, finding.Category);
        Assert.Equal("8.8.8.8", finding.Value);
    }

    // Pin that "::1" works: no \b anchors on the IPv6 pattern (a compressed literal starts/ends with a
    // colon, so \b structurally cannot match there) — this was a real bug caught during implementation.
    [Fact]
    public void Analyze_Ipv6Loopback_IsClassifiedPrivate()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetIpv6Loopback)));
        Assert.Equal(IndicatorCategory.PrivateIpLiteral, finding.Category);
        Assert.Equal("::1", finding.Value);
    }

    [Fact]
    public void Analyze_Ipv6LinkLocal_IsClassifiedPrivate()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetIpv6LinkLocal)));
        Assert.Equal(IndicatorCategory.PrivateIpLiteral, finding.Category);
    }

    [Fact]
    public void Analyze_Ipv6UniqueLocal_IsClassifiedPrivate()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetIpv6Ula)));
        Assert.Equal(IndicatorCategory.PrivateIpLiteral, finding.Category);
    }

    [Fact]
    public void Analyze_Ipv6Public_IsClassifiedPublic()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetIpv6Public)));
        Assert.Equal(IndicatorCategory.PublicIpLiteral, finding.Category);
    }

    // Port stripping for the IPv6 family — brackets and the trailing port must not survive into Value.
    [Fact]
    public void Analyze_Ipv6WithBracketsAndPort_StripsToBareAddress()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetIpv6WithPortBrackets)));
        Assert.Equal(IndicatorCategory.PrivateIpLiteral, finding.Category);
        Assert.Equal("::1", finding.Value);
    }
    #endregion

    #region F — the Version= quad exclusion
    [Theory]
    [InlineData(nameof(IndicatorPayloads.GetVersionAssignmentPlain))]
    [InlineData(nameof(IndicatorPayloads.GetVersionAssignmentLowerSpaced))]
    [InlineData(nameof(IndicatorPayloads.GetAssemblyVersionAssignment))]
    [InlineData(nameof(IndicatorPayloads.GetFileVersionAssignment))]
    [InlineData(nameof(IndicatorPayloads.GetProductVersionAssignment))]
    public void Analyze_VersionAssignmentQuads_ProduceNoIpFinding(string caller)
    {
        var findings = FindingsFor(caller);
        Assert.DoesNotContain(findings,
            f => f.Category is IndicatorCategory.PublicIpLiteral or IndicatorCategory.PrivateIpLiteral);
    }

    // The AQN's own Version= quad must not leak an IP finding, AND the AQN itself must still produce
    // exactly one ReflectionTypeName finding (the two-birds case ARCHITECT DECISIONS #2 calls out).
    [Fact]
    public void Analyze_FullAssemblyQualifiedName_ProducesExactlyOneReflectionFindingAndNoIpFinding()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetFullAssemblyQualifiedName));

        var finding = Assert.Single(findings);
        Assert.Equal(IndicatorCategory.ReflectionTypeName, finding.Category);
        Assert.Equal(IndicatorPayloads.FullAssemblyQualifiedName, finding.Value);
    }

    [Fact]
    public void Analyze_UrlWithVersionLikeHost_StillProducesPublicIpFinding()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetUrlWithVersionLikeHost)));
        Assert.Equal(IndicatorCategory.PublicIpLiteral, finding.Category);
        Assert.Equal("4.0.0.0", finding.Value);
    }

    // Boundary: "MyVersion=" is a word-boundary MISS against "Version=" (not merely a suffix match) — the
    // exclusion must not fire, so the quad is still a (public) IP literal.
    [Fact]
    public void Analyze_MyVersionFalseSuffix_StillProducesIpFinding()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetMyVersionFalseSuffix));
        Assert.Contains(findings,
            f => f.Value == "4.0.0.0" &&
                 f.Category is IndicatorCategory.PublicIpLiteral or IndicatorCategory.PrivateIpLiteral);
    }

    // Boundary: no '=' after "Version" — not an assignment — must still fire.
    [Fact]
    public void Analyze_VersionWithoutEquals_StillProducesIpFinding()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetVersionWithoutEquals));
        Assert.Contains(findings,
            f => f.Value == "4.0.0.0" &&
                 f.Category is IndicatorCategory.PublicIpLiteral or IndicatorCategory.PrivateIpLiteral);
    }
    #endregion

    #region F2 — OID-slicing and unspecified-address false-positive fixes
    // IsPartOfLongerDottedRun fix: MimeKit's real S/MIME OID "1.3.6.1.4.1.188.7.1.1.2" must produce NO IP
    // finding at all — the original defect sliced it into TWO false IP findings ("1.3.6.1" and
    // "4.1.188.7"), so both must be absent, not just one.
    [Fact]
    public void Analyze_OidSlicedIntoIpLiterals_ProducesNoIpFinding()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetOidSlicedIntoIpLiterals));
        Assert.DoesNotContain(findings,
            f => f.Category is IndicatorCategory.PublicIpLiteral or IndicatorCategory.PrivateIpLiteral);
        Assert.DoesNotContain(findings, f => f.Value == "1.3.6.1");
        Assert.DoesNotContain(findings, f => f.Value == "4.1.188.7");
    }

    // Negative side of the OID fix, which must STILL fire: none of these dotted quads are part of a
    // longer run, so each remains a genuine IP-literal finding.
    [Theory]
    [InlineData(nameof(IndicatorPayloads.GetIpLiteralTrailingSentencePeriod), "8.8.8.8")] // trailing sentence period
    [InlineData(nameof(IndicatorPayloads.GetUrlWithVersionLikeHost), "4.0.0.0")]          // mid-URL slash
    [InlineData(nameof(IndicatorPayloads.GetPublicIpv4EmbeddedInSentence), "8.8.8.8")]    // ordinary sentence
    [InlineData(nameof(IndicatorPayloads.GetPublicIpWithPort), "203.0.113.5")]            // trailing port
    public void Analyze_IpLiteralsNotPartOfLongerRun_StillProduceIpFinding(string caller, string expectedValue)
    {
        var findings = FindingsFor(caller);
        Assert.Contains(findings,
            f => f.Value == expectedValue &&
                 f.Category is IndicatorCategory.PublicIpLiteral or IndicatorCategory.PrivateIpLiteral);
    }

    // Combination case: the OID fragments must be suppressed AND the genuine public IP in the same
    // constant must still be reported. A test that only checks suppression cannot tell "the fix works"
    // from "IP detection broke".
    [Fact]
    public void Analyze_OidAndPublicIpCombined_SuppressesOidButStillReportsRealIp()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetOidAndPublicIpCombined));

        Assert.DoesNotContain(findings, f => f.Value == "1.3.6.1");
        Assert.DoesNotContain(findings, f => f.Value == "4.1.188.7");

        var finding = Assert.Single(findings);
        Assert.Equal(IndicatorCategory.PublicIpLiteral, finding.Category);
        Assert.Equal("8.8.8.8", finding.Value);
    }

    // HasHexGroup fix: a bare "::" carved out of a regex SOURCE-CODE literal carries no hex group and no
    // address information at all — it must now produce NO finding whatsoever (absence, not
    // reclassification into a different category).
    [Fact]
    public void Analyze_BareDoubleColonFromRegexSource_ProducesNoFinding()
    {
        Assert.Empty(FindingsFor(nameof(IndicatorPayloads.GetBareDoubleColonFromRegexSource)));
    }

    // IsPrivate fix: the unspecified addresses (0.0.0.0 / "::") are not routable, so they now classify as
    // PrivateIpLiteral rather than PublicIpLiteral — the category name says "private" but the real
    // distinction the fix encodes is routable vs not. This is a CHANGED expectation.
    [Fact]
    public void Analyze_UnspecifiedIpv4_IsClassifiedPrivateNotPublic()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetUnspecifiedIpv4)));
        Assert.Equal(IndicatorCategory.PrivateIpLiteral, finding.Category);
        Assert.Equal("0.0.0.0", finding.Value);
    }

    // Non-regression: ordinary compressed/unique-local/public IPv6 forms (which DO carry a hex group and
    // ARE routable-or-not for reasons unrelated to this fix) keep their pre-fix classification.
    [Theory]
    [InlineData(nameof(IndicatorPayloads.GetIpv6Loopback), IndicatorCategory.PrivateIpLiteral, "::1")]
    [InlineData(nameof(IndicatorPayloads.GetIpv6UniqueLocalFc00), IndicatorCategory.PrivateIpLiteral, "fc00::1")]
    [InlineData(nameof(IndicatorPayloads.GetIpv6PublicDocumentationExample), IndicatorCategory.PublicIpLiteral, "2001:db8::1")]
    [InlineData(nameof(IndicatorPayloads.GetIpv6WithPortBrackets), IndicatorCategory.PrivateIpLiteral, "::1")]
    public void Analyze_Ipv6NonRegressionForms_KeepPreFixClassification(
        string caller, IndicatorCategory expectedCategory, string expectedValue)
    {
        var finding = Assert.Single(FindingsFor(caller));
        Assert.Equal(expectedCategory, finding.Category);
        Assert.Equal(expectedValue, finding.Value);
    }

    // Non-regression on the earlier Version= quad fix, which this OID fix sits alongside and must not
    // disturb: "Version=4.0.0.0" still yields no IP finding (already asserted by
    // Analyze_VersionAssignmentQuads_ProduceNoIpFinding above), and the "MyVersion=" word-boundary miss
    // still yields a (public) IP finding for the whole token (already asserted by
    // Analyze_MyVersionFalseSuffix_StillProducesIpFinding above). Re-asserted here by name only, not
    // duplicated, to keep this region's own baseline visible without duplicating fixture data.
    [Fact]
    public void Analyze_VersionQuadExclusion_IsUnaffectedByOidFix()
    {
        Assert.DoesNotContain(FindingsFor(nameof(IndicatorPayloads.GetVersionAssignmentPlain)),
            f => f.Category is IndicatorCategory.PublicIpLiteral or IndicatorCategory.PrivateIpLiteral);
        Assert.Contains(FindingsFor(nameof(IndicatorPayloads.GetMyVersionFalseSuffix)),
            f => f.Value == "4.0.0.0" && f.Category == IndicatorCategory.PublicIpLiteral);
    }

    // KNOWN LIMITATIONS — pinned as documented current behaviour, NOT fixed, so nobody later mistakes
    // these for regressions. Both were reported by the implementer alongside the OID/unspecified-address
    // fixes above and deliberately left as-is: there is no positional or contextual signal available to
    // distinguish them from a genuine address without risking false negatives on real IP literals.
    [Fact]
    public void Analyze_BareFourArcOidFragmentWithNoContext_IsStillReadAsIp()
    {
        // A standalone exactly-4-arc OID fragment ("1.3.6.1", nothing before or after it) is
        // syntactically indistinguishable from a real IPv4 literal — IsPartOfLongerDottedRun has nothing
        // to key off when the run does not visibly continue.
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetBareOidFragmentReadAsIp)));
        Assert.Equal(IndicatorCategory.PublicIpLiteral, finding.Category);
        Assert.Equal("1.3.6.1", finding.Value);
    }

    [Fact]
    public void Analyze_UnlabeledVersionQuadWithNoPrefix_IsStillReadAsIp()
    {
        // An unlabeled 4-part version ("Fixed in 1.2.3.4") with no "Version="-shaped prefix and every
        // octet <= 255 is syntactically a valid IPv4 literal — IsVersionAssignment has no token to match
        // against, so this is not excluded.
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetUnlabeledVersionQuadReadAsIp)));
        Assert.Equal(IndicatorCategory.PublicIpLiteral, finding.Category);
        Assert.Equal("1.2.3.4", finding.Value);
    }
    #endregion

    #region F3 — IsAdjacentToWordCharacter (leading/trailing word-adjacency) fix
    // A 148-package corpus measurement found ordinary text misclassified as an IPv6 PublicIpLiteral via
    // two mechanisms: (1) LEADING side — a trailing hex digit of an ordinary word sitting directly
    // against "::" (e.g. XPath's "self::" read as "f::", a Discord emoji shortcode's "hand::" read as
    // "d::"); (2) TRAILING side — the greedy [A-Fa-f0-9]{0,4} group AFTER "::" swallows the first
    // letters of the FOLLOWING word (e.g. Npgsql's "'true'::boolean" read as "::b", which
    // IPAddress.TryParse accepts as "::000b"). The fix (IsAdjacentToWordCharacter) is symmetric: it
    // rejects a match with an ASCII letter or digit immediately before OR immediately after it. All four
    // real-world-shaped constants below must produce NO IP-literal finding — absence, not
    // reclassification into a different category (some may still legitimately surface non-IP findings
    // from other categories; that is not what these tests check).
    [Theory]
    [InlineData(nameof(IndicatorPayloads.GetNpgsqlCastToBoolean))]
    [InlineData(nameof(IndicatorPayloads.GetXPathDescendantOrSelfAxis))]
    [InlineData(nameof(IndicatorPayloads.GetDiscordEmojiShortcode))]
    [InlineData(nameof(IndicatorPayloads.GetSqlCaseWhenWithCastBoolean))]
    public void Analyze_WordAdjacentIpv6Candidates_ProduceNoIpFinding(string caller)
    {
        var findings = FindingsFor(caller);
        Assert.DoesNotContain(findings,
            f => f.Category is IndicatorCategory.PublicIpLiteral or IndicatorCategory.PrivateIpLiteral);
    }

    // Dedicated TRAILING-side case, independent of the three real-world examples above (per
    // IndicatorPayloads.TrailingSideWordAdjacencyDiscriminator's doc comment): "key'::a1b2c3" is
    // constructed so a LEADING-only guard would let it through (the character before the match is an
    // apostrophe, not alphanumeric) and IPAddress.TryParse("::a1b2") would happily accept the resulting
    // fragment as a valid IPv6 literal. Only the trailing half of the symmetric fix — the check on the
    // character immediately after the match ('c' of the following "c3") — rejects it. This is the case
    // that discriminates the shipped symmetric fix from a leading-only one.
    [Fact]
    public void Analyze_TrailingSideWordAdjacencyDiscriminator_ProducesNoIpFinding()
    {
        var findings = FindingsFor(nameof(IndicatorPayloads.GetTrailingSideWordAdjacencyDiscriminator));
        Assert.DoesNotContain(findings,
            f => f.Category is IndicatorCategory.PublicIpLiteral or IndicatorCategory.PrivateIpLiteral);
    }

    // Regression: the fix must not have blunted genuine detection. Covers private/public, compressed and
    // full-length IPv6 forms, including a real-world address (Google Public DNS) not already present in
    // the fixture set.
    [Theory]
    [InlineData(nameof(IndicatorPayloads.GetIpv6Loopback), IndicatorCategory.PrivateIpLiteral, "::1")]
    [InlineData(nameof(IndicatorPayloads.GetIpv6UniqueLocalFc00), IndicatorCategory.PrivateIpLiteral, "fc00::1")]
    [InlineData(nameof(IndicatorPayloads.GetIpv6WithPortBrackets), IndicatorCategory.PrivateIpLiteral, "::1")]
    [InlineData(nameof(IndicatorPayloads.GetIpv6PublicDocumentationExample), IndicatorCategory.PublicIpLiteral, "2001:db8::1")]
    [InlineData(nameof(IndicatorPayloads.GetIpv6GoogleDns), IndicatorCategory.PublicIpLiteral, "2001:4860:4860::8888")]
    public void Analyze_WordAdjacencyFix_DoesNotBluntGenuineIpv6Detection(
        string caller, IndicatorCategory expectedCategory, string expectedValue)
    {
        var finding = Assert.Single(FindingsFor(caller));
        Assert.Equal(expectedCategory, finding.Category);
        Assert.Equal(expectedValue, finding.Value);
    }

    // Regression: the IPv4 path (a wholly separate branch in Classify, unaffected by this fix) is
    // unaffected — a genuine public literal and the unspecified address both keep their classification.
    [Fact]
    public void Analyze_WordAdjacencyFix_Ipv4PathUnaffected()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetPublicIpv4EmbeddedInSentence)));
        Assert.Equal(IndicatorCategory.PublicIpLiteral, finding.Category);
        Assert.Equal("8.8.8.8", finding.Value);
    }

    [Fact]
    public void Analyze_WordAdjacencyFix_UnspecifiedIpv4StillClassifiedPrivate()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetUnspecifiedIpv4)));
        Assert.Equal(IndicatorCategory.PrivateIpLiteral, finding.Category);
        Assert.Equal("0.0.0.0", finding.Value);
    }

    // Boundary: no preceding character at all (start-of-string) is deliberately NOT treated the same as a
    // preceding alphanumeric — already pinned by Analyze_Ipv6Loopback_IsClassifiedPrivate above ("::1" is
    // the entire constant). The cases below cover a preceding non-word character that IS present: space,
    // '=', '"', and '(' — '[' is already covered by Analyze_Ipv6WithBracketsAndPort_StripsToBareAddress.
    [Theory]
    [InlineData(nameof(IndicatorPayloads.GetIpv6PrecededBySpace))]
    [InlineData(nameof(IndicatorPayloads.GetIpv6PrecededByEquals))]
    [InlineData(nameof(IndicatorPayloads.GetIpv6PrecededByQuote))]
    [InlineData(nameof(IndicatorPayloads.GetIpv6PrecededByParen))]
    public void Analyze_Ipv6PrecededByNonWordCharacter_StillFires(string caller)
    {
        var finding = Assert.Single(FindingsFor(caller));
        Assert.Equal(IndicatorCategory.PrivateIpLiteral, finding.Category);
        Assert.Equal("::1", finding.Value);
    }
    #endregion

    #region G — semantics
    // GenericUrl fires only when no other category claimed the host.
    [Fact]
    public void Analyze_UnclaimedUrl_YieldsGenericUrlOnly()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetGenericUrlUnclaimed)));
        Assert.Equal(IndicatorCategory.GenericUrl, finding.Category);
        Assert.Equal("example.com", finding.Value);
    }

    // Every named-category example above already demonstrates the converse: none of them ALSO produced a
    // GenericUrl finding for the same host (each assertion above is Assert.Single).

    // ReflectionTypeName case preservation: two AQNs differing only by the type-name segment's case must
    // remain two DISTINCT findings, unlike a host (which folds to lowercase).
    [Fact]
    public void Analyze_ReflectionTypeNameAqns_PreserveCaseAndDoNotAggregate()
    {
        var upper = FindingsFor(nameof(IndicatorPayloads.GetReflectionAqnCaseUpper));
        var lower = FindingsFor(nameof(IndicatorPayloads.GetReflectionAqnCaseLower));

        var upperFinding = Assert.Single(upper);
        var lowerFinding = Assert.Single(lower);

        Assert.Equal(IndicatorPayloads.ReflectionAqnCaseUpper, upperFinding.Value);
        Assert.Equal(IndicatorPayloads.ReflectionAqnCaseLower, lowerFinding.Value);
        Assert.NotEqual(upperFinding.Value, lowerFinding.Value, StringComparer.Ordinal);
    }

    // The namespace-qualified fallback works on its own when no AQN is present in the constant.
    [Fact]
    public void Analyze_NamespaceQualifiedFallback_IsFoundWhenNoAqnPresent()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetNamespaceQualifiedFallback)));
        Assert.Equal(IndicatorCategory.ReflectionTypeName, finding.Category);
        Assert.Equal("System.Net.WebClient", finding.Value);
    }

    // Occurrences is scoped to (Category, Value, CallerType, CallerMethod): the SAME host in a DIFFERENT
    // caller method must NOT merge.
    [Fact]
    public void Analyze_SameHostInDifferentCallerMethods_DoesNotMerge()
    {
        var report = Analyze();

        var one = report.Findings.Single(f =>
            f.Category == IndicatorCategory.CallbackDomain && f.Value == "x.pipedream.net" &&
            f.CallerMethod == nameof(IndicatorPayloads.GetCallbackHostInMethodOne));
        var two = report.Findings.Single(f =>
            f.Category == IndicatorCategory.CallbackDomain && f.Value == "x.pipedream.net" &&
            f.CallerMethod == nameof(IndicatorPayloads.GetCallbackHostInMethodTwo));

        Assert.Equal(1, one.Occurrences);
        Assert.Equal(1, two.Occurrences);
        Assert.NotEqual(one.CallerMethod, two.CallerMethod);
    }

    // Host aggregation is case-insensitive: the same host differing only by case, in ONE method, merges
    // into ONE finding with Occurrences == 2.
    [Fact]
    public void Analyze_SameHostDifferingOnlyByCase_AggregatesCaseInsensitively()
    {
        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetCaseVariantCallbackHost)));
        Assert.Equal(IndicatorCategory.CallbackDomain, finding.Category);
        Assert.Equal("x.pipedream.net", finding.Value);
        Assert.Equal(2, finding.Occurrences);
    }
    #endregion

    #region H — bounds
    // Excerpt is hard-capped at MaxExcerptLength (200) + the ellipsis marker, even though the containing
    // constant is much longer.
    [Fact]
    public void Analyze_LongConstant_ExcerptIsHardCapped()
    {
        Assert.True(IndicatorPayloads.LongExcerptWithIndicator.Length > IndicatorAnalysis.MaxExcerptLength,
            "Fixture constant must actually exceed the excerpt cap for this test to be meaningful.");

        var finding = Assert.Single(FindingsFor(nameof(IndicatorPayloads.GetLongExcerptWithIndicator)));
        Assert.Equal(IndicatorCategory.CallbackDomain, finding.Category);
        Assert.Equal(IndicatorAnalysis.MaxExcerptLength + 1, finding.Excerpt.Length); // +1 for the ellipsis
        Assert.EndsWith("…", finding.Excerpt, StringComparison.Ordinal);
        Assert.Contains("x.pipedream.net", finding.Excerpt, StringComparison.Ordinal);
    }

    // Sanity: the small, normal fixture assembly never hits the (real, 10,000) distinct-indicator cap.
    [Fact]
    public void Analyze_OnTheOrdinaryFixture_IsNeverTruncated()
    {
        Assert.False(Analyze().Truncated);
    }

    // The cap actually being hit — IndicatorReport.Truncated == true — is covered in
    // IndicatorAnalysisTruncationTests, which injects a small cap through IndicatorAnalysis's
    // maxDistinctIndicators constructor parameter (see ARCHITECT DECISIONS #4 in
    // docs/agent/tasks/ldstr-indicator-classifier.md) over a small, dedicated, hand-written fixture
    // (Silvergun.CodeAnalysis.IL.Tests.IndicatorCapFixture.IndicatorCapPayloads, ~8 constants), rather than
    // ever tripping the real 10,000-constant default. It is deliberately NOT this class: every test here
    // shares one AssemblyAnalyzerFixture and calls Analyze() fresh, so adding a cap-boundary fixture to that
    // shared fixture would have made every other test in this file pay for it too, and — more importantly —
    // the distinct-indicator cap is a GLOBAL, assembly-wide count, so pinning an exact boundary needs an
    // assembly with nothing else in it that could also classify as an indicator and consume cap slots.
    #endregion

    #region I — JSON round-trip
    [Fact]
    public void IndicatorReport_JsonRoundTrip_PreservesFindingsAndUsesEnumNames()
    {
        var report = Analyze();

        var json = report.ToJson();
        var restored = IndicatorReport.FromJson(json);

        Assert.NotNull(restored);
        Assert.Equal(report.AssemblyName, restored!.AssemblyName);
        Assert.Equal(report.AssemblyPath, restored.AssemblyPath);
        Assert.Equal(report.AnalyzedAt, restored.AnalyzedAt);
        Assert.Equal(report.Truncated, restored.Truncated);
        Assert.Equal(report.Findings, restored.Findings);

        // Category serializes by name, not as a bare number.
        Assert.Matches(new Regex("\"Category\"\\s*:\\s*\"[A-Za-z]+\""), json);
        Assert.DoesNotMatch(new Regex("\"Category\"\\s*:\\s*\\d"), json);
    }

    [Fact]
    public void IndicatorReport_FromJson_OnNullInput_ReturnsNull() =>
        Assert.Null(IndicatorReport.FromJson(null!));
    #endregion

    #region Helpers
    private IndicatorFinding[] FindingsFor(string callerMethod) =>
        Analyze().Findings.Where(f => f.CallerMethod == callerMethod).ToArray();

    private IndicatorReport Analyze()
    {
        var result = new IndicatorAnalysis(fixture.Assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }

    private readonly AssemblyAnalyzerFixture fixture;
    #endregion
}
