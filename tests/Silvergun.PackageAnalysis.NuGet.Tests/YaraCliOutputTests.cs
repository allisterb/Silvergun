namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit tests for <see cref="YaraCliOutput.ParseAll"/> (ADR 0016 / task <c>docs/agent/tasks/yara-scanning.md</c>,
/// Phase 2). The parser turns classic <c>yara</c> CLI stdout — header lines
/// <c>[namespace:]rule [tags] target</c> optionally followed by <c>-s</c> detail lines
/// <c>0xOFFSET:$id: data</c> — into backend-neutral <see cref="YaraMatch"/> POCOs, each paired with the raw
/// <c>Target</c> path echoed on its header line. The parser must be defensive: unrecognized, orphaned, or
/// truncated input yields an empty result rather than throwing.
///
/// The header regex is deliberately permissive (it matches arbitrary prose), so <see cref="YaraCliOutput"/> does
/// NOT decide whether a hit is trustworthy — it retains the echoed target and hands it back for the scanner to
/// anchor against the file it actually scanned. These tests therefore assert both the parse shape AND that the
/// scan target is retained verbatim (the point of the signature change), including the previously-weakened case
/// where prose parses into a rule hit but whose target is plainly not the scanned path.
/// </summary>
public sealed class YaraCliOutputTests
{
    #region Methods
    // A plain header with no namespace prefix and no tags: rule name and no strings, namespace stays null.
    [Fact]
    public void ParseAll_HeaderWithoutNamespaceOrTags_ProducesRuleWithNoNamespace()
    {
        var result = Assert.Single(YaraCliOutput.ParseAll("SilverRule /tmp/sample.dll"));

        Assert.Equal("SilverRule", result.Match.Rule);
        Assert.Null(result.Match.Namespace);
        Assert.Empty(result.Match.Tags);
        Assert.Empty(result.Match.Strings);
        Assert.Equal("/tmp/sample.dll", result.Target);
    }

    // The "namespace:" prefix is stripped into the Namespace field, leaving the bare rule name.
    [Fact]
    public void ParseAll_HeaderWithNamespacePrefix_CapturesNamespace()
    {
        var result = Assert.Single(YaraCliOutput.ParseAll("malware_ns:SilverRule /tmp/sample.dll"));

        Assert.Equal("SilverRule", result.Match.Rule);
        Assert.Equal("malware_ns", result.Match.Namespace);
        Assert.Equal("/tmp/sample.dll", result.Target);
    }

    // A [tags] bracket is comma-split and each tag trimmed of surrounding whitespace.
    [Fact]
    public void ParseAll_HeaderWithTags_SplitsAndTrimsTags()
    {
        var result = Assert.Single(YaraCliOutput.ParseAll("SilverRule [tag_one, tag_two ,tag_three] /tmp/sample.dll"));

        Assert.Equal(new[] { "tag_one", "tag_two", "tag_three" }, result.Match.Tags);
    }

    // A key=value bracket is metadata (from -m), not tags: it must NOT contribute to Tags.
    [Fact]
    public void ParseAll_MetaBracket_IsNotTreatedAsTags()
    {
        var result = Assert.Single(YaraCliOutput.ParseAll("SilverRule [author=silvergun] /tmp/sample.dll"));

        Assert.Empty(result.Match.Tags);
    }

    // Mixed brackets: a real tags bracket is kept while a neighbouring meta (key=value) bracket is dropped.
    [Fact]
    public void ParseAll_TagsBracketAndMetaBracket_KeepsOnlyTags()
    {
        var result = Assert.Single(YaraCliOutput.ParseAll("SilverRule [suspicious] [author=me] /tmp/sample.dll"));

        Assert.Equal(new[] { "suspicious" }, result.Match.Tags);
    }

    // Two header lines produce two independent (match, target) tuples in order, each keeping its own target.
    [Fact]
    public void ParseAll_MultipleRules_ProducesMultipleMatches()
    {
        var output = "RuleA /tmp/a.dll\nRuleB /tmp/b.dll";

        var matches = YaraCliOutput.ParseAll(output);

        Assert.Equal(2, matches.Count);
        Assert.Equal("RuleA", matches[0].Match.Rule);
        Assert.Equal("RuleB", matches[1].Match.Rule);
        Assert.Equal("/tmp/a.dll", matches[0].Target);
        Assert.Equal("/tmp/b.dll", matches[1].Target);
    }

    // A -s detail line "0x<hex>:$id: data" becomes a YaraStringMatch(identifier, offset) with the hex parsed.
    [Fact]
    public void ParseAll_DetailLine_ParsesIdentifierAndHexOffset()
    {
        var output = "SilverRule /tmp/sample.dll\n0x6:$a: CamelForensics";

        var result = Assert.Single(YaraCliOutput.ParseAll(output));
        var str = Assert.Single(result.Match.Strings);
        Assert.Equal("$a", str.Identifier);
        Assert.Equal(6, str.Offset);
    }

    // A multi-digit hex offset is parsed as hexadecimal (0x1a2b == 6699), not decimal.
    [Fact]
    public void ParseAll_DetailLine_ParsesMultiDigitHexOffset()
    {
        var output = "SilverRule /tmp/sample.dll\n0x1a2b:$str1: payload";

        var result = Assert.Single(YaraCliOutput.ParseAll(output));
        var str = Assert.Single(result.Match.Strings);
        Assert.Equal("$str1", str.Identifier);
        Assert.Equal(0x1a2b, str.Offset);
    }

    // Detail lines attach to the header that precedes them, across multiple rules; each keeps its own target.
    [Fact]
    public void ParseAll_DetailLinesAcrossRules_AttachToOwningRule()
    {
        var output =
            "ns1:RuleA [tag1,tag2] /tmp/a.dll\n" +
            "0x6:$a: CamelForensics\n" +
            "RuleB /tmp/b.dll";

        var matches = YaraCliOutput.ParseAll(output);

        Assert.Equal(2, matches.Count);
        Assert.Equal("ns1", matches[0].Match.Namespace);
        Assert.Equal(new[] { "tag1", "tag2" }, matches[0].Match.Tags);
        Assert.Equal("$a", Assert.Single(matches[0].Match.Strings).Identifier);
        Assert.Equal("/tmp/a.dll", matches[0].Target);
        Assert.Empty(matches[1].Match.Strings);
        Assert.Empty(matches[1].Match.Tags);
        Assert.Equal("/tmp/b.dll", matches[1].Target);
    }

    // An orphan detail line with no preceding header is ignored (not attributed to any rule) — no throw, empty.
    [Fact]
    public void ParseAll_OrphanDetailLineBeforeAnyHeader_ReturnsEmpty()
    {
        var matches = YaraCliOutput.ParseAll("0x6:$a: CamelForensics");

        Assert.Empty(matches);
    }

    // A genuine match line retains the scanned file path verbatim as its Target, so the scanner can confirm the
    // hit belongs to the file it actually handed yara (the anchoring the signature change exists to enable).
    [Fact]
    public void ParseAll_RealMatchLine_RetainsScannedTargetPath()
    {
        var result = Assert.Single(YaraCliOutput.ParseAll("Win32_Trojan_Foo /tmp/x/a.dll"));

        Assert.Equal("Win32_Trojan_Foo", result.Match.Rule);
        Assert.Equal("/tmp/x/a.dll", result.Target);
    }

    // The security-relevant case: arbitrary prose on stdout still satisfies the permissive header regex (rule
    // "this"), so a hit IS produced at the parse level — but its Target is the trailing prose, never the file we
    // scanned. Because ParseAll now surfaces that mismatched Target, YaraCliScanner.TargetMatches drops the hit
    // instead of fabricating a finding. (This restores coverage of the previously over-permissive case: before the
    // signature change the target was discarded and such prose could masquerade as a real match.)
    [Fact]
    public void ParseAll_GarbageProseLine_ParsesButTargetIsNotScannedPath()
    {
        const string scannedPath = "/tmp/x/a.dll";

        var result = Assert.Single(YaraCliOutput.ParseAll("this is not yara output at all"));

        Assert.Equal("this", result.Match.Rule);
        Assert.Equal("is not yara output at all", result.Target);
        Assert.NotEqual(scannedPath, result.Target);
    }

    // Null, empty, whitespace-only, and non-matching text all yield an empty result without throwing.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("\n\n   \n")]
    [InlineData("!!! not a rule line !!!")]   // does not start with a rule identifier ⇒ no header match
    [InlineData("2bad")]                       // a leading digit is not a valid rule identifier start
    public void ParseAll_MalformedOrEmptyInput_ReturnsEmpty(string? output)
    {
        Assert.Empty(YaraCliOutput.ParseAll(output));
    }
    #endregion
}
