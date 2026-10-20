namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The round-D (ADR 0032 decision 9) pins that need API added in that round, kept apart from
/// <see cref="YaraCliCoverageSentinelTests"/> so that file still compiles against the Round C scanner (where its
/// coverage tests are shown red by assertion).
///
/// <para><b>Not covered, and why (task item 7):</b> "an embedded rule containing the reserved prefix ⇒ the batch ruleset
/// refuses to prepare ⇒ incomplete" cannot be driven from <c>tests/</c>. <c>CompileRules</c> reads the rules from the
/// scanner's OWN assembly's manifest resources (<c>YaraRuleResources.ReadAll(GetType().Assembly)</c>) and there is no
/// seam to inject rule text; staging it would mean editing <c>src/</c> or its embedded resources. What IS pinned here is
/// the other half of that guard's contract — the rules we ship never trip it — so a future rule import that did would
/// fail this test instead of silently turning every scan Unavailable.</para>
/// </summary>
public sealed class YaraCliCoverageSentinelApiTests
{
    #region Methods
    // The reserved prefix the other tests spell out literally is the one the scanner uses.
    [Fact]
    public void SentinelPrefix_IsTheReservedName()
    {
        Assert.Equal(YaraCliCoverageSentinelTests.SentinelPrefix, YaraCliScanner.SentinelPrefix);
    }

    // The shipped embedded ruleset never uses the reserved prefix, in any case — otherwise CompileRules would refuse to
    // prepare the batch ruleset and every package would read Unavailable.
    [Fact]
    public void EmbeddedRules_NeverUseTheReservedSentinelPrefix()
    {
        var rules = YaraRuleResources.ReadAll(typeof(YaraCliScanner).Assembly).ToArray();

        Assert.NotEmpty(rules);
        Assert.DoesNotContain(rules, r => r.Text.Contains(YaraCliScanner.SentinelPrefix, StringComparison.OrdinalIgnoreCase));
    }

    // Round E, N3: no shipped rule is a GLOBAL rule. A global rule's condition gates every other rule in its namespace —
    // and the coverage sentinel lives in the default namespace with the embedded rules — so a global rule that is false
    // for a file would silence that file's sentinel line too. Every such file would read as "not scanned" by the batch
    // pass and cost a re-scan of its own, and past MaxIndividualScans of them an ordinary package would turn Unavailable;
    // and whether the sentinel fires would then depend on file content the package chooses.
    // Matched as YARA declares it (`global rule`, `global private rule`, `private global rule`; keywords are
    // case-sensitive), so prose and string literals that merely contain the word ("global trustee") do not count.
    [Fact]
    public void EmbeddedRules_DeclareNoGlobalRule()
    {
        var rules = YaraRuleResources.ReadAll(typeof(YaraCliScanner).Assembly).ToArray();
        var global = new Regex(@"(?<![\w$])(?:global\s+(?:private\s+)?|private\s+global\s+)rule\b");

        Assert.NotEmpty(rules);
        Assert.DoesNotContain(rules, r => global.IsMatch(r.Text));
    }
    #endregion
}
