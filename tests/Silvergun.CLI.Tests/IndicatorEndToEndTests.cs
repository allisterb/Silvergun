namespace Silvergun.CLI.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;

using Xunit;

/// <summary>
/// End-to-end (child-process) coverage for <c>docs/agent/tasks/indicator-cli-integration.md</c>: the real
/// <c>Silvergun.CLI</c> entrypoint driven against an assembly with real <see cref="Silvergun.CodeAnalysis.IL.IndicatorAnalysis"/>
/// findings across every category (the shared <c>IndicatorPayloads</c> fixture, reused unmodified from
/// <c>Silvergun.CodeAnalysis.IL.Tests.Fixture</c> — no second copy of the same payloads).
/// <para>
/// Two things can only be pinned this way, not by constructing a report by hand (see
/// <see cref="IndicatorHeadlineAndRenderingTests"/> / <see cref="IndicatorExitCodeInvarianceTests"/> for those):
/// acceptance criterion 1 (the real analysis actually reaches the report through <c>Program.cs</c>'s wiring), and
/// the <c>--json</c> duplicate-property hazard the task spec calls out by name — "if a future model change adds a
/// member to either report record, the splice can emit a DUPLICATE property" — which is a statement about the ACTUAL
/// emitted bytes of a real run, not about the model in isolation.
/// </para>
/// <para>
/// Every scan runs <c>--no-vulns --no-yara</c> so scan-package stays fully offline and deterministic, mirroring
/// <c>CompletenessCliTests</c>. Each CLI invocation is its own process (ADR 0021): a CCI <c>Debug.Assert</c> routes
/// to <c>Environment.FailFast</c>, which in-process would take the whole test run down.
/// </para>
/// </summary>
public sealed class IndicatorEndToEndTests
{
    #region Methods — acceptance criterion 1
    // "analyze on an assembly containing ldstr "https://x.pipedream.net/cb" prints a CallbackDomain detail row
    // naming the host and the caller." IndicatorPayloads.GetCallbackDomainUrl returns exactly that URL.
    //
    // The Caller column is narrow (the detail table has 5 columns at the CLI's fixed 100-column default width, ADR
    // 0014) and a fully-namespaced caller — "Silvergun.CodeAnalysis.IL.Tests.Fixture.IndicatorPayloads.
    // GetCallbackDomainUrl" — WILL wrap across several physical lines, mid-word, with no reproduced word boundary.
    // A plain Assert.Contains on that string is unreliable by construction (proven by running the CLI: the method
    // name literally splits as "…DomainU" / "rl"), so this reconstructs the Caller cell from the table's own column
    // boundaries (read off the header row's '|' positions) rather than asserting on wrapped, interleaved text.
    [Fact]
    public void Analyze_OnAssemblyWithCallbackDomainConstant_PrintsDetailRowNamingHostAndCaller()
    {
        var (exit, stdout, stderr, exited) = RunCli("analyze", FixtureDll);

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.True(exit is 0 or 2, $"unexpected exit {exit}. stderr:{Environment.NewLine}{stderr}");
        Assert.Contains("CallbackDomain", stdout);
        Assert.Contains("x.pipedream.net", stdout);

        var caller = ReconstructCallerForFindingWhoseExcerptStartsWith(stdout, "CallbackDomain", "https://x.pipedream");
        Assert.Equal(
            "Silvergun.CodeAnalysis.IL.Tests.Fixture.IndicatorPayloads.GetCallbackDomainUrl", caller);
    }

    // Reconstructs the (possibly word-wrapped) "Caller" cell of the one detail-table row whose Category matches
    // exactly and whose Excerpt starts with the given prefix, by reading column boundaries off the table's own
    // header row ('|' positions) rather than assuming any fixed width. Column continuation lines pad with trailing
    // spaces to the column width (never a hyphen or other marker), so trimming and concatenating each physical
    // line's slice in order reconstructs the original, unwrapped text exactly.
    private static string ReconstructCallerForFindingWhoseExcerptStartsWith(
        string stdout, string category, string excerptPrefix)
    {
        var lines = stdout.Replace("\r\n", "\n").Split('\n');
        var headerIndex = Array.FindIndex(
            lines, l => l.Contains("Category", StringComparison.Ordinal) && l.Contains("Caller", StringComparison.Ordinal)
                && l.Contains("Excerpt", StringComparison.Ordinal));
        Assert.True(headerIndex >= 0, "could not find the Indicators detail table header in stdout.");

        var pipes = lines[headerIndex].Select((c, i) => (c, i)).Where(t => t.c == '|').Select(t => t.i).ToArray();
        Assert.True(pipes.Length >= 6, $"unexpected column count in the detail table header: '{lines[headerIndex]}'");
        var (categoryRange, callerRange, excerptRange) =
            ((pipes[0] + 1, pipes[1]), (pipes[2] + 1, pipes[3]), (pipes[4] + 1, pipes[5]));

        static string Cell(string line, (int Start, int End) range) =>
            range.Start < line.Length ? line[range.Start..Math.Min(range.End, line.Length)].Trim() : string.Empty;

        var caller = new StringBuilder();
        var collecting = false;
        // +2 skips the header row itself and the "|---+---+---|" separator row directly beneath it.
        for (var i = headerIndex + 2; i < lines.Length && lines[i].StartsWith('|'); i++)
        {
            var line = lines[i];
            var thisCategory = Cell(line, categoryRange);
            if (thisCategory.Length > 0)   // a non-blank Category cell starts a new logical (possibly wrapped) row
                collecting = thisCategory == category && Cell(line, excerptRange).StartsWith(excerptPrefix, StringComparison.Ordinal);

            if (collecting)
                caller.Append(Cell(line, callerRange));
        }

        Assert.True(caller.Length > 0, $"found no detail row with Category='{category}' and Excerpt starting '{excerptPrefix}'.");
        return caller.ToString();
    }
    #endregion

    #region Methods — D: the --json duplicate-property hazard (parsed, not eyeballed)
    [Fact]
    public void Analyze_Json_HasNoDuplicatePropertyAtAnyNestingLevel()
    {
        var (exit, stdout, stderr, exited) = RunCli("analyze", FixtureDll, "--json");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.True(exit is 0 or 2, $"unexpected exit {exit}. stderr:{Environment.NewLine}{stderr}");

        using var document = JsonDocument.Parse(stdout.TrimEnd('\r', '\n'));
        AssertNoDuplicatePropertyNamesAtAnyLevel(document.RootElement, "$");

        // Not vacuous: Indicators really was populated (real IndicatorAnalysis findings), so the recursive walk
        // above actually descended into it, not merely into an empty/null placeholder.
        var indicators = document.RootElement.GetProperty("Indicators");
        Assert.Equal(JsonValueKind.Object, indicators.ValueKind);
        Assert.NotEmpty(indicators.GetProperty("Findings").EnumerateArray());
    }

    [Fact]
    public void ScanPackage_Json_HasNoDuplicatePropertyAtAnyNestingLevel_IncludingNestedPerAssemblyIndicators()
    {
        var nupkg = BuildNupkgWithFixtureAssembly("SilvergunIndicatorJson");
        try
        {
            var (exit, stdout, stderr, exited) =
                RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--json", "--allow-incomplete");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.True(exit is 0 or 2, $"unexpected exit {exit}. stderr:{Environment.NewLine}{stderr}");

            using var document = JsonDocument.Parse(stdout.TrimEnd('\r', '\n'));
            AssertNoDuplicatePropertyNamesAtAnyLevel(document.RootElement, "$");

            // The nested case the spec calls out by name: Indicators lives INSIDE each Assemblies[i], not at the
            // top level — walk to it explicitly so a passing recursive check above cannot be dismissed as having
            // never actually reached the nested object.
            var assemblies = document.RootElement.GetProperty("Assemblies").EnumerateArray().ToArray();
            Assert.NotEmpty(assemblies);
            var withIndicators = Assert.Single(assemblies, a =>
                a.TryGetProperty("Indicators", out var ind) && ind.ValueKind == JsonValueKind.Object);
            var findings = withIndicators.GetProperty("Indicators").GetProperty("Findings").EnumerateArray().ToArray();
            Assert.NotEmpty(findings);
            AssertNoDuplicatePropertyNamesAtAnyLevel(withIndicators, "$.Assemblies[withIndicators]");
        }
        finally
        {
            TryDelete(nupkg);
        }
    }
    #endregion

    #region Methods — acceptance criterion 3 (the --json half): noisy categories carry FULL detail
    // ReflectionTypeName/GenericUrl/PrivateIpLiteral are counts-only in the TERMINAL (pinned at the renderer level
    // in IndicatorHeadlineAndRenderingTests) but --json must carry every category in full — nothing is lost, only
    // deprioritised in the human view. IndicatorPayloads guarantees at least one ReflectionTypeName and one
    // GenericUrl finding (NamespaceQualifiedFallback / GenericUrlUnclaimed).
    [Fact]
    public void Analyze_Json_CarriesFullDetailForNoisyCategories()
    {
        var (exit, stdout, stderr, exited) = RunCli("analyze", FixtureDll, "--json");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.True(exit is 0 or 2, $"unexpected exit {exit}. stderr:{Environment.NewLine}{stderr}");

        using var document = JsonDocument.Parse(stdout.TrimEnd('\r', '\n'));
        var findings = document.RootElement.GetProperty("Indicators").GetProperty("Findings").EnumerateArray().ToArray();

        foreach (var category in new[] { "ReflectionTypeName", "GenericUrl" })
        {
            // IndicatorPayloads deliberately carries SEVERAL distinct constants per noisy category (e.g. multiple
            // assembly-qualified type names) — assert at least one, not exactly one, and that its detail fields
            // (Value/Excerpt) are fully populated exactly as a discriminating category's would be.
            var matches = findings.Where(f => f.GetProperty("Category").GetString() == category).ToArray();
            Assert.NotEmpty(matches);
            Assert.All(matches, finding =>
            {
                Assert.False(string.IsNullOrEmpty(finding.GetProperty("Value").GetString()));
                Assert.False(string.IsNullOrEmpty(finding.GetProperty("Excerpt").GetString()));
                Assert.False(string.IsNullOrEmpty(finding.GetProperty("CallerMethod").GetString()));
            });
        }
    }
    #endregion

    #region Methods — helpers
    // Walks every JSON object reachable from `element` (through nested objects and arrays) and asserts its OWN
    // property names are unique — the exact shape the task spec's known hazard describes ("the splice appends;
    // adding a member can emit a duplicate"), checked by parsing rather than by eye, and at EVERY level, not just
    // the top one.
    private static void AssertNoDuplicatePropertyNamesAtAnyLevel(JsonElement element, string path)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var names = element.EnumerateObject().Select(p => p.Name).ToArray();
                var duplicates = names.GroupBy(n => n, StringComparer.Ordinal)
                    .Where(g => g.Count() > 1).Select(g => g.Key).ToArray();
                Assert.True(duplicates.Length == 0, $"duplicate propert{(duplicates.Length == 1 ? "y" : "ies")} at {path}: {string.Join(", ", duplicates)}");
                foreach (var prop in element.EnumerateObject())
                    AssertNoDuplicatePropertyNamesAtAnyLevel(prop.Value, $"{path}.{prop.Name}");
                break;
            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    AssertNoDuplicatePropertyNamesAtAnyLevel(item, $"{path}[{index}]");
                    index++;
                }
                break;
        }
    }

    // Same shape as CompletenessCliTests.RunCli: both streams captured and drained asynchronously, stdin closed,
    // NO_COLOR set so the human report is plain-ASCII.
    private static (int Exit, string Output, string Error, bool Exited) RunCli(params string[] args)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";

        using var process = Process.Start(psi)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        var exited = process.WaitForExit(TimeoutMs);
        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            return (-1, string.Empty, string.Empty, false);
        }

        return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), true);
    }

    // Writes a minimal valid .nupkg (root "<id>.nuspec") carrying the real indicator fixture assembly as its one
    // lib dll — mirrors CompletenessCliTests.BuildNupkg, using pure BCL zip.
    private static string BuildNupkgWithFixtureAssembly(string id)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>Indicator --json duplicate-property regression package.</description>
                <dependencies>
                  <group targetFramework="netstandard2.0" />
                </dependencies>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-indicator-json-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
            Write(zip, "lib/netstandard2.0/Silvergun.CodeAnalysis.IL.Tests.Fixture.dll", File.ReadAllBytes(FixtureDll));
        }
        return path;

        static void Write(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    // Real IndicatorAnalysis findings across every category (shared with the IL suite — see the csproj comment).
    private static readonly string FixtureDll =
        Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.Fixture.dll");

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    private const int TimeoutMs = 120_000;
    #endregion
}
