namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Graph;
using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

using S = Silvergun.PackageAnalysis.NuGet.Tests.ReachabilitySummaryTests;

/// <summary>
/// Reachability R3, S1 (<c>docs/agent/tasks/reachability-r3.md</c>): the scanner hook and the two report fields.
/// <see cref="PackageCapabilityReport.Reachability"/> round-trips byte for byte and is omitted when null;
/// <see cref="PackageCapabilityReport.ReachabilityStatus"/> is derived (written only when not NotRun, ignored on reading);
/// <see cref="PackageScanner.Scan(string, bool, bool, IYaraScanner?, bool)"/> runs no pass by default; the injected pass runs
/// once, last, while the package is open, and its summary is <see cref="ReachabilitySummary.From"/> of what it returned; a
/// throwing pass costs only the reachability section, which then reads Incomplete with an escaped, bounded reason.
/// The projection itself is <see cref="ReachabilitySummaryTests"/>' (S0), whose report builders this reuses. Hostile
/// characters are built from code points; the source holds none raw.
/// </summary>
public sealed class ReachabilityScanWiringTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public ReachabilityScanWiringTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: the report's JSON
    // The rich summary is Incomplete (an Unknown class, a LoadTime note, a TimedOut folder); the lean one is Completed.
    // Records holding IReadOnlyList do not compare structurally, so the round trip is judged on the JSON.
    [Theory]
    [InlineData(true, ReachabilityScanStatus.Incomplete)]
    [InlineData(false, ReachabilityScanStatus.Completed)]
    public void Report_JsonRoundTrip_WithReachability(bool rich, ReachabilityScanStatus expected)
    {
        var summary = ReachabilitySummary.From(rich ? RichReport() : LeanReport());
        AssertNonTrivial(summary, rich);
        Assert.Equal(expected, summary.Status());
        var report = ReportWith(summary);

        var json = report.ToJson();
        var back = PackageCapabilityReport.FromJson(json)!;
        var again = back.ToJson();

        Assert.Equal(json, again);
        Assert.NotNull(back.Reachability);
        Assert.Equal(summary.Folders.Count, back.Reachability!.Folders.Count);
        Assert.Equal(expected, back.ReachabilityStatus);
        Assert.Equal(Serialize(summary), Serialize(back.Reachability));

        using var doc = JsonDocument.Parse(json);
        Assert.Equal(expected.ToString(), doc.RootElement.GetProperty("ReachabilityStatus").GetString());
        var enums = EnumValuesIn(doc.RootElement.GetProperty("Reachability")).ToArray();
        Assert.All(enums, e => Assert.True(e.Value.ValueKind is JsonValueKind.String or JsonValueKind.Null, $"{e.Name} is written as {e.Value.ValueKind}"));
        // Not vacuous: every enum-typed member of the summary appears, as a name.
        Assert.Equal(EnumMembers.Order(StringComparer.Ordinal), enums.Select(e => e.Name).Distinct().Order(StringComparer.Ordinal));
        Assert.Contains(enums, e => e.Name == "Kind" && e.Value.GetString() == "Trigger");
        Assert.Contains(enums, e => e.Name == "Capability" && e.Value.ValueKind == JsonValueKind.Null);
        if (rich)
        {
            Assert.Contains(enums, e => e.Name == "Outcome" && e.Value.GetString() == "TimedOut");
            Assert.Contains(enums, e => e.Name == "Verdict" && e.Value.GetString() == "Unknown");
        }
    }

    // Acceptance criterion 5, the library half: without a summary neither key is written. Judged on the parsed root's
    // property names, since the substring could appear elsewhere.
    [Fact]
    public void Report_JsonWithoutReachability_HasNeitherKey()
    {
        var report = ReportWith(null);

        using var doc = JsonDocument.Parse(report.ToJson());

        var names = doc.RootElement.EnumerateObject().Select(p => p.Name).ToArray();
        Assert.DoesNotContain("Reachability", names);
        Assert.DoesNotContain("ReachabilityStatus", names);
        Assert.Contains("ScriptScanStatus", names);   // the premise: this is the root object, written in full
        Assert.Equal(ReachabilityScanStatus.NotRun, report.ReachabilityStatus);
    }

    // A genuinely pre-R3 report: one written with a summary, both keys then cut out, so the input never depends on what
    // the current writer does without one. It reads NotRun and writes back as a report without a summary.
    [Fact]
    public void Report_OldJson_DeserializesToNotRun()
    {
        var node = JsonNode.Parse(ReportWith(ReachabilitySummary.From(RichReport())).ToJson())!.AsObject();
        Assert.True(node.Remove("Reachability"), "the premise: the report was written with a summary");
        Assert.True(node.Remove("ReachabilityStatus"), "the premise: the report was written with a status");
        var old = node.ToJsonString();

        var back = PackageCapabilityReport.FromJson(old)!;

        Assert.Null(back.Reachability);
        Assert.Equal(ReachabilityScanStatus.NotRun, back.ReachabilityStatus);
        var written = JsonNode.Parse(back.ToJson())!.AsObject();
        Assert.False(written.ContainsKey("Reachability"));
        Assert.False(written.ContainsKey("ReachabilityStatus"));
        Assert.True(JsonNode.DeepEquals(node, written), "the old report did not write back as it was read");
        Assert.Equal(ReportWith(null).ToJson(), back.ToJson());
    }

    // The status is derived from the summary, so a stray status without a summary is ignored on reading, whatever it says,
    // and is not written back.
    [Theory]
    [InlineData("Completed")]
    [InlineData("Incomplete")]
    public void Report_JsonWithAStrayStatusAndNoSummary_ReadsNotRun(string stray)
    {
        var node = JsonNode.Parse(ReportWith(null).ToJson())!.AsObject();
        node["ReachabilityStatus"] = stray;

        var back = PackageCapabilityReport.FromJson(node.ToJsonString())!;

        Assert.Null(back.Reachability);
        Assert.Equal(ReachabilityScanStatus.NotRun, back.ReachabilityStatus);
        using var doc = JsonDocument.Parse(back.ToJson());
        Assert.False(doc.RootElement.TryGetProperty("ReachabilityStatus", out _));
    }

    // A stray status that disagrees with the summary loses to the summary.
    [Fact]
    public void Report_JsonWhoseStatusDisagreesWithItsSummary_ReadsTheSummarysStatus()
    {
        var node = JsonNode.Parse(ReportWith(ReachabilitySummary.From(RichReport())).ToJson())!.AsObject();
        node["ReachabilityStatus"] = "Completed";

        var back = PackageCapabilityReport.FromJson(node.ToJsonString())!;

        Assert.Equal(ReachabilityScanStatus.Incomplete, back.ReachabilityStatus);
    }

    [Fact]
    public void Report_JsonWithAnExplicitNullSummary_ReadsNotRun()
    {
        var node = JsonNode.Parse(ReportWith(null).ToJson())!.AsObject();
        node["Reachability"] = null;

        var back = PackageCapabilityReport.FromJson(node.ToJsonString())!;

        Assert.Null(back.Reachability);
        Assert.Equal(ReachabilityScanStatus.NotRun, back.ReachabilityStatus);
    }
    #endregion

    #region Methods: PackageScanner
    // The default, the explicit opt-out, and the internal overload with no pass: no summary, NotRun, and neither key in the
    // JSON. (Were a worker started, even one that cannot run, the summary would be non-null: its folders would read NotRun.)
    [Fact]
    public void Scan_WithoutReachability_NeverStartsAWorker()
    {
        var reports = new[]
        {
            PackageScanner.Scan(fixture.PkgAPath, runYara: false),
            PackageScanner.Scan(fixture.PkgAPath, runYara: false, runReachability: false),
            PackageScanner.Scan(fixture.PkgAPath, true, false, null, (Func<NuGetPackage, PackageReachabilityReport>?)null),
        };

        Assert.All(reports, scan =>
        {
            Assert.True(scan.IsSuccess, scan.Message);
            Assert.Null(scan.Value.Reachability);
            Assert.Equal(ReachabilityScanStatus.NotRun, scan.Value.ReachabilityStatus);
            using var doc = JsonDocument.Parse(scan.Value.ToJson());
            Assert.False(doc.RootElement.TryGetProperty("Reachability", out _));
            Assert.False(doc.RootElement.TryGetProperty("ReachabilityStatus", out _));
        });
    }

    [Fact]
    public void Scan_WithReachability_RunsWhilePackageIsOpen_AndSummarizes()
    {
        var handBuilt = RichReport();
        var order = 0;
        var yara = new RecordingYara(() => ++order);
        var calls = 0;
        var calledAt = 0;
        string? extractionDir = null;
        var dirExisted = false;
        string[] assemblies = [];
        string[] missing = [];

        var scan = PackageScanner.Scan(fixture.PkgAPath, true, true, yara, package =>
        {
            calls++;
            calledAt = ++order;
            extractionDir = package.ExtractionDir;
            dirExisted = Directory.Exists(package.ExtractionDir);
            assemblies = [.. package.Assemblies.Select(a => a.FullPath)];
            missing = [.. assemblies.Where(p => !File.Exists(p))];
            return handBuilt;
        });

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(1, calls);
        Assert.True(dirExisted, "the extraction directory did not exist during the pass");
        Assert.NotEmpty(assemblies);
        Assert.Empty(missing);
        Assert.True(yara.CalledAt > 0 && calledAt > yara.CalledAt, $"the pass ran at step {calledAt}, YARA at step {yara.CalledAt}: the pass must run last");
        Assert.False(Directory.Exists(extractionDir), "the package was not disposed after the scan");

        var report = scan.Value;
        Assert.Equal(Serialize(ReachabilitySummary.From(handBuilt)), Serialize(report.Reachability));
        Assert.Equal(ReachabilityScanStatus.Incomplete, report.ReachabilityStatus);
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
        Assert.Equal(Comparable(Baseline(new RecordingYara(() => 0))), Comparable(report));
    }

    [Fact]
    public void Scan_ReachabilityThrows_ScanSucceeds_SummaryIncomplete()
    {
        var rlo = char.ConvertFromUtf32(0x202E);
        var message = "evil" + rlo + "txt";
        using var warnings = new WarningCapture();

        var scan = PackageScanner.Scan(fixture.PkgAPath, true, false, null, _ => throw new InvalidOperationException(message));

        Assert.True(scan.IsSuccess, scan.Message);
        var report = scan.Value;
        Assert.Equal(ReachabilityScanStatus.Incomplete, report.ReachabilityStatus);
        var summary = report.Reachability!;
        Assert.False(summary.Complete);
        Assert.Equal(0, summary.StatementsDropped);
        var folder = Assert.Single(summary.Folders);
        Assert.Equal((string.Empty, PackageItemRole.Other, FolderOutcome.NotRun, (string?)null), (folder.Folder, folder.Role, folder.Outcome, folder.SameAs));
        Assert.Empty(folder.Classes);
        Assert.Empty(folder.Notes);
        Assert.Empty(folder.Statements);
        Assert.Equal(ReasonPrefix + "evil" + EscapedRlo + "txt", folder.Reason);
        Assert.DoesNotContain(rlo, folder.Reason!, StringComparison.Ordinal);
        Assert.DoesNotContain(rlo, report.ToJson(), StringComparison.Ordinal);

        // One warning names the failure, escaped too.
        var warning = Assert.Single(warnings.Warnings, w => w.StartsWith("Reachability failed for ", StringComparison.Ordinal));
        Assert.Contains(PackageFixture.PkgAId, warning, StringComparison.Ordinal);
        Assert.DoesNotContain(rlo, warning, StringComparison.Ordinal);

        // The failure costs only the reachability section.
        Assert.Equal(Comparable(Baseline(null)), Comparable(report));
    }

    [Fact]
    public void Scan_ReachabilityThrowsWithALongMessage_ReasonIsCutWithTheHashSuffix()
    {
        var message = new string('m', 10_000);
        var full = ReasonPrefix + message;

        var scan = PackageScanner.Scan(fixture.PkgAPath, true, false, null, _ => throw new InvalidOperationException(message));

        Assert.True(scan.IsSuccess, scan.Message);
        var reason = Assert.Single(scan.Value.Reachability!.Folders).Reason!;
        Assert.Equal(Reachability.BoundNameTo(full, ReachabilitySummary.MaxNameChars), reason);
        Assert.StartsWith(full[..256] + (char)0x2026 + $"[+{full.Length - 256} chars, sha256:", reason, StringComparison.Ordinal);
        Assert.Matches(@"\[\+\d+ chars, sha256:[0-9a-f]{8}\]$", reason);
        Assert.True(reason.Length <= 256 + 64, $"the reason is {reason.Length} chars");
        Assert.Equal(ReachabilityScanStatus.Incomplete, scan.Value.ReachabilityStatus);
    }

    // End to end through the real graph worker. net10.0-windows has the CLI beside the tests, so the fixture's lib folder is
    // analysed; the net10.0 build has none, so every folder reads NotRun with the reason, never an in-process fallback.
    [Fact]
    public void Scan_WithRunReachability_RunsTheRealWorker_AndCarriesItsSummary()
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath, runYara: false, runReachability: true);

        Assert.True(scan.IsSuccess, scan.Message);
        var summary = scan.Value.Reachability;
        Assert.NotNull(summary);
        Assert.NotEmpty(summary!.Folders);
        Assert.NotEqual(ReachabilityScanStatus.NotRun, scan.Value.ReachabilityStatus);
        Assert.Equal(summary.Status(), scan.Value.ReachabilityStatus);
        var lib = Assert.Single(summary.Folders, f => f.Folder == "lib/netstandard2.0");
#if WINDOWS
        Assert.Equal(FolderOutcome.Analyzed, lib.Outcome);
        Assert.Null(lib.Reason);
        Assert.Equal(S.presented, lib.Classes.Select(c => c.Class));
#else
        Assert.All(summary.Folders, f => Assert.Equal(FolderOutcome.NotRun, f.Outcome));
        Assert.Contains("there is no graph worker executable", lib.Reason, StringComparison.Ordinal);
        Assert.Equal(ReachabilityScanStatus.Incomplete, scan.Value.ReachabilityStatus);
#endif
    }
    #endregion

    #region Methods: helpers
    // Folders: lib/net8.0 (a NativeEntry trigger with a 12-hop example, an informational Cryptography reach, an unseen sink;
    // HostContract Unknown with two reasons; LoadTime Unknown for a module initializer, which gives a note), lib/net9.0 the
    // same files (SameAs), and tools/net8.0/any TimedOut with its reason. Incomplete.
    private static PackageReachabilityReport RichReport()
    {
        var report = S.Report(
            [
                S.Row(RootClass.NativeEntry, Capability.Network, 3, 1, S.PathOf(true, 12), S.PathOf(false, 3, prefix: "App.D")),
                S.Row(RootClass.TypeInitializer, Capability.Cryptography, 1, 1, S.PathOf(true)),
                S.Row(RootClass.TypeInitializer, null, 2, 2, S.PathOf(true, opacity: OpacityKind.IndirectCall), S.PathOf(true, ownSink: true)),
            ],
            [
                S.Status(RootClass.NativeEntry, RootClassVerdict.Reaches, 3),
                S.Status(RootClass.Finalizer, RootClassVerdict.None, 0),
                S.Status(RootClass.TypeInitializer, RootClassVerdict.Reaches, 3),
                S.Status(RootClass.HostContract, RootClassVerdict.Unknown, 1, "1 root(s) reach code the graph cannot see", "another reason"),
                S.Status(RootClass.LoadTime, RootClassVerdict.Unknown, 0, "lib/net8.0/a.dll: " + GraphFacts.ModuleInitializerGap),
            ]);
        return new(
        [
            S.Analyzed("lib/net8.0", report),
            S.Analyzed("lib/net9.0", report, sameAs: "lib/net8.0"),
            S.NotAnalyzed("tools/net8.0/any", FolderOutcome.TimedOut, "the folder timeout of 120 s ran out"),
        ]);
    }

    // The same reaches with every class decided: Completed.
    private static PackageReachabilityReport LeanReport()
    {
        var report = S.Report(
        [
            S.Row(RootClass.NativeEntry, Capability.Network, 3, 1, S.PathOf(true, 12), S.PathOf(false, 3, prefix: "App.D")),
            S.Row(RootClass.TypeInitializer, Capability.Cryptography, 1, 1, S.PathOf(true)),
            S.Row(RootClass.TypeInitializer, null, 2, 2, S.PathOf(true, opacity: OpacityKind.IndirectCall)),
        ]);
        return new([S.Analyzed("lib/net8.0", report), S.Analyzed("lib/net9.0", report, sameAs: "lib/net8.0")]);
    }

    // The premises of the round trip: the summary carries what the test claims it does.
    private static void AssertNonTrivial(ReachabilitySummary summary, bool rich)
    {
        var statements = summary.Folders.SelectMany(f => f.Statements).ToArray();
        Assert.Contains(statements, s => s.Kind == ReachStatementKind.Trigger);
        Assert.Contains(statements, s => s.Kind == ReachStatementKind.Informational && s.Capability is not null);
        Assert.Contains(statements, s => s.Capability is null);
        Assert.Contains(statements, s => s.Example is { HiddenHops: > 0 });
        Assert.Contains(summary.Folders, f => f.SameAs is not null);
        if (!rich)
            return;
        Assert.Contains(summary.Folders.SelectMany(f => f.Classes), c => c.Verdict == RootClassVerdict.Unknown && c.Reasons.Count > 0);
        Assert.Contains(summary.Folders, f => f.Notes.Count > 0);
        Assert.Contains(summary.Folders, f => f.Outcome != FolderOutcome.Analyzed && f.Reason is not null);
    }

    // Every member of an enum type in the summary, by name, wherever it occurs.
    private static IEnumerable<(string Name, JsonElement Value)> EnumValuesIn(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => element.EnumerateObject().SelectMany(p =>
            EnumMembers.Contains(p.Name) ? [(p.Name, p.Value)] : EnumValuesIn(p.Value)),
        JsonValueKind.Array => element.EnumerateArray().SelectMany(EnumValuesIn),
        _ => [],
    };

    private static PackageCapabilityReport ReportWith(ReachabilitySummary? reachability) => new(
        new PackageIdentityInfo("Pkg", "1.0.0", "Silvergun Tests", "Reachability wiring.", []),
        new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero),
        [],
        [],
        [],
        YaraScanStatus: YaraScanStatus.NotRun,
        ScriptScanStatus: ScriptScanStatus.Completed,
        Reachability: reachability);

    // PkgA scanned without a pass: the baseline the rest of a report with one must equal.
    private PackageCapabilityReport Baseline(IYaraScanner? yara)
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath, true, yara is not null, yara, (Func<NuGetPackage, PackageReachabilityReport>?)null);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    // A report's JSON without its reachability, its timestamps or its random extraction directory name.
    private static string Comparable(PackageCapabilityReport report) =>
        extractionName.Replace(analyzedAt.Replace((report with { Reachability = null }).ToJson(), "\"AnalyzedAt\": \"-\""), "pkg-*");

    private static string Serialize(ReachabilitySummary? summary) => JsonSerializer.Serialize(summary, json);
    #endregion

    #region Nested types
    // An available YARA backend that finds nothing and records when it ran.
    private sealed class RecordingYara(Func<int> tick) : IYaraScanner
    {
        public bool Available => true;

        public int CalledAt { get; private set; }

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => [];

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files)
        {
            CalledAt = tick();
            return [];
        }
    }
    #endregion

    #region Fields
    private readonly PackageFixture fixture;

    private const string ReasonPrefix = "the reachability pass failed: InvalidOperationException: ";

    // The backslash-u form YaraPathSafety.Escape renders U+202E as, built so the source never carries the escape decoded.
    private const string EscapedRlo = @"\" + "u202e";

    // The enum-typed members of ReachabilitySummary and its records.
    private static readonly string[] EnumMembers = ["Role", "Outcome", "Class", "Verdict", "Kind", "Capability", "Evidence"];

    private static readonly Regex analyzedAt = new("\"AnalyzedAt\": \"[^\"]*\"", RegexOptions.CultureInvariant);

    private static readonly Regex extractionName = new(@"pkg-[^\\/""]+", RegexOptions.CultureInvariant);

    private static readonly JsonSerializerOptions json = new() { Converters = { new JsonStringEnumConverter() } };
    #endregion
}
