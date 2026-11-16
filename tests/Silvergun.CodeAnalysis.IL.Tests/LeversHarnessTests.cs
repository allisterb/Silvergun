namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// The harness's <c>--levers</c> mode (<c>docs/agent/tasks/recall-levers-1.md</c>, L2): <see cref="LeversMeasure"/>'s per
/// package result and <see cref="LeversReport"/>'s aggregation are pure functions over reports and results, so they are pinned
/// here on hand-built ones; the offline, cached run goes over a fake cache with a fake measurement. No package is read and no
/// worker runs.
/// </summary>
public sealed class LeversHarnessTests
{
    #region Methods: a package's cells
    [Fact]
    public void Of_ACoReachProfile_FiresItsOwnCellOnly()
    {
        var result = Of(Folder("lib/net8.0", Report(Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network], roots: 3))));

        Assert.Equal(20, result.Cells.Count);
        var fired = Assert.Single(result.Cells, c => c.Fired);
        Assert.Equal(("HostContract", "FileSystem", "Direct", 3, false), (fired.Class, fired.Collection, fired.Label, fired.Roots, fired.Floor));
        Assert.All(result.Cells.Where(c => !c.Fired), c => Assert.Equal((0, false), (c.Roots, c.Floor)));
    }

    [Fact]
    public void Of_ADeferredProfile_FiresTheDeferredCell()
    {
        var result = Of(Folder("lib/net8.0", Report(Profile(RootClass.LoadTime, [Capability.EnvironmentProbe, Capability.Network], direct: [Capability.EnvironmentProbe], roots: 2))));

        var fired = Assert.Single(result.Cells, c => c.Fired);
        Assert.Equal(("LoadTime", "EnvironmentProbe", "Deferred", 2), (fired.Class, fired.Collection, fired.Label, fired.Roots));
    }

    // Roots add up over the folders; a SameAs copy lists no statements, so adds none.
    [Fact]
    public void Of_RootsSumOverFolders_AndACopyAddsNone()
    {
        var report = Report(Profile(RootClass.TypeInitializer, [Capability.FileSystem, Capability.Network], roots: 4));

        var result = Of(Folder("lib/net8.0", report), Folder("lib/net9.0", report), Folder("lib/net10.0", report, sameAs: "lib/net9.0"));

        Assert.Equal(8, Assert.Single(result.Cells, c => c.Fired).Roots);
    }

    [Fact]
    public void Of_AClassUnknownInAnAnalysedFolder_IsAFloorForThatClassOnly()
    {
        var classes = LeversMeasure.Classes.Select(c => new RootClassStatus(c, 1, c == RootClass.Finalizer ? RootClassVerdict.Unknown : RootClassVerdict.Reaches, c == RootClass.Finalizer ? ["a gap"] : []));

        var result = Of(Folder("lib/net8.0", Report([], classes)));

        Assert.All(result.Cells, c => Assert.Equal(c.Class == "Finalizer", c.Floor));
        Assert.All(result.Cells, c => Assert.False(c.Fired));
    }

    [Fact]
    public void Of_AFolderNotAnalysed_IsAFloorForEveryCell()
    {
        var failed = new FolderReachability("tools/any", ["tools/any/a.dll"], [], FolderOutcome.Crashed, null, "worker died", null, 0, 0);

        var result = Of(Folder("lib/net8.0", Report()), failed);

        Assert.All(result.Cells, c => Assert.True(c.Floor));
        Assert.All(result.Cells, c => Assert.False(c.Fired));
    }

    // A cut profile list may be missing the pair: that class is a floor, never a "no".
    [Fact]
    public void Of_ProfilesCutForAClass_IsAFloorForThatClass()
    {
        var profiles = Enumerable.Range(0, ReachabilityChild.MaxProfiles).Select(i => Profile(RootClass.HostContract, [Capability.Registry, (Capability)(i % 11)], root: $"R{i}"));

        var result = Of(Folder("lib/net8.0", Report(profiles, truncated: true)));

        Assert.All(result.Cells, c => Assert.Equal(c.Class == "HostContract", c.Floor));
    }

    [Fact]
    public void Of_NoReport_EveryCellAndSignalIsAFloor_AndNothingFired()
    {
        var result = LeversMeasure.Of("A 1.0.0", "id", "open-failed", 0, null);

        Assert.Equal((20, 4, "open-failed"), (result.Cells.Count, result.Signals.Count, result.Status));
        Assert.All(result.Cells, c => Assert.Equal((false, 0, true), (c.Fired, c.Roots, c.Floor)));
        Assert.All(result.Signals, s => Assert.Equal((0, true), (s.Sites, s.Floor)));
        Assert.Empty(result.Examples);
        Assert.Empty(result.ConstantSinks);
    }
    #endregion

    #region Methods: a package's signals
    [Fact]
    public void Of_Signals_SumTheirSitesOverTheFolders()
    {
        var result = Of(
            Folder("lib/net8.0", Report(), Ssa(Shell("A.M()"), Shell("B.M()"), Secret("C.M()"))),
            Folder("lib/net9.0", Report(), Ssa(Shell("A.M()"))));

        Assert.Equal([("ShellInterpreter", 3), ("StealthArguments", 0), ("ExecutableMemory", 0), ("SecretEnvironmentName", 1)], result.Signals.Select(s => (s.Signal, s.Sites)));
        Assert.All(result.Signals, s => Assert.False(s.Floor));
    }

    [Fact]
    public void Of_ASignalIsAFloor_WhenAFolderHasNoSsaOrIncompleteSsa()
    {
        var noSsa = Of(Folder("lib/net8.0", Report(), Ssa(Shell("A.M()"))), Folder("lib/net9.0", Report()));
        var incomplete = Of(Folder("lib/net8.0", Report(), new FolderSsa(SsaFolderOutcome.Analyzed, Facts(Variant("A.M()", SsaSiteStatus.NotRun)), null)));

        Assert.All(noSsa.Signals, s => Assert.True(s.Floor));
        Assert.All(incomplete.Signals, s => Assert.True(s.Floor));
        Assert.Equal(1, noSsa.Signals.Single(s => s.Signal == "ShellInterpreter").Sites);
    }

    [Fact]
    public void Of_Examples_AreTheSignalSitesOnly_WithTheirFolder()
    {
        var result = Of(Folder("lib/net8.0", Report(), Ssa(Plain("Z.M()"), Shell("A.M()"))));

        var example = Assert.Single(result.Examples);
        Assert.Equal(("lib/net8.0", "ShellInterpreter", "A.M()"), (example.Folder, example.Signal, example.Caller));
        Assert.Equal("System.Diagnostics.Process.Start(\"cmd.exe\")", example.Call);
        Assert.Contains("Process.Start", example.Callee, StringComparison.Ordinal);
    }

    // The --ssa table's rule: Analyzed sites with a Constant or OneOf argument, by capability and callee.
    [Fact]
    public void Of_ConstantSinks_AreAnalyzedSitesWithAConstantArgument()
    {
        var parameter = Variant("B.M()", SsaSiteStatus.Analyzed, SsaValue.OfParameter(0));
        var unknown = Variant("C.M()", SsaSiteStatus.MethodUnknown);
        var oneOf = Variant("D.M()", SsaSiteStatus.Analyzed, new SsaValue(SsaValueKind.OneOf, [Const("a"), Const("b")], null, null));

        var result = Of(Folder("lib/net8.0", Report(), Ssa(Shell("A.M()"), parameter, unknown, oneOf)));

        Assert.Equal(
            new Dictionary<string, int> { ["ProcessExecution\tSystem.Diagnostics.Process.Start"] = 1, ["FileSystem\tSystem.IO.File.ReadAllText"] = 1 }.OrderBy(p => p.Key),
            result.ConstantSinks.OrderBy(p => p.Key));
    }
    #endregion

    #region Methods: a corpus
    [Fact]
    public void CellTallies_CountFiredAndFloorPackages_AndNameThoseThatFired()
    {
        var a = Package("A", Folder("lib/net8.0", Report(Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network]))));
        var b = Package("B", Folder("lib/net8.0", Report(Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network]))));
        var c = Package("C", Folder("lib/net8.0", Report()));
        var d = Package("D", Folder("lib/net8.0", Report([], LeversMeasure.Classes.Select(k => new RootClassStatus(k, 1, k == RootClass.HostContract ? RootClassVerdict.Unknown : RootClassVerdict.Reaches, [])))));
        var e = LeversMeasure.Of("E 1.0.0", "id", "open-failed", 0, null);

        var tallies = LeversReport.CellTallies([b, a, c, d, e]);

        var cell = Assert.Single(tallies, t => t.Name == "HostContract FileSystem+Network Direct");
        Assert.Equal((4, 2, 2, 4), (cell.Measured, cell.Fired, cell.FloorPackages.Count, cell.WorstCase));
        Assert.Equal(["A 1.0.0", "B 1.0.0"], cell.FiredPackages);
        Assert.Equal(["D 1.0.0", "E 1.0.0"], cell.FloorPackages);
        var quiet = Assert.Single(tallies, t => t.Name == "Finalizer EnvironmentProbe+Network Deferred");
        Assert.Equal((0, 1), (quiet.Fired, quiet.FloorPackages.Count));
        Assert.Equal(20, tallies.Count);
        Assert.Equal("TypeInitializer EnvironmentProbe+Network Direct", tallies[0].Name);
        Assert.Equal("LoadTime FileSystem+Network Deferred", tallies[^1].Name);
    }

    [Fact]
    public void SignalTallies_AreInEnumOrder_WithSitesAndFiredNames()
    {
        var a = Package("A", Folder("lib/net8.0", Report(), Ssa(Shell("A.M()"), Shell("B.M()"))));
        var b = Package("B", Folder("lib/net8.0", Report(), Ssa(Secret("A.M()"))));
        var c = Package("C", Folder("lib/net8.0", Report(), Ssa(Plain("A.M()"))));

        var tallies = LeversReport.SignalTallies([a, b, c]);

        Assert.Equal(["ShellInterpreter", "StealthArguments", "ExecutableMemory", "SecretEnvironmentName"], tallies.Select(t => t.Name));
        Assert.Equal((1, 2L), (tallies[0].Fired, tallies[0].Sites));
        Assert.Equal(["A 1.0.0"], tallies[0].FiredPackages);
        Assert.Equal((1, 1L), (tallies[3].Fired, tallies[3].Sites));
        Assert.All(tallies, t => Assert.Empty(t.FloorPackages));
    }

    // --ssa's table: sites descending, then key ordinal; packages are the distinct ones with any.
    [Fact]
    public void ConstantSinks_AreOrderedAsTheSsaReportOrdersThem_AndWriteItsFormat()
    {
        var a = Package("A", Folder("lib/net8.0", Report(), Ssa(Shell("A.M()"), Shell("B.M()"), Plain("C.M()"))));
        var b = Package("B", Folder("lib/net8.0", Report(), Ssa(Shell("A.M()"), Secret("B.M()"))));

        var tsv = LeversReport.ConstantSinksTsv([a, b]);

        Assert.Equal(
            "capability\tcallee\tsites\tpackages\n" +
            "ProcessExecution\tSystem.Diagnostics.Process.Start\t3\t2\n" +
            "EnvironmentProbe\tSystem.Environment.GetEnvironmentVariable\t1\t1\n" +
            "FileSystem\tSystem.IO.File.ReadAllText\t1\t1\n",
            tsv);
    }

    [Fact]
    public void Write_WritesEveryFile_WithTheTablesAndTheFiredNames()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "A", "B");
        var packages = new[]
        {
            Package("A", Folder("lib/net8.0", Report(Profile(RootClass.HostContract, [Capability.EnvironmentProbe, Capability.Network])), Ssa(Shell("A.M()")))),
            Package("B", Folder("lib/net8.0", Report(), Ssa(Plain("A.M()")))),
        };

        var (paths, problems) = LeversReport.Write(manifest, Path.Combine(dir.Path, "cache"), Path.Combine(dir.Path, "results"), dir.Path, new DateOnly(2026, 11, 15), "id", packages);

        Assert.Equal(0, problems);
        Assert.Equal(6, paths.Count);
        Assert.All(paths, p => Assert.True(File.Exists(p), p));
        Assert.Equal(
            ["levers-test-" + LeversMeasure.Configuration.ToLowerInvariant() + "-2026-11-15.md"],
            paths.Select(Path.GetFileName).Where(n => n!.EndsWith(".md", StringComparison.Ordinal)));
        var md = File.ReadAllText(paths[0]);
        Assert.Contains("## Co-reach cells", md, StringComparison.Ordinal);
        Assert.Contains("| HostContract EnvironmentProbe+Network Direct | 2 | 1 | 0 | 1 | A 1.0.0 |", md, StringComparison.Ordinal);
        Assert.Contains("| ShellInterpreter | 2 | 1 | 1 | 0 | 1 | A 1.0.0 |", md, StringComparison.Ordinal);
        Assert.Contains("| A 1.0.0 | ShellInterpreter | lib/net8.0 |", md, StringComparison.Ordinal);
        var cells = File.ReadAllLines(paths[1]);
        Assert.Equal("package\tclass\tcollection\tlabel\tfired\troots\tfloor", cells[0]);
        Assert.Equal(1 + 2 * 20, cells.Length);
        Assert.Contains("A 1.0.0\tHostContract\tEnvironmentProbe\tDirect\tyes\t1\tno", cells);
        Assert.Equal("package\tsignal\tsites\tfloor", File.ReadAllLines(paths[2])[0]);
        Assert.Equal("package\tfolder\tsignal\tcaller\tcallee\tcall", File.ReadAllLines(paths[3])[0]);
    }

    // A package with no report is the one problem, and the report still says so.
    [Fact]
    public void Write_APackageWithoutAReport_IsAProblem()
    {
        using var dir = new TempDirectory();
        var packages = new[] { LeversMeasure.Of("A 1.0.0", "id", "open-failed", 0, null) };

        var (paths, problems) = LeversReport.Write(Manifest(dir, "A"), dir.Path, dir.Path, dir.Path, new DateOnly(2026, 11, 15), "id", packages);

        Assert.Equal(1, problems);
        Assert.Contains("A 1.0.0: open-failed", File.ReadAllText(paths[0]), StringComparison.Ordinal);
    }

    // The cache's own path is a local-app-data path on a developer's machine: the report shows it redacted.
    [Fact]
    public void Write_ShowsTheCachePathRedacted()
    {
        using var dir = new TempDirectory();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        if (local.Length == 0)
            return;
        var cache = Path.Combine(local, "Silvergun", "benign-corpus");

        var (paths, _) = LeversReport.Write(Manifest(dir, "A"), cache, Path.Combine(local, "Silvergun", "results"), dir.Path, new DateOnly(2026, 11, 15), "id", [Package("A", Folder("lib/net8.0", Report()))]);

        var md = File.ReadAllText(paths[0]);
        Assert.DoesNotContain(local, md, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(OperatingSystem.IsWindows() ? "%LOCALAPPDATA%" : "~", md, StringComparison.Ordinal);
    }

    // The sites are a benign package's own text: control, bidi, backtick and pipe characters never reach the report.
    [Fact]
    public void Write_HostileSiteText_IsCleaned()
    {
        using var dir = new TempDirectory();
        var hostile = "K(" + (char)0x202E + "|`" + (char)0x0A + (char)0x07 + ")";
        var package = Package("A", Folder("lib/net8.0", Report(), Ssa(Shell("A.M()")))) with
        {
            Examples = [new LeversExample("lib/" + hostile, "ShellInterpreter", hostile, hostile, hostile)],
            ConstantSinks = new Dictionary<string, int> { ["ProcessExecution\t" + hostile] = 1 },
        };

        var (paths, _) = LeversReport.Write(Manifest(dir, "A"), dir.Path, dir.Path, dir.Path, new DateOnly(2026, 11, 15), "id", [package]);

        foreach (var file in paths)
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotContain((char)0x202E, text);
            Assert.DoesNotContain((char)0x07, text);
        }
        var example = File.ReadAllLines(paths[3])[1].Split('\t');
        Assert.Equal(["A 1.0.0", "lib/K(?????)", "ShellInterpreter", "K(?????)", "K(?????)", "K(?????)"], example);
        Assert.Contains("| A 1.0.0 | ShellInterpreter | lib/K(?????) | `K(?????)` | `K(?????)` |", File.ReadAllText(paths[0]), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the offline, cached run
    // One package per invocation until all are measured: results are reused, a re-run measures nothing.
    [Fact]
    public void Run_CachesPerPackage_AndAReRunNeverMeasuresTwice()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "A", "B", "C");
        var cache = FakeCache(dir, "A", "B", "C");
        var results = Path.Combine(dir.Path, "results");
        var asked = new List<string>();
        LeversPackageResult Measure(string name, string nupkg) { asked.Add(name); return Package(name.Split(' ')[0], Folder("lib/net8.0", Report())); }

        var first = LeversMeasure.Run(manifest, cache, results, dir.Path, new DateOnly(2026, 11, 15), "id", 2, TimeSpan.MaxValue, TextWriter.Null, Measure);
        var second = LeversMeasure.Run(manifest, cache, results, dir.Path, new DateOnly(2026, 11, 15), "id", 2, TimeSpan.MaxValue, TextWriter.Null, Measure);
        var third = LeversMeasure.Run(manifest, cache, results, dir.Path, new DateOnly(2026, 11, 15), "id", 2, TimeSpan.MaxValue, TextWriter.Null, Measure);

        Assert.Equal((1, 0, 0, 0), (first.Pending, first.NotCached, first.Problems, first.Paths.Count));
        Assert.Equal(0, second.Pending);
        Assert.Equal(6, second.Paths.Count);
        Assert.Equal(6, third.Paths.Count);
        Assert.Equal(["A 1.0.0", "B 1.0.0", "C 1.0.0"], asked);
        Assert.Equal(3, Directory.GetFiles(results, "*.levers.json").Length);
    }

    [Fact]
    public void Run_AMissingPackage_IsNotCached_NoMeasurement_NoReport()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "A", "Missing");
        var cache = FakeCache(dir, "A");
        var asked = new List<string>();

        var run = LeversMeasure.Run(manifest, cache, Path.Combine(dir.Path, "results"), dir.Path, new DateOnly(2026, 11, 15), "id", int.MaxValue, TimeSpan.MaxValue, TextWriter.Null,
            (name, _) => { asked.Add(name); return Package("A", Folder("lib/net8.0", Report())); });

        Assert.Equal((1, 0), (run.NotCached, run.Pending));
        Assert.Empty(run.Paths);
        Assert.Equal(["A 1.0.0"], asked);
        Assert.Empty(Directory.GetFiles(dir.Path, "levers-*"));
    }

    [Fact]
    public void Run_AResultOfAnotherBuild_IsRefused_BeforeAnyMeasurement()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "A", "B");
        var cache = FakeCache(dir, "A", "B");
        var results = Directory.CreateDirectory(Path.Combine(dir.Path, "results")).FullName;
        PackageReachResult.WriteAtomically(LeversMeasure.PathOf(results, manifest.Entries[0]), JsonSerializer.Serialize(Package("A", Folder("lib/net8.0", Report())) with { Identity = "old" }, PackageReachResult.JsonOptions));
        var asked = 0;

        var ex = Assert.Throws<InvalidOperationException>(() =>
            LeversMeasure.Run(manifest, cache, results, dir.Path, new DateOnly(2026, 11, 15), "id", int.MaxValue, TimeSpan.MaxValue, TextWriter.Null, (_, _) => { asked++; return Package("B", Folder("lib/net8.0", Report())); }));

        Assert.Contains("another build (old, not id)", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, asked);
    }

    [Fact]
    public void Run_AResultOfAnOlderSchema_IsMeasuredAgain()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "A");
        var cache = FakeCache(dir, "A");
        var results = Directory.CreateDirectory(Path.Combine(dir.Path, "results")).FullName;
        PackageReachResult.WriteAtomically(LeversMeasure.PathOf(results, manifest.Entries[0]), JsonSerializer.Serialize(Package("A", Folder("lib/net8.0", Report())) with { Schema = 0 }, PackageReachResult.JsonOptions));
        var asked = 0;

        LeversMeasure.Run(manifest, cache, results, dir.Path, new DateOnly(2026, 11, 15), "id", int.MaxValue, TimeSpan.MaxValue, TextWriter.Null, (_, _) => { asked++; return Package("A", Folder("lib/net8.0", Report())); });

        Assert.Equal(1, asked);
        Assert.Equal(LeversMeasure.CurrentSchema, JsonSerializer.Deserialize<LeversPackageResult>(File.ReadAllText(LeversMeasure.PathOf(results, manifest.Entries[0])), PackageReachResult.JsonOptions)!.Schema);
    }

    [Fact]
    public void Result_RoundTripsThroughJson()
    {
        var result = Package("A", Folder("lib/net8.0", Report(Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network])), Ssa(Shell("A.M()"))));

        var back = JsonSerializer.Deserialize<LeversPackageResult>(JsonSerializer.Serialize(result, PackageReachResult.JsonOptions), PackageReachResult.JsonOptions)!;

        Assert.Equal(JsonSerializer.Serialize(result, PackageReachResult.JsonOptions), JsonSerializer.Serialize(back, PackageReachResult.JsonOptions));
        Assert.Equal(result.Cells.Count(c => c.Fired), back.Cells.Count(c => c.Fired));
    }

    [Fact]
    public void ReachabilityChild_MaxProfiles_IsTheLibrarys() =>
        Assert.Equal(Reachability.MaxProfilesPerClass, ReachabilityChild.MaxProfiles);
    #endregion

    #region Methods: helpers
    private static LeversPackageResult Of(params FolderReachability[] folders) => Package("A", folders);

    private static LeversPackageResult Package(string id, params FolderReachability[] folders) =>
        LeversMeasure.Of($"{id} 1.0.0", "id", "ok", 5, new PackageReachabilityReport(folders));

    private static FolderReachability Folder(string name, ReachabilityReport report, FolderSsa? ssa = null, string? sameAs = null) =>
        new(name, [$"{name}/a.dll"], [], FolderOutcome.Analyzed, report, null, sameAs, 10, 10, ssa);

    private static ReachabilityReport Report(params ReachProfile[] profiles) => Report(profiles, null);

    private static ReachabilityReport Report(IEnumerable<ReachProfile> profiles, IEnumerable<RootClassStatus>? classes = null, bool truncated = false) =>
        new([], [.. profiles], truncated, [.. classes ?? LeversMeasure.Classes.Select(c => new RootClassStatus(c, 1, RootClassVerdict.Reaches, []))], 0, [], 0, coverage, false, null);

    private static ReachProfile Profile(RootClass cls, Capability[] capabilities, Capability[]? direct = null, int roots = 1, string root = "App.Root") =>
        new(cls, capabilities, false, direct ?? capabilities, false, roots, root);

    private static FolderSsa Ssa(params SsaSinkFact[] facts) => new(SsaFolderOutcome.Analyzed, Facts(facts), null);

    private static SsaFolderFacts Facts(params SsaSinkFact[] facts) => new(facts, facts.Length, false, facts.Length, [], false, false, false, 0);

    private static SinkSite Site(string caller, string key, Capability capability) => new(caller, 1, MethodEdgeKind.Call, key + "(System.String)", key, capability);

    private static SsaSinkFact Fact(SinkSite site, SsaSiteStatus status, params SsaValue[] arguments) =>
        new(site, status, null, status == SsaSiteStatus.Analyzed ? arguments : [], status == SsaSiteStatus.Analyzed ? arguments.Length : 0, false,
            status == SsaSiteStatus.MethodUnknown ? SsaFailureKind.Import : null, status == SsaSiteStatus.Analyzed ? null : "not analysed");

    // A File.ReadAllText site with the given status (and arguments, kept only when Analyzed).
    private static SsaSinkFact Variant(string caller, SsaSiteStatus status, params SsaValue[] arguments) =>
        Fact(Site(caller, "System.IO.File.ReadAllText", Capability.FileSystem), status, arguments);

    private static SsaSinkFact Shell(string caller) => Fact(Site(caller, "System.Diagnostics.Process.Start", Capability.ProcessExecution), SsaSiteStatus.Analyzed, Str("cmd.exe"));

    private static SsaSinkFact Secret(string caller) => Fact(Site(caller, "System.Environment.GetEnvironmentVariable", Capability.EnvironmentProbe), SsaSiteStatus.Analyzed, Str("GITHUB_TOKEN"));

    private static SsaSinkFact Plain(string caller) => Fact(Site(caller, "System.IO.File.ReadAllText", Capability.FileSystem), SsaSiteStatus.Analyzed, Str("x"));

    private static SsaConstant Const(string text) => new(SsaConstantKind.String, text);

    private static SsaValue Str(string text) => SsaValue.OfConstant(Const(text));

    private static CorpusManifest Manifest(TempDirectory dir, params string[] ids)
    {
        var path = Path.Combine(dir.Path, "test.manifest");
        File.WriteAllLines(path, ids.Select(i => $"{i},1.0.0"));
        return CorpusManifest.Load(path, 0);
    }

    // A cache directory holding a (dummy) .nupkg for each id: the run only ever tests that the file exists.
    private static string FakeCache(TempDirectory dir, params string[] ids)
    {
        var root = Path.Combine(dir.Path, "cache");
        foreach (var id in ids)
        {
            var path = CachedNupkg.PathOf(root, new ManifestEntry(id, "1.0.0"));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "not a real package");
        }
        return root;
    }
    #endregion

    #region Fields
    private static readonly GraphCoverage coverage = new(new IndexCoverage(0, 0, 0), 0, 0, 0, 0, ResolutionCounts.None, 0, 0, 0, 0, 0, 0, 0, false, null);
    #endregion

    #region Child types
    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateDirectory(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "silvergun-levers-tests", Guid.NewGuid().ToString("N"))).FullName;

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
    #endregion
}
