namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests;
using Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using Xunit;

/// <summary>
/// The R2b harness work (<c>docs/agent/tasks/reachability-r2b.md</c>, S1 harness work and S4): each trigger class judged at
/// ChaOnly and Direct; the runtime classes on the single run in both populations, HostContract and LoadTime only by
/// <c>--combine</c> on P-all over C100 and C-build; the result schema that carries the Direct data; <c>--oracle</c>; and the
/// combine step's gates. Synthetic results throughout (in memory or in temp directories), plus one in-process measurement
/// of the S1 delegate fixture and the harness executable for the combine mode's exit codes.
/// </summary>
public sealed class ReachabilityR2bHarnessTests
{
    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Direct cells
    // ---------------------------------------------------------------------------------------------------

    // 6 of 10 present Network; 4 reach it from TypeInitializer, only one of them without a delegate edge. ChaOnly fails
    // (2 x 4 > 6), Direct passes (2 x 1 <= 6): the two cells of one class get their own outcomes.
    [Fact]
    public void E1_AtDirect_CountsOnlyDirectRoots_AndCanPassWhereChaOnlyFails()
    {
        var plib = ReachabilityAggregation.View(Ten(i => Lib(
            presence: i < 6 ? [(Capability.Network, 1)] : [],
            reaches: i < 4 ? [Reach(RootClass.TypeInitializer, Capability.Network, 1, direct: i == 0 ? 1 : 0)] : [])), Population.Plib);

        var chaOnly = ReachabilityAggregation.E1(plib, RootClass.TypeInitializer);
        var direct = ReachabilityAggregation.E1(plib, RootClass.TypeInitializer, ReachLabel.Direct);

        Assert.Equal((ReachLabel.ChaOnly, Outcome.Fail), (chaOnly.Label, chaOnly.Outcome));
        Assert.Equal((ReachLabel.Direct, Outcome.Pass), (direct.Label, direct.Outcome));
        Assert.Equal(new Share(4, 10), chaOnly.Cells.Single(c => c.Capability == Capability.Network).Reach);
        Assert.Equal(new Share(1, 10), direct.Cells.Single(c => c.Capability == Capability.Network).Reach);
        Assert.Equal(new Share(1, 10), ReachabilityAggregation.Reach(plib, RootClass.TypeInitializer, Capability.Network, ReachLabel.Direct));
        Assert.Equal(new Share(4, 10), ReachabilityAggregation.Reach(plib, RootClass.TypeInitializer, Capability.Network, ReachLabel.ChaOnly));
    }

    // A floor package that reaches only through a delegate is "already reaching" at ChaOnly, so nothing is counted against
    // the pass there; at Direct it does not reach, so it is.
    [Fact]
    public void E1_AtDirect_AFloorPackageReachingOnlyThroughADelegate_CountsAgainstThePass()
    {
        var results = Ten(i => Lib(
            presence: i < 6 ? [(Capability.Network, 1)] : [],
            reaches: i == 0 ? [Reach(RootClass.TypeInitializer, Capability.Network, 1, direct: 1)]
                : i == 8 ? [Reach(RootClass.TypeInitializer, Capability.Network, 1)] : []) with
        {
            ReachPartial = i == 8,
            PartialReason = i == 8 ? "the graph is truncated: nodes" : null,
        });
        var plib = ReachabilityAggregation.View(results, Population.Plib);

        Assert.Equal(0, ReachabilityAggregation.E1(plib, RootClass.TypeInitializer).Cells.Single(c => c.Capability == Capability.Network).FloorPackages);
        Assert.Equal(1, ReachabilityAggregation.E1(plib, RootClass.TypeInitializer, ReachLabel.Direct).Cells.Single(c => c.Capability == Capability.Network).FloorPackages);
    }

    // E2 at Direct counts the profiles' Direct sets: two packages compose FileSystem and Network at ChaOnly (2 of 10 > 10%,
    // fail), but only through a delegate, so at Direct each composes one signal capability (0 of 10, pass). The Unseen
    // split reads DirectUnseen.
    [Fact]
    public void E2_AtDirect_CountsTheProfilesDirectSets()
    {
        var plib = ReachabilityAggregation.View(Ten(i => Lib(profiles: i < 2
            ? [Profile(RootClass.Finalizer, [Capability.FileSystem, Capability.Network], direct: [Capability.FileSystem], unseen: true, directUnseen: false)]
            : i == 2 ? [Profile(RootClass.Finalizer, [Capability.Registry], direct: [Capability.Registry], unseen: true, directUnseen: true)] : [])), Population.Plib);

        var chaOnly = ReachabilityAggregation.E2(plib, RootClass.Finalizer);
        var direct = ReachabilityAggregation.E2(plib, RootClass.Finalizer, ReachLabel.Direct);

        Assert.Equal((Outcome.Fail, new Share(2, 10), new Share(2, 10)), (chaOnly.Outcome, chaOnly.Inclusive, chaOnly.WithUnseen));
        Assert.Equal((Outcome.Pass, new Share(0, 10), ReachLabel.Direct), (direct.Outcome, direct.Inclusive, direct.Label));
    }

    // ...and the reverse composition is counted at Direct too: a profile whose Direct set holds two signals.
    [Fact]
    public void E2_AtDirect_ADirectCompositionFails()
    {
        var plib = ReachabilityAggregation.View(Ten(i => Lib(profiles: i < 2
            ? [Profile(RootClass.NativeEntry, [Capability.FileSystem, Capability.ProcessExecution], direct: [Capability.FileSystem, Capability.ProcessExecution], directUnseen: true)]
            : [])), Population.Plib);

        var direct = ReachabilityAggregation.E2(plib, RootClass.NativeEntry, ReachLabel.Direct);

        Assert.Equal((Outcome.Fail, new Share(2, 10), new Share(2, 10), new Share(0, 10)), (direct.Outcome, direct.Inclusive, direct.WithUnseen, direct.Exclusive));
    }

    // The report: an E1 table per (population, label), the Direct one with a Direct reach column per class; a Direct matrix;
    // the TSV's reach rows carry the Direct count; and the evidence names whether the example and the reach are Direct.
    [Fact]
    public void Report_RendersTheDirectCells_Matrix_Tsv_AndEvidence()
    {
        using var dir = new TempDirectory();
        var delegatePath = new ExampleRecord(RootClass.TypeInitializer, Capability.Network, "App.C..cctor()", ReachEvidence.Bound, false, 3, false, null,
            [new HopRecord("App.C..cctor()", "App.dll", null, 0), new HopRecord("App.C.Payload()", "App.dll", MethodEdgeKind.Ldftn, 1), new HopRecord("System.Net.Http.HttpClient..ctor()", null, MethodEdgeKind.Call, 2)]);
        var directPath = delegatePath with { Root = "App.D..cctor()", Direct = true, Length = 2, Hops = [delegatePath.Hops[0], delegatePath.Hops[2]] };
        var results = Ten(i => Lib(
            presence: i < 6 ? [(Capability.Network, 1)] : [],
            reaches: i < 2 ? [Reach(RootClass.TypeInitializer, Capability.Network, 1, direct: i)] : []) with
        {
            Examples = i == 0 ? [delegatePath] : i == 1 ? [directPath] : [],
        });
        var context = ComparableContext(dir, results);

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(context, results));
        var e1 = Section(md, "## 3.", "## 4.");
        var tsv = ReachabilityCorpusReport.Tsv(results);

        Assert.Null(ReachabilityCorpusReport.NotComparable(context, results));
        Assert.Contains("#### P-lib - ChaOnly", e1);
        Assert.Contains("#### P-all - Direct", e1);
        Assert.Contains("| Signal capability | Presence | LoadTime Direct reach | LoadTime E1 | HostContract Direct reach | HostContract E1 | TypeInitializer Direct reach | TypeInitializer E1 |", e1);
        Assert.Contains("| Network | 6/10 (60.0%) | 0/10 (0.0%) | judged by --combine | 0/10 (0.0%) | judged by --combine | 1/10 (10.0%) | pass | 0/10 (0.0%) | pass | 0/10 (0.0%) | pass |", e1);
        Assert.Contains("| Network | 6/10 (60.0%) | 0/10 (0.0%) | 0/10 (0.0%) | judged by --combine | 0/10 (0.0%) | 0/10 (0.0%) | judged by --combine | 2/10 (20.0%) | 0/10 (0.0%) | pass |", e1);
        Assert.Contains("### P-lib - Direct (denominator 10; unmeasured 0)", Section(md, "## 5.", "## 6."));
        Assert.EndsWith("\tInstantiated\tDirect", tsv[0]);
        Assert.Contains("reach\tP1\t1.0.0\tlib/net8.0\tlib\tyes\tTypeInitializer\tNetwork\t-\t1\t0\t0\t1", tsv);
        Assert.Contains("reach\tP0\t1.0.0\tlib/net8.0\tlib\tyes\tTypeInitializer\tNetwork\t-\t1\t0\t0\t0", tsv);
        var evidence = Section(md, "## 11.", "## 12.");
        Assert.Contains("| Evidence | Direct path | Direct reach | Length | Path |", evidence);
        Assert.Contains("| App.C..cctor() | Bound | no | no | 3 |", evidence);
        Assert.Contains("| App.D..cctor() | Bound | yes | yes | 2 |", evidence);
    }

    // End to end, in process, over the S1 delegate fixture as a package's lib/net10.0: the child carries the library's
    // Direct counts, Direct sets and example labels into the result (schema 4), and the aggregation reads them. FileSystem
    // is reached by six initializers (the expression tree's, by a LoadToken, included), one Direct; Network by the Timer's
    // alone, not Direct (DelegateRootTests pins the library side). The fixture's one long name is cut, and the folder's
    // NamesCut is the report's, through the JSON too (review W2).
    [Fact]
    public void Measure_TheDelegateFixture_CarriesTheDirectCountsSetsAndExamples()
    {
        using var dir = new TempDirectory();
        var nupkg = SyntheticPackage(dir, DelegateRootFixtureAssembly.Path, "lib/net10.0/Delegates.dll");

        var payload = ReachabilityChild.Measure(nupkg);
        var folder = Assert.Single(payload.Folders);
        var result = PackageReachResult.FromJson(PackageReachResult.From(Entry("Synthetic"), payload, identity, 1).ToJson());
        var plib = ReachabilityAggregation.View([result], Population.Plib);

        Assert.Equal((1, 1), (folder.NamesCut, result.Folders[0].NamesCut));
        Assert.Contains("\"NamesCut\": 1", result.ToJson(), StringComparison.Ordinal);
        Assert.Equal((6, 1), (folder.ReachOf(RootClass.TypeInitializer, Capability.FileSystem)!.Roots, folder.ReachOf(RootClass.TypeInitializer, Capability.FileSystem)!.Direct));
        Assert.Equal((1, 0), (folder.ReachOf(RootClass.TypeInitializer, Capability.Network)!.Roots, folder.ReachOf(RootClass.TypeInitializer, Capability.Network)!.Direct));
        Assert.All(folder.Reaches, r => Assert.InRange(r.Direct, 0, r.Roots));
        Assert.All(folder.Profiles, p => Assert.Empty(p.DirectCapabilities.Except(p.Capabilities)));
        Assert.Contains(folder.Profiles, p => p.Class == RootClass.TypeInitializer && p.Capabilities.Contains(Capability.Network) && !p.DirectCapabilities.Contains(Capability.Network));
        Assert.True(folder.Examples.Single(e => e.Class == RootClass.TypeInitializer && e.Capability == Capability.FileSystem).Direct);
        Assert.False(folder.Examples.Single(e => e.Class == RootClass.TypeInitializer && e.Capability == Capability.Network).Direct);
        Assert.Equal(new Share(1, 1), ReachabilityAggregation.Reach(plib, RootClass.TypeInitializer, Capability.Network, ReachLabel.ChaOnly));
        Assert.Equal(new Share(0, 1), ReachabilityAggregation.Reach(plib, RootClass.TypeInitializer, Capability.Network, ReachLabel.Direct));
        Assert.Equal(new Share(1, 1), ReachabilityAggregation.Reach(plib, RootClass.TypeInitializer, Capability.FileSystem, ReachLabel.Direct));
    }

    // ---------------------------------------------------------------------------------------------------
    // Population rules
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void ClassSets_RuntimeClassesInTheSingleRun_HostContractAndLoadTimeByCombine()
    {
        Assert.Equal([RootClass.TypeInitializer, RootClass.Finalizer, RootClass.NativeEntry], ReachabilityAggregation.RuntimeClasses);
        Assert.Equal([RootClass.LoadTime, RootClass.HostContract], ReachabilityAggregation.CombineClasses);
        Assert.Equal(ReachabilityChild.TriggerClasses.Order(), ReachabilityAggregation.RuntimeClasses.Concat(ReachabilityAggregation.CombineClasses).Order());
        Assert.Equal([ReachLabel.ChaOnly, ReachLabel.Direct], ReachabilityAggregation.Labels);
        Assert.All(ReachabilityAggregation.RuntimeClasses, k => Assert.True(ReachabilityAggregation.JudgedInSingleRun(k)));
        Assert.All(ReachabilityAggregation.CombineClasses, k => Assert.False(ReachabilityAggregation.JudgedInSingleRun(k)));
    }

    // A runtime class passes only when it passes in both populations: TypeInitializer reaches Network only from build
    // folders, so P-lib passes and P-all fails (2 x 4 > 6) at ChaOnly - does not discriminate. At Direct it reaches through a
    // delegate only, so both pass. The report's verdict table says so per (class, label).
    [Fact]
    public void Verdict_ARuntimeClass_PassesOnlyWhenBothPopulationsPass()
    {
        using var dir = new TempDirectory();
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}",
            i < 4 ? new[] { Lib(presence: [(Capability.Network, 1)]), Folder("build", "build", reaches: [Reach(RootClass.TypeInitializer, Capability.Network, 1)]) }
                : new[] { Lib(presence: i < 6 ? [(Capability.Network, 1)] : []) })).ToArray();
        var (plib, pall) = (ReachabilityAggregation.View(results, Population.Plib), ReachabilityAggregation.View(results, Population.Pall));
        var context = ComparableContext(dir, results);

        var chaOnly = ReachabilityAggregation.Verdicts(plib, pall).Single(v => v.Class == RootClass.TypeInitializer);
        var direct = ReachabilityAggregation.Verdicts(plib, pall, ReachLabel.Direct).Single(v => v.Class == RootClass.TypeInitializer);
        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(context, results));

        Assert.Equal((Outcome.Pass, Outcome.Pass, Outcome.Fail, Outcome.Pass), (chaOnly.PlibE1!.Value, chaOnly.PlibE2!.Value, chaOnly.PallE1, chaOnly.PallE2));
        Assert.Equal(ClassVerdict.DoesNotDiscriminate, chaOnly.Verdict);
        Assert.Equal((ReachLabel.Direct, ClassVerdict.Discriminates), (direct.Label, direct.Verdict));
        Assert.Null(ReachabilityCorpusReport.NotComparable(context, results));
        Assert.Contains("| TypeInitializer | ChaOnly | pass | pass | **FAIL** | pass | does not discriminate on the benign corpus |", md);
        Assert.Contains("| TypeInitializer | Direct | pass | pass | pass | pass | E1 and E2 hold in both populations |", md);
        Assert.Contains("| Finalizer | ChaOnly | pass | pass | pass | pass | E1 and E2 hold in both populations |", md);
    }

    // HostContract and LoadTime are never given a verdict in a single run, even on a comparable population where the data
    // would decide one (HostContract fails E1 in both populations; LoadTime would pass): their cells and rows read "judged by
    // --combine", while the shares are still shown as data.
    [Fact]
    public void Report_HostContractAndLoadTime_NeverGetAVerdictInASingleRun()
    {
        using var dir = new TempDirectory();
        var results = Ten(i => Lib(presence: i < 6 ? [(Capability.Network, 1)] : [], reaches: i < 4 ? [Reach(RootClass.HostContract, Capability.Network, 1, direct: 1)] : []));
        var context = ComparableContext(dir, results);
        var (plib, pall) = (ReachabilityAggregation.View(results, Population.Plib), ReachabilityAggregation.View(results, Population.Pall));

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(context, results));
        var judged = Section(md, "## 3.", "## 5.");
        var rows = judged.Split('\n').Where(l => l.StartsWith("| HostContract |", StringComparison.Ordinal) || l.StartsWith("| LoadTime |", StringComparison.Ordinal)).ToArray();

        Assert.Null(ReachabilityCorpusReport.NotComparable(context, results));
        Assert.Equal(ClassVerdict.DoesNotDiscriminate, ReachabilityAggregation.Verdicts(plib, pall).Single(v => v.Class == RootClass.HostContract).Verdict);
        Assert.Equal(ClassVerdict.Discriminates, ReachabilityAggregation.Verdicts(plib, pall).Single(v => v.Class == RootClass.LoadTime).Verdict);
        // Per population and label: an E1 class row, an E2 row; and two verdict rows per class.
        Assert.Equal(2 * (2 * 2 + 2 * 2) + 2 * 2, rows.Length);
        Assert.All(rows, r =>
        {
            Assert.Contains(ClassVerdict.JudgedByCombine, r);
            Assert.DoesNotContain("pass", r);
            Assert.DoesNotContain("FAIL", r);
            Assert.DoesNotContain("discriminate", r);
            Assert.DoesNotContain("hold", r);
        });
        Assert.Contains("| HostContract | ChaOnly | judged by --combine | judged by --combine | judged by --combine | judged by --combine | judged by --combine |", rows);
        Assert.Contains("| LoadTime | Direct | judged by --combine | judged by --combine | judged by --combine | judged by --combine | judged by --combine |", rows);
        Assert.Contains("| HostContract | 10 | judged by --combine |", rows);
        // The data: HostContract's reach share (and Bound) in the Network row, its cell reading judged by --combine.
        Assert.Contains("| Network | 6/10 (60.0%) | 0/10 (0.0%) | 0/10 (0.0%) | judged by --combine | 4/10 (40.0%) | 0/10 (0.0%) | judged by --combine |", judged);
    }

    // On a population that is not comparable, the runtime classes read the reason; HostContract and LoadTime still read
    // "judged by --combine": never a verdict, and never a not-comparable reason a reader could take as one pending.
    [Fact]
    public void Report_NotComparable_RuntimeClassesReadTheReason_TheCombineClassesStayJudgedByCombine()
    {
        using var dir = new TempDirectory();
        var results = Ten(i => Lib(presence: i < 6 ? [(Capability.Network, 1)] : []));
        var context = ComparableContext(dir, results) with { Oracle = PresenceOracle.Parse(OracleText(Manifest(dir, "other.manifest", results.Take(1)), results.Take(1))) };

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(context, results));

        Assert.Equal("not comparable (oracle not applicable: another manifest)", ReachabilityCorpusReport.NotComparable(context, results));
        Assert.Contains("| TypeInitializer | ChaOnly | not comparable (oracle not applicable: another manifest) |", md);
        Assert.Contains("| HostContract | ChaOnly | judged by --combine | judged by --combine |", md);
    }

    // The P-all-only verdict: no P-lib outcome, "E1 and E2 hold in P-all" when both pass, the outcome rule otherwise.
    [Theory]
    [InlineData(Outcome.Pass, Outcome.Pass, ClassVerdict.DiscriminatesInPall)]
    [InlineData(Outcome.Fail, Outcome.Pass, ClassVerdict.DoesNotDiscriminate)]
    [InlineData(Outcome.Pass, Outcome.Floor, ClassVerdict.UndecidedFloor)]
    [InlineData(Outcome.NoData, Outcome.NoData, ClassVerdict.Undecided)]
    [InlineData(Outcome.NothingJudged, Outcome.Pass, ClassVerdict.Undecided)]
    public void ClassVerdict_PallOnly_FollowsTheOutcomeRuleOverPallAlone(Outcome pallE1, Outcome pallE2, string expected)
    {
        var verdict = new ClassVerdict(RootClass.HostContract, null, null, pallE1, pallE2, ReachLabel.Direct);

        Assert.True(verdict.PallOnly);
        Assert.Equal(expected, verdict.Verdict);
    }

    // ---------------------------------------------------------------------------------------------------
    // The result schema
    // ---------------------------------------------------------------------------------------------------

    // A schema 3 result (no Direct fields) deserializes into this schema with every Direct count 0: the misread. The
    // reader looks at the schema first and calls it not cached instead.
    [Fact]
    public void CachedResults_AResultOfAnOlderSchema_IsNotCached_RatherThanMisread()
    {
        using var dir = new TempDirectory();
        var entry = Entry("A");
        var old = OlderSchema(Package("A", Lib(reaches: [Reach(RootClass.TypeInitializer, Capability.Network, 2, direct: 1)])));
        File.WriteAllText(PackageReachResult.PathOf(dir.Path, entry), old);

        Assert.Equal(0, PackageReachResult.FromJson(old).Folders[0].Reaches[0].Direct);
        Assert.Null(CachedResults.Load(dir.Path, entry));
        Assert.Null(CachedResults.Load(dir.Path, Entry("Missing")));
    }

    // A current-schema result loads; a file with no schema is not a result and refuses the run, as an unreadable one does.
    [Fact]
    public void CachedResults_ACurrentResultLoads_AndAFileWithNoSchemaIsRefused()
    {
        using var dir = new TempDirectory();
        var result = Package("A", Lib(reaches: [Reach(RootClass.TypeInitializer, Capability.Network, 2, direct: 1)]));
        PackageReachResult.WriteAtomically(PackageReachResult.PathOf(dir.Path, Entry("A")), result.ToJson());
        File.WriteAllText(PackageReachResult.PathOf(dir.Path, Entry("B")), "{ \"Id\": \"B\" }");

        Assert.Equal(1, CachedResults.Load(dir.Path, Entry("A"))!.Folders[0].Reaches[0].Direct);
        Assert.Contains("not a reachability result", Assert.Throws<MixedBuildException>(() => CachedResults.Load(dir.Path, Entry("B"))).Message);
    }

    // The driver re-measures a package whose cached result is of an older schema, and overwrites it with this schema.
    [Fact]
    public void Driver_AResultOfAnOlderSchema_IsReMeasured()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "test.manifest", [Package("A", Lib())]);
        var cache = Path.Combine(dir.Path, "cache");
        var nupkg = CachedNupkg.PathOf(cache, manifest.Entries[0]);
        Directory.CreateDirectory(Path.GetDirectoryName(nupkg)!);
        File.WriteAllText(nupkg, "not a real package");
        var results = Directory.CreateDirectory(Path.Combine(dir.Path, "results")).FullName;
        File.WriteAllText(PackageReachResult.PathOf(results, manifest.Entries[0]), OlderSchema(Package("A", Lib())));
        var children = 0;

        var run = new ReachabilityDriver(cache, results, int.MaxValue, identity, (e, _) =>
        {
            children++;
            return Package(e.Id, Lib(reaches: [Reach(RootClass.Finalizer, Capability.FileSystem, 1, direct: 1)]));
        }).Run(manifest, TextWriter.Null);

        Assert.Equal(1, children);
        Assert.True(run.Complete);
        Assert.Equal(1, CachedResults.Load(results, manifest.Entries[0])!.Folders[0].Reaches[0].Direct);
    }

    [Fact]
    public void Schema_IsFour()
    {
        Assert.Equal(4, PackageReachResult.CurrentSchema);
    }

    // ---------------------------------------------------------------------------------------------------
    // NamesCut (review W2)
    // ---------------------------------------------------------------------------------------------------

    // A folder's NamesCut round-trips through the result file; a folder written without it (none shipped: schema 4 gained
    // it before any corpus run) reads 0.
    [Fact]
    public void NamesCut_RoundTripsThroughTheResultFile()
    {
        var result = Package("A", Lib() with { NamesCut = 3 }, Folder("build", "build"));
        var json = JsonNode.Parse(result.ToJson())!.AsObject();

        Assert.Equal([3, 0], PackageReachResult.FromJson(result.ToJson()).Folders.Select(f => f.NamesCut));
        Assert.Equal(3, (int)json["Folders"]![0]!["NamesCut"]!);
        json["Folders"]![0]!.AsObject().Remove("NamesCut");
        Assert.Equal(0, PackageReachResult.FromJson(json.ToJsonString()).Folders[0].NamesCut);
    }

    // The corpus report: section 1 the corpus total, bold when nonzero; section 12 each cutting folder with its count, and
    // the total again. Folders that cut nothing are not listed for it.
    [Fact]
    public void Report_ShowsNamesCut_PerFolderAndInTotal()
    {
        using var dir = new TempDirectory();
        var results = Ten(i => Lib() with { NamesCut = i switch { 0 => 2, 3 => 5, _ => 0 } });
        var context = ComparableContext(dir, results);

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(context, results)) + "\n## end";
        var (parameters, coverage) = (Section(md, "## 1.", "## 2."), Section(md, "## 12.", "## end"));

        Assert.Contains("| Names cut at 1024 chars (amendment a5; distinct per folder, summed over every folder; per folder in section 12) | **7** (some reported names are bounded, not whole) |", parameters);
        Assert.Contains("| P0 | 1.0.0 | lib/net8.0 | 2 name(s) cut at 1024 chars (amendment a5)\\: reported names bounded, counts whole |", coverage);
        Assert.Contains("| P3 | 1.0.0 | lib/net8.0 | 5 name(s) cut at 1024 chars (amendment a5)\\: reported names bounded, counts whole |", coverage);
        Assert.DoesNotContain("| P1 |", coverage);
        Assert.Contains("Names cut at 1024 chars (amendment a5), over every folder: **7** (some reported names are bounded, not whole).", coverage);
    }

    // ...and an ordinary corpus reads 0 in both places, with section 12 still "None".
    [Fact]
    public void Report_NoNameCut_ReadsZero()
    {
        using var dir = new TempDirectory();
        var results = Ten(i => Lib());

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(ComparableContext(dir, results), results)) + "\n## end";
        var coverage = Section(md, "## 12.", "## end");

        Assert.Contains("per folder in section 12) | 0 |", Section(md, "## 1.", "## 2."));
        Assert.Contains("*None.*", coverage);
        Assert.Contains("over every folder: 0.", coverage);
    }

    // The combine report shows each side's total.
    [Fact]
    public void CombineReport_ShowsEachSidesNamesCut()
    {
        using var dir = new TempDirectory();
        PackageReachResult[] cbuild = [.. Cbuild().Select((r, i) => r with { Folders = [r.Folders[0] with { NamesCut = i + 1 }] })];

        var result = WriteScenario(dir, C100(), cbuild).Combine();
        var md = string.Join("\n", ReachabilityCombine.Markdown(new DateOnly(2026, 11, 7), "o.tsv", identity, result));

        Assert.Null(result.NotComparable);
        Assert.Contains("| Names cut at 1024 chars (amendment a5; distinct per folder, summed over every folder) | 0 | **6** (some reported names are bounded, not whole) |", md);
    }

    // ---------------------------------------------------------------------------------------------------
    // --oracle
    // ---------------------------------------------------------------------------------------------------

    // The default is R2b's oracle beside the harness (and it is there, with R2's); --oracle overrides it.
    [Fact]
    public void Oracle_DefaultsToTheR2bFileBesideTheHarness_AndTheOptionOverridesIt()
    {
        var byDefault = Program.ParseReachability(["--reachability", "--results", "r"])!;
        var overridden = Program.ParseReachability(["--reachability", "--results", "r", "--oracle", "custom.tsv"])!;

        Assert.Equal("presence-oracle-2026-11-06.tsv", Program.OracleFileName);
        Assert.Equal(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, Program.OracleFileName)), byDefault.Oracle);
        Assert.True(File.Exists(byDefault.Oracle));
        Assert.True(File.Exists(Path.Combine(AppContext.BaseDirectory, Program.R2OracleFileName)));
        Assert.Equal(Path.GetFullPath("custom.tsv"), overridden.Oracle);
        Assert.Equal(byDefault.Oracle, Program.OracleOf([]));
    }

    // Both checked-in oracles are over C100 (the same manifest hash), and they differ exactly where the S2 map moved
    // findings (reachability-r2b.md, "Re-baseline"): FileSystem 407 -> 406, NativeInterop 15/1247 -> 13/1188, UnsafeMemory
    // 35/847 -> 37/906, the total 8193 -> 8192; every other capability unchanged.
    [Fact]
    public void Oracle_TheR2bFile_DiffersFromR2sOnlyWhereTheS2MapMovedFindings()
    {
        PresenceOracle Read(string file) => PresenceOracle.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, file)));
        var (r2, r2b) = (Read(Program.R2OracleFileName), Read(Program.OracleFileName));
        var moved = new Dictionary<Capability, (int, int, int, int)>
        {
            [Capability.FileSystem] = (26, 407, 26, 406),
            [Capability.NativeInterop] = (15, 1247, 13, 1188),
            [Capability.UnsafeMemory] = (35, 847, 37, 906),
        };

        Assert.Equal(r2.ManifestHash, r2b.ManifestHash);
        Assert.Equal((r2.Denominator, r2.Assemblies, r2.MethodsAnalysed), (r2b.Denominator, r2b.Assemblies, r2b.MethodsAnalysed));
        Assert.Equal((8193, 8192), (r2.TotalFindings, r2b.TotalFindings));
        foreach (var capability in Enum.GetValues<Capability>())
        {
            var (before, after) = (r2.Capabilities.Single(c => c.Capability == capability), r2b.Capabilities.Single(c => c.Capability == capability));
            Assert.Equal(moved.TryGetValue(capability, out var change) ? change : (before.Packages, before.Total, before.Packages, before.Total),
                (before.Packages, before.Total, after.Packages, after.Total));
        }
    }

    // The report names the oracle it compared against.
    [Fact]
    public void Report_NamesTheOracleFile()
    {
        using var dir = new TempDirectory();
        var results = Ten(i => Lib());
        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(ComparableContext(dir, results) with { OracleName = "my-oracle.tsv" }, results));

        Assert.Contains("## 2. Regression oracle (P-lib presence against `my-oracle.tsv`)", md);
        Assert.Contains("| Presence oracle (`--oracle`) | `my-oracle.tsv` |", md);
    }

    // A committed report must not name the machine's account: a cache root under local app-data is printed from
    // %LOCALAPPDATA% (Program.DisplayPath), and neither the expanded local app-data nor the profile folder appears.
    // Windows only: off Windows the home folder is printed as ~ (HarnessDisplayPathTests).
    [Fact]
    public void Report_PrintsACacheRootUnderLocalAppData_WithoutTheAccountName()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
        if (!OperatingSystem.IsWindows() || local.Length == 0)
            return; // %LOCALAPPDATA% is a Windows name, and there must be a local app-data folder to map.
        using var dir = new TempDirectory();
        var results = Ten(i => Lib());

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(ComparableContext(dir, results) with { CacheRoot = Path.Combine(local, "Silvergun", "benign-corpus") }, results));

        Assert.Contains($"| Cache root (read only; no download in this mode) | `{Path.Combine("%LOCALAPPDATA%", "Silvergun", "benign-corpus")}` |", md);
        Assert.DoesNotContain(local, md, StringComparison.OrdinalIgnoreCase);
        if (profile.Length > 0)
            Assert.DoesNotContain(profile, md, StringComparison.OrdinalIgnoreCase);
    }

    // The free-text rows (a child's detail, a load-failure reason, a presence failure, a partial-reach reason) name files
    // the analysis touched; under local app-data each is printed from %LOCALAPPDATA%: Deterministic redacts before Escape
    // rewrites the separators. None of the three files names the expanded local app-data or profile folder, as written or
    // escaped. Windows only, as above.
    [Fact]
    public void Report_RedactsLocalAppDataInTheFreeTextRows_BeforeEscaping()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
        if (!OperatingSystem.IsWindows() || local.Length == 0)
            return;
        using var dir = new TempDirectory();
        string Under(string root) => Path.Combine(root, "Silvergun", "benign-corpus", "extracted", "x.dll");
        string Load(string root) => $"BadImageFormatException: Could not load '{Under(root)}'.";
        string Crash(string root) => $"exit 35 while reading {Under(root)}";
        string Scan(string root) => $"load failed: {Under(root)}";
        string Partial(string root) => $"the body of {Under(root)} is unreadable";
        PackageReachResult[] results =
        [
            .. Ten(i => i switch
            {
                0 => Lib() with { LoadFailures = [new LoadFailureRecord("lib/net8.0/b.dll", Load(local))] },
                1 => Lib() with { Presence = [new AssemblyPresence("lib/net8.0/a.dll", false, Scan(local), 0, 0, [])] },
                2 => Lib() with { ReachPartial = true, PartialReason = Partial(local) },
                _ => Lib(),
            }),
            PackageReachResult.Without(new ManifestEntry("Q", "1.0.0"), PackageReachResult.Crashed, Crash(local), 35, identity),
        ];
        const string L = "%LOCALAPPDATA%";

        var (paths, _) = ReachabilityCorpusReport.Write(Path.Combine(dir.Path, "out"), ComparableContext(dir, results), results);
        var md = File.ReadAllText(paths[0]);
        var coverage = md[md.IndexOf("## 12.", StringComparison.Ordinal)..];

        Assert.Equal(ReachabilityCorpusReport.MarkdownName(new DateOnly(2026, 11, 7)), Path.GetFileName(paths[0]));
        Assert.Contains($"| Q | 1.0.0 | {PackageReachResult.Crashed} | 35 | {ReachabilityCorpusReport.Escape(Crash(L))} |", md);
        Assert.Contains($"| P0 | 1.0.0 | lib/net8.0 | lib/net8.0/b.dll | {ReachabilityCorpusReport.Escape(Load(L))} |", md);
        Assert.Contains($"| P1 | 1.0.0 | lib/net8.0 | lib/net8.0/a.dll | {ReachabilityCorpusReport.Escape(Scan(L))} | 0 |", md);
        Assert.Contains(ReachabilityCorpusReport.Escape($"{PackageReachResult.Crashed}: {Crash(L)}"), coverage);
        Assert.Contains(ReachabilityCorpusReport.Escape($"reachability partial: {Partial(L)}"), coverage);
        foreach (var text in paths.Select(File.ReadAllText))
            foreach (var root in new[] { local, profile }.Where(r => r.Length > 0))
            {
                Assert.DoesNotContain(root, text, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(ReachabilityCorpusReport.Escape(root), text, StringComparison.OrdinalIgnoreCase);
            }
    }

    // --combine's options: the five required ones, else null; the C-build manifest defaults to the checked-in one beside the
    // harness (50 entries), and the oracle as --reachability's.
    [Fact]
    public void ParseCombine_NeedsItsFiveDirectoriesAndManifest_AndDefaultsTheRest()
    {
        string[] full = ["--combine", "--c100-manifest", "c100.manifest", "--c100-results", "r1", "--c100-repeat", "r2", "--cbuild-results", "b1", "--cbuild-repeat", "b2", "--date", "2026-11-07"];

        var options = Program.ParseCombine(full)!;

        Assert.Null(Program.ParseCombine(["--combine", "--c100-manifest", "c100.manifest", "--c100-results", "r1", "--c100-repeat", "r2", "--cbuild-results", "b1"]));
        Assert.Equal(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, Program.CbuildManifestFileName)), options.CbuildManifest);
        Assert.Equal(50, CorpusManifest.Load(options.CbuildManifest, 0).Entries.Count);
        Assert.Equal(Program.OracleOf([]), options.Oracle);
        Assert.Equal((Path.GetFullPath("r1"), Path.GetFullPath("b2"), new DateOnly(2026, 11, 7)), (options.C100Results, options.CbuildRepeat, options.Date));
        Assert.Equal(Path.GetFullPath("o.tsv"), Program.ParseCombine([.. full, "--oracle", "o.tsv"])!.Oracle);
        Assert.Equal(Path.GetFullPath("c.manifest"), Program.ParseCombine([.. full, "--cbuild-manifest", "c.manifest"])!.CbuildManifest);
    }

    // Nit 5b: the pinned hash is CorpusManifest's hash of the checked-in c-build.manifest, as in the source tree's
    // data/corpus (as corrected after S3; c-build.provenance.md) and as copied beside the harness, 50 entries. Changing the
    // manifest fails this until the constant is re-pinned, deliberately. (An independent recomputation, outside .NET,
    // gave the same value.)
    [Fact]
    public void PinnedCbuildManifestHash_IsTheCheckedInManifestsHash()
    {
        var source = CorpusManifest.Load(Path.Combine(RepositoryRoot(), "data", "corpus", Program.CbuildManifestFileName), 0);
        var beside = CorpusManifest.Load(Path.Combine(AppContext.BaseDirectory, Program.CbuildManifestFileName), 0);

        Assert.Equal(ReachabilityCombine.PinnedCbuildManifestHash, source.Hash);
        Assert.Equal(source.Hash, beside.Hash);
        Assert.Equal(50, source.Entries.Count);
        Assert.Matches("^[0-9a-f]{64}$", ReachabilityCombine.PinnedCbuildManifestHash);
    }

    // The checked-in manifests share no id (R2b S3: "C100 ids excluded"; S4: "none should overlap"). The combine step
    // gives no verdict otherwise, so an overlap here blocks S4.
    [Fact]
    public void CheckedInManifests_C100AndCbuild_ShareNoId()
    {
        var c100 = CorpusManifest.Load(Path.Combine(RepositoryRoot(), "data", "corpus", "benign-top.manifest"), 0);
        var cbuild = CorpusManifest.Load(Path.Combine(AppContext.BaseDirectory, Program.CbuildManifestFileName), 0);

        Assert.Equal(100, c100.Entries.Count);
        Assert.Empty(ReachabilityCombine.Overlap(c100, cbuild));
    }

    // ---------------------------------------------------------------------------------------------------
    // --combine
    // ---------------------------------------------------------------------------------------------------

    // Every gate holds: one P-all population over both runs with one denominator (C100's 5 + C-build's 3), and HostContract
    // and LoadTime judged at both labels. HostContract reaches FileSystem from three C-build packages (2 x 3 > 5: does not
    // discriminate at ChaOnly), only one of them Direct (pass at Direct). Read offline: no PackageCache.
    [Fact]
    public void Combine_WhenEveryGateHolds_JudgesHostContractAndLoadTimeOnTheUnion()
    {
        using var dir = new TempDirectory();
        var scenario = WriteScenario(dir, C100(), Cbuild());
        var before = PackageCache.Constructed;

        var result = scenario.Combine();

        Assert.Equal(before, PackageCache.Constructed);
        Assert.Null(result.NotComparable);
        Assert.True(result.Oracle is { Full: true, Match: true });
        Assert.Equal(8, result.Union.Denominator);
        Assert.Equal(5, ReachabilityAggregation.View(scenario.ReadC100().Results, Population.Pall).Denominator);
        Assert.Equal(new Share(5, 8), ReachabilityAggregation.Presence(result.Union, Capability.FileSystem));
        Assert.Equal(new Share(3, 8), ReachabilityAggregation.Reach(result.Union, RootClass.HostContract, Capability.FileSystem, ReachLabel.ChaOnly));
        Assert.Equal(new Share(1, 8), ReachabilityAggregation.Reach(result.Union, RootClass.HostContract, Capability.FileSystem, ReachLabel.Direct));
        Assert.Equal(
            [
                (RootClass.LoadTime, ReachLabel.ChaOnly, ClassVerdict.DiscriminatesInPall),
                (RootClass.HostContract, ReachLabel.ChaOnly, ClassVerdict.DoesNotDiscriminate),
                (RootClass.LoadTime, ReachLabel.Direct, ClassVerdict.DiscriminatesInPall),
                (RootClass.HostContract, ReachLabel.Direct, ClassVerdict.DiscriminatesInPall),
            ],
            ReachabilityAggregation.Labels.SelectMany(result.Verdicts).Select(v => (v.Class, v.Label, v.Verdict)));
        Assert.All(ReachabilityAggregation.Labels.SelectMany(result.Verdicts), v => Assert.True(v.PallOnly));
    }

    // The combine report: the gates, the union denominator, and a verdict row per (class, label).
    [Fact]
    public void CombineReport_WhenEveryGateHolds_RendersTheGatesAndVerdicts()
    {
        using var dir = new TempDirectory();
        var result = WriteScenario(dir, C100(), Cbuild()).Combine();

        var path = ReachabilityCombine.Write(Path.Combine(dir.Path, "out"), new DateOnly(2026, 11, 7), "o.tsv", identity, result);
        var md = File.ReadAllText(path);

        Assert.Equal("reachability-combine-2026-11-07.md", Path.GetFileName(path));
        Assert.Contains("| C100 oracle, recomputed from the cached results (a full MATCH) | MATCH (4 packages compared) |", md);
        Assert.Contains("| Ids in both manifests (none) | none |", md);
        Assert.Contains($"| C-build manifest is the pinned `c-build.manifest` (hash `{result.Cbuild.Manifest.Hash}`) | yes |", md);
        Assert.Contains("| **P-all denominator** (C100 and C-build, one population) | **8** |", md);
        Assert.Contains("| In P-all (the union's denominator, by run) | 5 | 3 |", md);
        Assert.Contains("**Every gate holds:** the verdicts below stand.", md);
        Assert.Contains("| HostContract | ChaOnly | **FAIL** | pass | does not discriminate on the benign corpus |", md);
        Assert.Contains("| HostContract | Direct | pass | pass | E1 and E2 hold in P-all |", md);
        Assert.Contains("| LoadTime | Direct | pass | pass | E1 and E2 hold in P-all |", md);
        Assert.Contains("| FileSystem | 5/8 (62.5%) | 0/8 (0.0%) | 0/8 (0.0%) | pass | 3/8 (37.5%) | 0/8 (0.0%) | **FAIL** |", md);
        Assert.Contains("| FileSystem | 5/8 (62.5%) | 0/8 (0.0%) | pass | 1/8 (12.5%) | pass |", md);
        Assert.DoesNotContain("TypeInitializer", md);
        Assert.DoesNotContain("\r", md);
        Assert.Equal(md, string.Join("\n", ReachabilityCombine.Markdown(new DateOnly(2026, 11, 7), "o.tsv", identity, result)) + "\n");
    }

    // Each gate failing on its own gives no verdict, and names itself.
    [Theory]
    [InlineData("oracle", "not comparable (C100 oracle MISMATCH)")]
    [InlineData("oracle-other-manifest", "not comparable (C100 oracle not applicable: another manifest)")]
    [InlineData("c100-not-cached", "not comparable (C100 not-cached 1)")]
    [InlineData("cbuild-not-cached", "not comparable (C-build not-cached 1)")]
    [InlineData("cbuild-old-schema", "not comparable (C-build not-cached 1)")]
    [InlineData("c100-repeat-differs", "not comparable (C100 run and repeat differ (1 package(s)))")]
    [InlineData("cbuild-repeat-missing", "not comparable (C-build run and repeat differ (1 package(s)))")]
    [InlineData("overlap", "not comparable (id overlap between the manifests (1))")]
    [InlineData("cbuild-not-pinned", "not comparable (C-build manifest is not the pinned one)")]
    public void Combine_EachGateFailingAlone_GivesNoVerdict(string gate, string expected)
    {
        using var dir = new TempDirectory();
        PackageReachResult[] cbuild = gate == "overlap" ? [.. Cbuild(), Package("a", Folder("build", "build")) with { Version = "9.9.9" }] : Cbuild();
        var scenario = WriteScenario(dir, C100(), cbuild);
        string? oracle = null;
        switch (gate)
        {
            case "oracle":
                oracle = OracleText(scenario.C100, C100().Select(r => r.Id == "A" ? Package("A", Lib(presence: [(Capability.FileSystem, 2), (Capability.Network, 1)])) : r));
                break;
            case "oracle-other-manifest":
                oracle = OracleText(Manifest(dir, "other.manifest", C100().Take(4)), C100().Take(4));
                break;
            case "c100-not-cached":
                // E is build-only, outside P-lib, so the oracle still matches: only the not-cached gate fails.
                File.Delete(PackageReachResult.PathOf(scenario.C100Results, Entry("E")));
                File.Delete(PackageReachResult.PathOf(scenario.C100Repeat, Entry("E")));
                break;
            case "cbuild-not-cached":
                File.Delete(PackageReachResult.PathOf(scenario.CbuildResults, Entry("Z")));
                File.Delete(PackageReachResult.PathOf(scenario.CbuildRepeat, Entry("Z")));
                break;
            case "cbuild-old-schema":
                foreach (var results in new[] { scenario.CbuildResults, scenario.CbuildRepeat })
                    File.WriteAllText(PackageReachResult.PathOf(results, Entry("Y")), OlderSchema(Cbuild()[1]));
                break;
            case "c100-repeat-differs":
                PackageReachResult.WriteAtomically(PackageReachResult.PathOf(scenario.C100Repeat, Entry("B")), Package("B", Lib(presence: [(Capability.FileSystem, 1), (Capability.Registry, 1)])).ToJson());
                break;
            case "cbuild-repeat-missing":
                File.Delete(PackageReachResult.PathOf(scenario.CbuildRepeat, Entry("Y")));
                break;
        }

        var result = scenario.Combine(oracle: oracle, pinned: gate == "cbuild-not-pinned" ? ReachabilityCombine.PinnedCbuildManifestHash : null);
        var md = string.Join("\n", ReachabilityCombine.Markdown(new DateOnly(2026, 11, 7), "o.tsv", identity, result));

        Assert.Equal(expected, result.NotComparable);
        Assert.Equal(gate != "cbuild-not-pinned", result.CbuildPinned);
        if (gate == "cbuild-not-pinned")
            Assert.Contains($"| C-build manifest is the pinned `c-build.manifest` (hash `{ReachabilityCombine.PinnedCbuildManifestHash}`) | **no** (hash `{scenario.Cbuild.Hash}`) |", md);
        Assert.Contains($"**No verdict: {expected}.**", md);
        Assert.Contains($"| HostContract | Direct | {expected} | {expected} | {expected} |", md);
        Assert.DoesNotContain(ClassVerdict.DiscriminatesInPall, md);
        Assert.DoesNotContain("| pass |", md);
        Assert.DoesNotContain("FAIL", md);
    }

    // Results of another build than the harness's refuse the run, as in --reachability.
    [Fact]
    public void Combine_WithResultsOfAnotherBuild_Refuses()
    {
        using var dir = new TempDirectory();
        var scenario = WriteScenario(dir, C100(), Cbuild());

        var ex = Assert.Throws<MixedBuildException>(() => scenario.Combine(new BuildIdentity("other", "other")));

        Assert.Contains("Refusing to aggregate results of different builds", ex.Message);
    }

    // The floor rule takes both runs' floor packages: C100's crashed build-only package (a P-all floor that leaves the
    // oracle alone) and C-build's timed-out one. HostContract reaches FileSystem from one package of 10, presence 5: with
    // both floors counted against it, 2 x (1 + 2) > 5 - Floor; with either alone, 2 x (1 + 1) <= 5 - Pass.
    [Fact]
    public void Combine_CountsTheFloorPackagesOfBothRuns()
    {
        PackageReachResult Crashed(string id, string status) =>
            PackageReachResult.Without(Entry(id), status, "boom", status == PackageReachResult.Crashed ? 35 : null, identity).WithLibTfm(TfmSelection.Choose([$"build/{id}.dll"]));
        PackageReachResult[] cbuild = [Cbuild()[0], .. Cbuild().Skip(1).Select(r => r with { Folders = [r.Folders[0] with { Reaches = [] }] })];
        Outcome HostContract(params PackageReachResult[][] sides)
        {
            using var dir = new TempDirectory();
            var result = WriteScenario(dir, sides[0], sides[1]).Combine();
            Assert.Null(result.NotComparable);
            return ReachabilityAggregation.E1(result.Union, RootClass.HostContract).Outcome;
        }

        Assert.Equal(Outcome.Pass, HostContract(C100(), cbuild));
        Assert.Equal(Outcome.Pass, HostContract([.. C100(), Crashed("F", PackageReachResult.Crashed)], cbuild));
        Assert.Equal(Outcome.Pass, HostContract(C100(), [.. cbuild, Crashed("W", PackageReachResult.Timeout)]));
        Assert.Equal(Outcome.Floor, HostContract([.. C100(), Crashed("F", PackageReachResult.Crashed)], [.. cbuild, Crashed("W", PackageReachResult.Timeout)]));

        using var both = new TempDirectory();
        var floored = WriteScenario(both, [.. C100(), Crashed("F", PackageReachResult.Crashed)], [.. cbuild, Crashed("W", PackageReachResult.Timeout)]).Combine();
        var md = string.Join("\n", ReachabilityCombine.Markdown(new DateOnly(2026, 11, 7), "o.tsv", identity, floored));
        Assert.Equal((10, 2, 2), (floored.Union.Denominator, floored.Union.Units.Count(u => u.Floor), floored.Union.Unmeasured));
        Assert.Contains("| C100 | F | 1.0.0 | crashed\\: boom; presence and reach unmeasured |", md);
        Assert.Contains("| C-build | W | 1.0.0 | timeout\\: boom; presence and reach unmeasured |", md);
    }

    // The per-package comparison of a run and its repeat ignores what differs between two runs of one build (cost, the temp
    // directory, a random extraction name), and nothing else.
    [Fact]
    public void Comparable_IgnoresCostAndExtractionPaths_ButNotMeasurements()
    {
        var failed = new AssemblyPresence("lib/net8.0/a.dll", false, $"load failed: {Path.Combine(Path.GetTempPath(), "silvergun", "pkg-abcdef012345", "a.dll")}", 0, 0, []);
        var result = Package("A", Lib() with { Presence = [failed] });
        var rerun = result with
        {
            Cost = new PackageCost(1, 2, 3, 4, [new FolderCost("lib/net8.0", 5, 6, 7, 8)]),
            Folders = [result.Folders[0] with { Presence = [failed with { Failure = failed.Failure!.Replace("pkg-abcdef012345", "pkg-zyxwvu987654", StringComparison.Ordinal) }] }],
        };

        Assert.Equal(ReachabilityCombine.Comparable(result), ReachabilityCombine.Comparable(rerun));
        Assert.DoesNotContain(Path.GetTempPath().Replace("\\", "\\\\", StringComparison.Ordinal), ReachabilityCombine.Comparable(result), StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(ReachabilityCombine.Comparable(result), ReachabilityCombine.Comparable(Package("A", Lib(reaches: [Reach(RootClass.Finalizer, Capability.FileSystem, 1)]))));
        Assert.NotEqual(ReachabilityCombine.Comparable(result), ReachabilityCombine.Comparable(result with { Status = PackageReachResult.GraphFailed }));
    }

    // Overlap compares NuGet ids case-insensitively, and names both versions.
    [Fact]
    public void Overlap_ComparesIdsCaseInsensitively_AndNamesBothVersions()
    {
        using var dir = new TempDirectory();
        var c100 = Manifest(dir, "a.manifest", [Package("Foo", Lib()), Package("Bar", Lib())]);
        var cbuild = Manifest(dir, "b.manifest", [Package("foo", Lib()) with { Version = "2.0.0" }, Package("Baz", Lib())]);

        Assert.Equal(["Foo (C100 1.0.0, C-build 2.0.0)"], ReachabilityCombine.Overlap(c100, cbuild));
    }

    // The harness end to end. --combine requires the pinned C-build manifest (Nit 5b) and has no flag to waive it, so the
    // passing run reads synthetic results for every entry of the checked-in c-build.manifest. Exit 0 with the verdicts
    // when every gate holds; exit 3 and no verdict for any other C-build manifest (here a 3-entry one), and when another
    // gate fails (here an id overlap, put on C100's side so the C-build manifest stays the pinned one), after writing the
    // report; exit 1 on results of another build; exit 2 without the required options.
    [Fact]
    public async Task Harness_Combine_ExitCodesFollowTheReachabilityConvention()
    {
        using var dir = new TempDirectory();
        var harnessIdentity = BuildIdentities.Current(RepositoryRoot(), AppContext.BaseDirectory);
        var pinned = PinnedCbuild();
        var good = WriteScenario(Sub(dir, "good"), C100(), pinned, harnessIdentity);
        var overlap = WriteScenario(Sub(dir, "overlap"), [.. C100(), Package(pinned[0].Id, Folder("build", "build")) with { Version = "9.9.9" }], pinned, harnessIdentity);
        var unpinned = WriteScenario(Sub(dir, "unpinned"), C100(), Cbuild(), harnessIdentity);
        var mixed = WriteScenario(Sub(dir, "mixed"), C100(), pinned);
        Assert.Equal(ReachabilityCombine.PinnedCbuildManifestHash, good.Cbuild.Hash);   // the premise
        Assert.NotEqual(ReachabilityCombine.PinnedCbuildManifestHash, unpinned.Cbuild.Hash);

        var ok = await RunCombine(good, Path.Combine(dir.Path, "out-good"));
        var notComparable = await RunCombine(overlap, Path.Combine(dir.Path, "out-overlap"));
        var notPinned = await RunCombine(unpinned, Path.Combine(dir.Path, "out-unpinned"));
        var refused = await RunCombine(mixed, Path.Combine(dir.Path, "out-mixed"));
        var usage = await Run(["--combine", "--c100-manifest", good.C100.Path]);

        Assert.True(ok.ExitCode == 0, ok.Stderr + ok.Stdout);
        Assert.Contains("VERDICT HostContract ChaOnly: does not discriminate on the benign corpus", ok.Stdout);
        Assert.Contains("VERDICT HostContract Direct: E1 and E2 hold in P-all", ok.Stdout);
        Assert.True(File.Exists(Path.Combine(dir.Path, "out-good", "reachability-combine-2026-11-07.md")));
        Assert.Equal(Program.NotComparableExitCode, notComparable.ExitCode);
        Assert.Contains("NOT-COMPARABLE not comparable (id overlap between the manifests (1))", notComparable.Stderr);
        Assert.True(File.Exists(Path.Combine(dir.Path, "out-overlap", "reachability-combine-2026-11-07.md")));
        Assert.True(notPinned.ExitCode == Program.NotComparableExitCode, notPinned.Stderr + notPinned.Stdout);
        Assert.Contains("NOT-COMPARABLE not comparable (C-build manifest is not the pinned one)", notPinned.Stderr);
        Assert.DoesNotContain("VERDICT", notPinned.Stdout);
        Assert.Equal(1, refused.ExitCode);
        Assert.Contains("Refusing to aggregate results of different builds", refused.Stderr);
        Assert.Equal(2, usage.ExitCode);
    }

    // ---------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------

    private static Task<(int ExitCode, string Stdout, string Stderr)> RunCombine(Scenario scenario, string output) =>
        Run(["--combine", "--c100-manifest", scenario.C100.Path, "--c100-results", scenario.C100Results, "--c100-repeat", scenario.C100Repeat,
            "--cbuild-manifest", scenario.Cbuild.Path, "--cbuild-results", scenario.CbuildResults, "--cbuild-repeat", scenario.CbuildRepeat,
            "--oracle", scenario.OraclePath, "--out", output, "--date", "2026-11-07"]);

    private static async Task<(int ExitCode, string Stdout, string Stderr)> Run(string[] args)
    {
        var psi = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.exe"))
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "the harness did not finish");
        return (process.ExitCode, await stdout, await stderr);
    }

    // C100: four lib packages presenting FileSystem (A also Network), and a build-only one, E.
    private static PackageReachResult[] C100() =>
    [
        Package("A", Lib(presence: [(Capability.FileSystem, 1), (Capability.Network, 1)])),
        Package("B", Lib(presence: [(Capability.FileSystem, 1)])),
        Package("C", Lib(presence: [(Capability.FileSystem, 1)])),
        Package("D", Lib(presence: [(Capability.FileSystem, 1)])),
        Package("E", Folder("build", "build")),
    ];

    // C-build: three build-time packages whose HostContract roots reach FileSystem; only X's without a delegate edge.
    private static PackageReachResult[] Cbuild() =>
    [
        Package("X", Folder("analyzers/dotnet/cs", "analyzers", presence: [(Capability.FileSystem, 1)], reaches: [Reach(RootClass.HostContract, Capability.FileSystem, 1, direct: 1)])),
        Package("Y", Folder("analyzers/dotnet/cs", "analyzers", reaches: [Reach(RootClass.HostContract, Capability.FileSystem, 1)])),
        Package("Z", Folder("build", "build", reaches: [Reach(RootClass.HostContract, Capability.FileSystem, 1)])),
    ];

    // Results for every entry of the checked-in c-build.manifest, in its order, so the manifest written from them has the
    // pinned hash: the first three shaped as Cbuild()'s X, Y and Z, the rest build folders reaching nothing.
    private static PackageReachResult[] PinnedCbuild()
    {
        var entries = CorpusManifest.Load(Path.Combine(AppContext.BaseDirectory, Program.CbuildManifestFileName), 0).Entries;
        var shaped = Cbuild();
        return [.. entries.Select((e, i) => (i < shaped.Length ? shaped[i] : Package(e.Id, Folder("build", "build"))) with { Id = e.Id, Version = e.Version })];
    }

    // Both manifests, a run and a repeat directory per manifest (the repeat with other costs, as a real second run has),
    // and the C100 oracle its results reproduce, written as a file too.
    private static Scenario WriteScenario(TempDirectory dir, IReadOnlyList<PackageReachResult> c100, IReadOnlyList<PackageReachResult> cbuild, BuildIdentity? by = null)
    {
        var (c100s, cbuilds) = (c100.Select(r => r with { Identity = by ?? identity }).ToArray(), cbuild.Select(r => r with { Identity = by ?? identity }).ToArray());
        string Results(string name, IEnumerable<PackageReachResult> results, long wallMs)
        {
            var path = Directory.CreateDirectory(Path.Combine(dir.Path, name)).FullName;
            foreach (var result in results)
                PackageReachResult.WriteAtomically(PackageReachResult.PathOf(path, new ManifestEntry(result.Id, result.Version)), (result with { Cost = PackageCost.None with { ChildWallMs = wallMs } }).ToJson());
            return path;
        }

        var c100Manifest = Manifest(dir, "c100.manifest", c100s);
        var oracle = OracleText(c100Manifest, c100s);
        var oraclePath = Path.Combine(dir.Path, "oracle.tsv");
        File.WriteAllText(oraclePath, oracle);
        return new Scenario(c100Manifest, Manifest(dir, "c-build.manifest", cbuilds),
            Results("c100-1", c100s, 11), Results("c100-2", c100s, 22), Results("cbuild-1", cbuilds, 33), Results("cbuild-2", cbuilds, 44), oracle, oraclePath);
    }

    private static TempDirectory Sub(TempDirectory dir, string name) => new(Path.Combine(dir.Path, name));

    // The presence oracle `results` reproduce over `manifest`: P-lib .dll presence, as CompareOracle reads it.
    private static string OracleText(CorpusManifest manifest, IEnumerable<PackageReachResult> results)
    {
        var units = ReachabilityAggregation.View(results.ToArray(), Population.Plib).Units
            .Select(u => (u.Result, Dlls: u.Folders.SelectMany(f => f.Presence).Where(p => p.Ok && p.Assembly.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).ToArray()))
            .ToArray();
        int Of(AssemblyPresence[] dlls, Capability c) => dlls.Sum(d => d.Of(c));
        int Findings(AssemblyPresence[] dlls) => dlls.Sum(d => d.Findings.Sum(f => f.Findings));
        return string.Join("\n", new[]
            {
                "# a test oracle",
                $"manifest-hash\t{manifest.Hash}",
                $"denominator\t{units.Length}",
                $"assemblies\t{units.Sum(u => u.Dlls.Length)}",
                $"methods-analysed\t{units.Sum(u => u.Dlls.Sum(d => d.MethodsAnalyzed))}",
                $"total-findings\t{units.Sum(u => Findings(u.Dlls))}",
            }
            .Concat(Enum.GetValues<Capability>().Select(c => $"capability\t{c}\t{units.Count(u => Of(u.Dlls, c) > 0)}\t{units.Sum(u => Of(u.Dlls, c))}"))
            .Concat(units.Select(u => $"package\t{u.Result.Id}\t{u.Result.Version}\t{u.Result.LibTfm}\t{u.Dlls.Length}\t{u.Dlls.Sum(d => d.MethodsAnalyzed)}\t{Findings(u.Dlls)}"))
            .Concat(units.SelectMany(u => Enum.GetValues<Capability>().Where(c => Of(u.Dlls, c) > 0).Select(c => $"package-capability\t{u.Result.Id}\t{c}\t{Of(u.Dlls, c)}"))));
    }

    // A --reachability report context whose manifest is the results' and whose oracle they reproduce: comparable.
    private static ReachabilityReportContext ComparableContext(TempDirectory dir, IReadOnlyList<PackageReachResult> results)
    {
        var manifest = Manifest(dir, "comparable.manifest", results);
        return new ReachabilityReportContext(new DateOnly(2026, 11, 7), manifest, "C:\\cache", identity, TimeSpan.FromSeconds(600),
            PresenceOracle.Parse(OracleText(manifest, results)), "test-oracle.tsv");
    }

    private static CorpusManifest Manifest(TempDirectory dir, string name, IEnumerable<PackageReachResult> results)
    {
        var path = Path.Combine(dir.Path, name);
        File.WriteAllLines(path, results.Select(r => $"{r.Id},{r.Version}"));
        return CorpusManifest.Load(path, 0);
    }

    // `result` as a schema 3 harness wrote it: Schema 3, and no Direct fields on its reaches, profiles or examples.
    private static string OlderSchema(PackageReachResult result)
    {
        var json = JsonNode.Parse(result.ToJson())!.AsObject();
        json["Schema"] = 3;
        foreach (var folder in json["Folders"]!.AsArray())
        {
            foreach (var reach in folder!["Reaches"]!.AsArray())
                reach!.AsObject().Remove("Direct");
            foreach (var profile in folder["Profiles"]!.AsArray())
            {
                profile!.AsObject().Remove("DirectCapabilities");
                profile.AsObject().Remove("DirectUnseen");
            }
            foreach (var example in folder["Examples"]!.AsArray())
                example!.AsObject().Remove("Direct");
        }
        return json.ToJsonString(PackageReachResult.JsonOptions);
    }

    // The text of a markdown report from one heading up to the next given one.
    private static string Section(string md, string from, string to) =>
        md[md.IndexOf(from, StringComparison.Ordinal)..md.IndexOf(to, StringComparison.Ordinal)];

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (Directory.Exists(Path.Combine(dir.FullName, ".git")) || File.Exists(Path.Combine(dir.FullName, ".git")))
                return dir.FullName;
        throw new InvalidOperationException("no repository above the test output");
    }

    // Ten P-lib packages P0..P9, the i-th with folder(i).
    private static PackageReachResult[] Ten(Func<int, FolderResult> folder) => [.. Enumerable.Range(0, 10).Select(i => Package($"P{i}", folder(i)))];

    private static ManifestEntry Entry(string id) => new(id, "1.0.0");

    private static PackageReachResult Package(string id, params FolderResult[] folders) =>
        new(PackageReachResult.CurrentSchema, id, "1.0.0", PackageReachResult.Scanned, null, 0, identity,
            folders.Any(f => f.IsPlib) ? "net8.0" : null, [], folders, PackageCost.None);

    private static FolderResult Lib(
        IReadOnlyList<(Capability, int)>? presence = null, IReadOnlyList<ReachRecord>? reaches = null, IReadOnlyList<ProfileRecord>? profiles = null) =>
        Folder("lib/net8.0", "lib", presence, reaches, profiles) with { IsPlib = true };

    // One root of every class, an assembly the graph and presence both read, 5 methods analysed.
    private static FolderResult Folder(
        string folder, string role, IReadOnlyList<(Capability, int)>? presence = null, IReadOnlyList<ReachRecord>? reaches = null, IReadOnlyList<ProfileRecord>? profiles = null) =>
        new(folder, role, false, [$"{folder}/a.dll"], [], true, null, 10, [.. ReachabilityChild.AllClasses.Select(k => new ClassCount(k, 1))], 0, 0,
            reaches ?? [], [], profiles ?? [], [], false, null, 0, null,
            [new AssemblyPresence($"{folder}/a.dll", true, null, 5, 0, [.. (presence ?? []).Select(p => new PresenceCount(p.Item1, ApiCallKind.Call, p.Item2))])],
            null, []);

    private static ReachRecord Reach(RootClass @class, Capability? capability, int roots, int direct = 0) => new(@class, capability, roots, 0, 0, direct);

    private static ProfileRecord Profile(
        RootClass @class, IReadOnlyList<Capability> capabilities, IReadOnlyList<Capability> direct, bool unseen = false, bool directUnseen = false) =>
        new(@class, capabilities, unseen, direct, directUnseen, 1, "App.M()");

    // A minimal .nupkg: a nuspec, and a copy of `assembly` at each package path.
    private static string SyntheticPackage(TempDirectory dir, string assembly, params string[] paths)
    {
        var nupkg = Path.Combine(dir.Path, "Synthetic.1.0.0.nupkg");
        using (var zip = ZipFile.Open(nupkg, ZipArchiveMode.Create))
        {
            using (var writer = new StreamWriter(zip.CreateEntry("Synthetic.nuspec").Open(), new UTF8Encoding(false)))
                writer.Write("""
                    <?xml version="1.0" encoding="utf-8"?>
                    <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                      <metadata>
                        <id>Synthetic</id>
                        <version>1.0.0</version>
                        <authors>Silvergun tests</authors>
                        <description>A synthetic package for the R2b harness tests.</description>
                      </metadata>
                    </package>
                    """);
            foreach (var path in paths)
                zip.CreateEntryFromFile(assembly, path);
        }
        return nupkg;
    }
    #endregion

    #region Fields
    private static readonly BuildIdentity identity = new("c0ffee", "5ha256");
    #endregion

    #region Child types
    private sealed record Scenario(
        CorpusManifest C100, CorpusManifest Cbuild, string C100Results, string C100Repeat, string CbuildResults, string CbuildRepeat, string OracleText, string OraclePath)
    {
        public CombineSide ReadC100() => ReachabilityCombine.ReadSide(ReachabilityCombine.C100Name, C100, C100Results, C100Repeat);

        // pinned: the hash C-build's manifest must have; by default this scenario's own, so only the other gates are tested.
        public CombineResult Combine(BuildIdentity? by = null, string? oracle = null, string? pinned = null) => ReachabilityCombine.Combine(
            ReadC100(), ReachabilityCombine.ReadSide(ReachabilityCombine.CbuildName, Cbuild, CbuildResults, CbuildRepeat),
            PresenceOracle.Parse(oracle ?? OracleText), by ?? identity, pinned ?? Cbuild.Hash);
    }

    private sealed class TempDirectory : IDisposable
    {
        public TempDirectory()
            : this(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "silvergun-r2b-tests", Guid.NewGuid().ToString("N")))
        {
        }

        public TempDirectory(string path) => Path = Directory.CreateDirectory(path).FullName;

        public string Path { get; }

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
    #endregion
}
