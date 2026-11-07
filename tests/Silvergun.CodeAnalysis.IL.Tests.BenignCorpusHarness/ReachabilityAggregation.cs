namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

/// <summary>The two populations of reachability R2 (spec "Populations").</summary>
public enum Population
{
    /// <summary>Per package, the one folder <c>lib/&lt;TfmSelection.Choose&gt;</c>: comparable to the presence baseline.</summary>
    Plib,

    /// <summary>Per package, every folder holding a loaded assembly.</summary>
    Pall
}

/// <summary>The edge set a reach is counted on (<see cref="ReachEvidence"/>), from the record's three counts.</summary>
public enum Tier { ChaOnly, Instantiated, Bound }

/// <summary>
/// The two labels each trigger class is judged at (R2b, "Pre-registered expectations" 1; ADR 0037 amendment a2), each
/// cell with its own verdict.
/// </summary>
public enum ReachLabel
{
    /// <summary>R2's cell: reach is <c>CapabilityReach.Roots &gt; 0</c>, E2 counts the profiles' capability sets.</summary>
    ChaOnly,

    /// <summary>
    /// Reach counts only roots reaching the capability without a deferred edge (<c>CapabilityReach.Direct &gt; 0</c>); E2
    /// counts only the profiles' Direct capability sets (<see cref="ProfileRecord.DirectCapabilities"/>).
    /// </summary>
    Direct
}

/// <summary>How a pre-registered expectation came out for one trigger class in one population.</summary>
public enum Outcome
{
    Pass,
    Fail,

    /// <summary>The class has zero roots in the population: not a pass.</summary>
    NoData,

    /// <summary>E1 only: no signal capability reaches presence in 3 packages, so nothing is judged. Not a pass.</summary>
    NothingJudged,

    /// <summary>
    /// Computed from floor data (spec, "Floor"; review C1): it does not fail on the counted data, but would not pass with
    /// every floor package counted against it. Not a pass.
    /// </summary>
    Floor
}

/// <summary>A share: <see cref="Count"/> of <see cref="Denominator"/> packages.</summary>
public sealed record Share(int Count, int Denominator)
{
    #region Properties
    public double Percent => Denominator == 0 ? 0 : 100.0 * Count / Denominator;
    #endregion

    #region Methods
    public override string ToString() =>
        $"{Count}/{Denominator} ({Percent.ToString("F1", CultureInfo.InvariantCulture)}%)";
    #endregion
}

/// <summary>
/// One package in a population, with the scoped folders either side read (<see cref="FolderResult.Read"/>: a built graph,
/// or a graph-failed folder whose presence was scanned). <see cref="Floor"/>: a scoped folder is a floor folder
/// (<see cref="FolderResult.Floor"/>). <see cref="PresenceFloor"/>: a scoped folder's presence is incomplete
/// (<see cref="FolderResult.PresenceIncomplete"/>: an assembly the graph loaded but presence could not scan, or one
/// presence scanned only partly). <see cref="TruncatedClasses"/>: the classes whose profiles a scoped folder cut. An
/// unmeasured package (<see cref="PackageReachResult.UnmeasuredFloor"/>) has no folders and both floors set.
/// </summary>
public sealed record PackageUnit(PackageReachResult Result, IReadOnlyList<FolderResult> Folders, bool Floor, bool PresenceFloor, IReadOnlySet<RootClass> TruncatedClasses)
{
    #region Properties
    public string Id => Result.Id;
    #endregion

    #region Methods
    /// <summary>A floor package for E2 of <paramref name="class"/>: a floor package, or its class profiles were cut.</summary>
    public bool ProfileFloor(RootClass @class) => Floor || TruncatedClasses.Contains(@class);
    #endregion
}

/// <summary>A population (optionally restricted to one role) and its denominator.</summary>
public sealed record PopulationView(Population Population, string? Role, IReadOnlyList<PackageUnit> Units)
{
    #region Properties
    public int Denominator => Units.Count;

    /// <summary>The units in the denominator that measured nothing (<see cref="PackageReachResult.UnmeasuredFloor"/>).</summary>
    public int Unmeasured => Units.Count(u => u.Result.UnmeasuredFloor);

    public string Name => Population == Population.Plib ? "P-lib" : Role is null ? "P-all" : $"P-all, role {Role}";
    #endregion
}

/// <summary>
/// E1 for one trigger class and one signal capability, judged symmetrically (spec, "Floor"; review round 2).
/// <see cref="Presence"/> is every scoped folder's measured presence (graph-failed folders included), which also decides
/// <see cref="Judged"/>; <see cref="Reach"/> is counted from built graphs only.
/// <list type="bullet">
/// <item><description><b>Best case</b> (for Fail): that reach, against <see cref="PresenceBest"/> = measured presence plus
/// every floor package whose presence could not be measured and is not already counted.</description></item>
/// <item><description><b>Worst case</b> (for Pass): every floor package not already reaching counted as reaching
/// (<see cref="FloorPackages"/>), against <see cref="PresenceSeen"/>, presence only from the assemblies the graph
/// loaded.</description></item>
/// </list>
/// </summary>
public sealed record E1Cell(
    RootClass Class, Capability Capability, Share Presence, Share Reach, Share Bound, bool Judged, int FloorPackages, int PresenceSeen, int PresenceBest)
{
    #region Properties
    /// <summary>
    /// Fail when <c>2 x reach &gt; presenceBest</c>; Pass only when <c>2 x (reach + floor) &lt;= presenceSeen</c>; else Floor.
    /// (<c>reachShare &lt;= 0.5 x presenceShare</c> on integers: both shares have the same denominator.)
    /// </summary>
    public Outcome Outcome =>
        2 * Reach.Count > PresenceBest ? Outcome.Fail
        : WorstCasePasses ? Outcome.Pass
        : Outcome.Floor;

    /// <summary>The worst-case Pass: <c>2 x (reach + floor) &lt;= presenceSeen</c>.</summary>
    public bool WorstCasePasses => 2 * (Reach.Count + FloorPackages) <= PresenceSeen;

    /// <summary>
    /// Not judged on measured presence, but would be in the best case (<see cref="PresenceBest"/> &gt;= 3; review round 3):
    /// floor packages might lift it over the gate.
    /// </summary>
    public bool PossiblyJudged => !Judged && PresenceBest >= ReachabilityAggregation.MinimumJudgedPresence;

    /// <summary>
    /// What the cell contributes to its class: a judged cell its <see cref="Outcome"/>; a possibly judged one Pass when its
    /// worst case passes and Floor otherwise, never Fail; any other cell nothing (too rare to judge).
    /// </summary>
    public Outcome? Contribution =>
        Judged ? Outcome
        : PossiblyJudged ? (WorstCasePasses ? Outcome.Pass : Outcome.Floor)
        : null;
    #endregion
}

/// <summary>E1 for one trigger class in one population at one label: every cell, and the outcome.</summary>
public sealed record E1Result(RootClass Class, int Roots, IReadOnlyList<E1Cell> Cells, Outcome Outcome, ReachLabel Label = ReachLabel.ChaOnly);

/// <summary>
/// E2 for one trigger class in one population. <see cref="Inclusive"/> (the judged count) is the packages with a profile
/// of the class holding two or more distinct signal capabilities, whether or not the profile also reaches Unseen;
/// <see cref="Exclusive"/> counts only profiles without Unseen, <see cref="WithUnseen"/> only profiles with it.
/// <see cref="FloorPackages"/> are the floor packages (<see cref="PackageUnit.ProfileFloor"/>) not already counted, of
/// which <see cref="TruncatedPackages"/> are floors because the class's profiles were cut. At <see cref="ReachLabel.Direct"/>
/// the counts are over the profiles' Direct sets (<see cref="ProfileRecord.DirectCapabilities"/>, <see cref="ProfileRecord.DirectUnseen"/>).
/// </summary>
public sealed record E2Result(
    RootClass Class, int Roots, Share Inclusive, Share Exclusive, Share WithUnseen, Outcome Outcome, int FloorPackages, int TruncatedPackages,
    ReachLabel Label = ReachLabel.ChaOnly);

/// <summary>
/// One (class, label)'s per-population outcomes and its verdict under the pre-registered outcome rule. P-lib's outcomes
/// are null for a class judged on P-all only (<see cref="PallOnly"/>: HostContract and LoadTime, by <c>--combine</c>).
/// </summary>
public sealed record ClassVerdict(RootClass Class, Outcome? PlibE1, Outcome? PlibE2, Outcome PallE1, Outcome PallE2, ReachLabel Label = ReachLabel.ChaOnly)
{
    #region Properties
    /// <summary>Judged on P-all alone: no P-lib outcome.</summary>
    public bool PallOnly => PlibE1 is null && PlibE2 is null;

    /// <summary>
    /// A Fail anywhere decides; else any Floor is "undecided (floor)"; a pass needs Pass in every judged population's E1
    /// and E2 (all four, or P-all's two when <see cref="PallOnly"/>).
    /// </summary>
    public string Verdict =>
        Outcomes.Contains(Outcome.Fail) ? DoesNotDiscriminate
        : Outcomes.Contains(Outcome.Floor) ? UndecidedFloor
        : Outcomes.All(o => o == Outcome.Pass) ? (PallOnly ? DiscriminatesInPall : Discriminates)
        : Undecided;

    private Outcome[] Outcomes => [.. new[] { PlibE1, PlibE2, PallE1, PallE2 }.OfType<Outcome>()];
    #endregion

    #region Fields
    public const string DoesNotDiscriminate = "does not discriminate on the benign corpus";
    public const string Discriminates = "E1 and E2 hold in both populations";
    public const string DiscriminatesInPall = "E1 and E2 hold in P-all";
    public const string UndecidedFloor = "undecided (floor): a cell is computed from floor data, and no failure";
    public const string Undecided = "undecided: no data (or nothing judged) in a population, and no failure";

    /// <summary>What a HostContract or LoadTime cell reads in a single <c>--reachability</c> run: data, never a verdict.</summary>
    public const string JudgedByCombine = "judged by --combine";
    #endregion
}

/// <summary>Q3: the reached (package, capability) pairs of one class, by the strongest tier reaching them.</summary>
public sealed record TierSplit(RootClass Class, int Pairs, int Bound, int InstantiatedNotBound, int ChaOnlyOnly);

/// <summary>Q4: how often one class is Unknown in a population, and why (packages per reason category).</summary>
public sealed record UnknownSplit(
    RootClass Class, Share Unknown, IReadOnlyList<NamedCount> Reasons, IReadOnlyList<NamedCount> UnseenEnds, int PackagesWithLoadFailures);

/// <summary>Q2: the median and p90 of one root class's share of own methods, over a population's packages.</summary>
public sealed record RootShareStats(RootClass Class, int Packages, double Median, double P90);

/// <summary>Q5: one folder's parity.</summary>
public sealed record FolderParity(string Package, string Version, string Folder, ParityRecord Parity);

/// <summary>
/// Section 11: one trigger-class x signal-capability reach, with the example a human checks. <see cref="DirectReach"/>: the
/// folder's reach row counts a Direct root (<see cref="ReachRecord.Direct"/>), which its example need not show (the S1
/// known limit: the Direct pass is over ChaOnly edges, the example is the strongest tier's).
/// </summary>
public sealed record Evidence(string Package, string Version, string Folder, string Role, bool IsPlib, ExampleRecord Example, bool DirectReach);

/// <summary>A presence baseline, as data (<c>--oracle</c>: R2's <c>presence-oracle-2026-08-21.tsv</c>, R2b's <c>presence-oracle-2026-11-06.tsv</c>).</summary>
public sealed record PresenceOracle(
    string ManifestHash, int Denominator, int Assemblies, int MethodsAnalysed, int TotalFindings,
    IReadOnlyList<OracleCapability> Capabilities, IReadOnlyList<OraclePackage> Packages)
{
    #region Methods
    /// <summary>Parses the oracle file: <c>#</c> comments, then tab-separated records. A malformed line throws.</summary>
    public static PresenceOracle Parse(string text)
    {
        var rows = text.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0 && !l.StartsWith('#')).Select(l => l.Split('\t')).ToArray();
        string Scalar(string name) => rows.Single(r => r[0] == name)[1];
        int Number(string value) => int.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);

        var byPackage = rows.Where(r => r[0] == "package-capability")
            .GroupBy(r => r[1], StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (IReadOnlyDictionary<Capability, int>)g.ToDictionary(r => Enum.Parse<Capability>(r[2]), r => Number(r[3])), StringComparer.Ordinal);

        return new PresenceOracle(
            Scalar("manifest-hash"),
            Number(Scalar("denominator")),
            Number(Scalar("assemblies")),
            Number(Scalar("methods-analysed")),
            Number(Scalar("total-findings")),
            [.. rows.Where(r => r[0] == "capability").Select(r => new OracleCapability(Enum.Parse<Capability>(r[1]), Number(r[2]), Number(r[3])))],
            [.. rows.Where(r => r[0] == "package").Select(r => new OraclePackage(r[1], r[2], r[3], Number(r[4]), Number(r[5]), Number(r[6]),
                byPackage.GetValueOrDefault(r[1]) ?? new Dictionary<Capability, int>()))]);
    }
    #endregion
}

public sealed record OracleCapability(Capability Capability, int Packages, int Total);

public sealed record OraclePackage(
    string Id, string Version, string Tfm, int Assemblies, int MethodsAnalysed, int Findings, IReadOnlyDictionary<Capability, int> ByCapability);

/// <summary>
/// The regression oracle's outcome. <see cref="Full"/> when the manifest is the oracle's, so the totals are compared; on
/// another manifest only the packages both hold are compared, and <see cref="Match"/> says nothing about the totals.
/// </summary>
public sealed record OracleComparison(bool Full, bool Match, int PackagesCompared, IReadOnlyList<string> Differences);

/// <summary>
/// Aggregation of reachability R2 child results, and the pre-registered E1/E2 decision. Every member is a pure function
/// of its arguments (no clock, no file system), deterministic and ordinal throughout.
/// </summary>
public static class ReachabilityAggregation
{
    #region Methods
    /// <summary>
    /// Refuses results of more than one build: every result must carry <paramref name="identity"/>. The message names
    /// each mismatching package and both identities.
    /// </summary>
    public static void EnsureOneBuild(IEnumerable<PackageReachResult> results, BuildIdentity identity)
    {
        var mismatched = results.Where(r => r.Identity != identity).ToArray();
        if (mismatched.Length > 0)
            throw new MixedBuildException(
                $"Refusing to aggregate results of different builds: this harness is {identity}, but " +
                string.Join("; ", mismatched.Select(r => $"{r.Id} {r.Version} was measured by {r.Identity}")) + ".");
    }

    /// <summary>
    /// The packages of <paramref name="population"/>, in result order:
    /// <list type="bullet">
    /// <item><description>the measured packages (<see cref="PackageReachResult.Measured"/>) with a scoped folder either side
    /// read (<see cref="FolderResult.Read"/>). The scope is the P-lib folder for P-lib, every folder for P-all, restricted
    /// to <paramref name="role"/>'s folders when given. Only folders neither side read are left out, so a package whose
    /// every scoped folder is graph-failed stays in the denominator, as a floor package (spec: "A floor package stays in
    /// its population's denominator");</description></item>
    /// <item><description>the <see cref="PackageReachResult.UnmeasuredFloor"/> packages (crashed, timeout, incomplete), as
    /// floor packages with no folders and unmeasured presence: in P-all always, in P-lib when the <c>.nupkg</c> has a lib
    /// TFM or whether it has one is unknown (the cautious direction). Never in a role view: which roles they hold was not
    /// measured.</description></item>
    /// </list>
    /// </summary>
    public static PopulationView View(IEnumerable<PackageReachResult> results, Population population, string? role = null) =>
        new(population, role, [.. results.Select(r => Unit(r, population, role)).OfType<PackageUnit>()]);

    // One package's unit in a population, or null when it is not in it (see View).
    private static PackageUnit? Unit(PackageReachResult result, Population population, string? role)
    {
        if (result.UnmeasuredFloor)
            return role is null && (population == Population.Pall || result.LibTfmState != LibTfmState.None)
                ? new PackageUnit(result, [], Floor: true, PresenceFloor: true, new HashSet<RootClass>())
                : null;
        if (!result.Measured)
            return null;
        var scope = (population == Population.Plib ? result.PlibFolders : result.Folders)
            .Where(f => f.Read && (role is null || string.Equals(f.Role, role, StringComparison.Ordinal))).ToArray();
        return scope.Length == 0 ? null
            : new PackageUnit(result, scope, scope.Any(f => f.Floor), scope.Any(f => f.PresenceIncomplete),
                scope.SelectMany(f => f.ProfilesTruncatedClasses).ToHashSet());
    }

    /// <summary>The roles of every folder either side read, ordinal.</summary>
    public static IReadOnlyList<string> Roles(IEnumerable<PackageReachResult> results) =>
        [.. results.Where(r => r.Measured).SelectMany(r => r.Folders).Where(f => f.Read).Select(f => f.Role)
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];

    /// <summary>Packages with at least one measured presence finding of <paramref name="capability"/> (any kind) in the view's folders.</summary>
    public static Share Presence(PopulationView view, Capability capability) =>
        new(view.Units.Count(u => u.Folders.Any(f => f.PresenceOf(capability) > 0)), view.Denominator);

    /// <summary>
    /// Packages where a root of <paramref name="class"/> reaches <paramref name="capability"/> (null = Unseen) on
    /// <paramref name="tier"/>: <c>Roots &gt; 0</c> at ChaOnly, <c>Bound &gt; 0</c> at Bound.
    /// </summary>
    public static Share Reach(PopulationView view, RootClass @class, Capability? capability, Tier tier = Tier.ChaOnly) =>
        new(view.Units.Count(u => u.Folders.Any(f => f.ReachOf(@class, capability) is { } r && Count(r, tier) > 0)), view.Denominator);

    /// <summary>
    /// Packages where a root of <paramref name="class"/> reaches <paramref name="capability"/> at <paramref name="label"/>:
    /// <c>Roots &gt; 0</c> at ChaOnly, <c>Direct &gt; 0</c> at Direct.
    /// </summary>
    public static Share Reach(PopulationView view, RootClass @class, Capability? capability, ReachLabel label) =>
        new(view.Units.Count(u => Reaches(u, @class, capability, label)), view.Denominator);

    /// <summary>The roots of <paramref name="class"/> over the view's folders.</summary>
    public static int Roots(PopulationView view, RootClass @class) => view.Units.Sum(u => u.Folders.Sum(f => f.RootsOf(@class)));

    /// <summary>A signal capability is judged only when its presence reaches <see cref="MinimumJudgedPresence"/> packages.</summary>
    public static bool Judged(Share presence) => presence.Count >= MinimumJudgedPresence;

    /// <summary>
    /// E1 for <paramref name="class"/>: a cell per signal capability, each contributing <see cref="E1Cell.Contribution"/>.
    /// Over the judged and possibly judged cells: any Fail fails (only a judged cell can); else any Floor is Floor; else
    /// Pass. With no judged cell, a possibly judged one makes the class Floor (spec, round 3), and none at all is
    /// "nothing judged". Zero roots is "no data", or Floor when a floor package may be hiding roots. At
    /// <paramref name="label"/> Direct the reach (and so the floor packages not already reaching) counts Direct roots only;
    /// presence, the gate and the Bound column (ChaOnly's, informational) are the same at both labels.
    /// </summary>
    public static E1Result E1(PopulationView view, RootClass @class, ReachLabel label = ReachLabel.ChaOnly)
    {
        bool Present(PackageUnit u, Capability c) => u.Folders.Any(f => f.PresenceOf(c) > 0);
        var cells = ReachabilityChild.SignalCapabilities
            .Select(c => (Capability: c, Presence: Presence(view, c)))
            .Select(x => new E1Cell(@class, x.Capability, x.Presence, Reach(view, @class, x.Capability, label), Reach(view, @class, x.Capability, Tier.Bound),
                Judged(x.Presence),
                view.Units.Count(u => u.Floor && !Reaches(u, @class, x.Capability, label)),
                view.Units.Count(u => u.Folders.Any(f => f.PresenceSeenOf(x.Capability) > 0)),
                x.Presence.Count + view.Units.Count(u => u.PresenceFloor && !Present(u, x.Capability))))
            .ToArray();
        var roots = Roots(view, @class);
        var candidates = cells.Select(c => c.Contribution).OfType<Outcome>().ToArray();
        var outcome = roots == 0 ? (view.Units.Any(u => u.Floor) ? Outcome.Floor : Outcome.NoData)
            : candidates.Length == 0 ? Outcome.NothingJudged
            : !cells.Any(c => c.Judged) ? Outcome.Floor
            : candidates.Contains(Outcome.Fail) ? Outcome.Fail
            : candidates.Contains(Outcome.Floor) ? Outcome.Floor
            : Outcome.Pass;
        return new E1Result(@class, roots, cells, outcome, label);
    }

    /// <summary>
    /// E2 for <paramref name="class"/> on the Unseen-inclusive count: Fail when <c>10 x counted &gt; denominator</c>; Pass
    /// only when <c>10 x (counted + floor) &lt;= denominator</c>, the floor packages
    /// (<see cref="PackageUnit.ProfileFloor"/>) not already counted; else Floor. At <paramref name="label"/> Direct a profile
    /// counts by its Direct capability set, and the Unseen split by <see cref="ProfileRecord.DirectUnseen"/>; profiles cut
    /// at 64 are a floor at both labels.
    /// </summary>
    public static E2Result E2(PopulationView view, RootClass @class, ReachLabel label = ReachLabel.ChaOnly)
    {
        IReadOnlyList<Capability> Set(ProfileRecord p) => label == ReachLabel.Direct ? p.DirectCapabilities : p.Capabilities;
        bool Unseen(ProfileRecord p) => label == ReachLabel.Direct ? p.DirectUnseen : p.Unseen;
        bool Composed(ProfileRecord p) => p.Class == @class && Set(p).Distinct().Count(c => ReachabilityChild.SignalCapabilities.Contains(c)) >= 2;
        bool Has(PackageUnit u, Func<ProfileRecord, bool> which) => u.Folders.Any(f => f.Profiles.Any(p => Composed(p) && which(p)));
        Share Packages(Func<ProfileRecord, bool> which) => new(view.Units.Count(u => Has(u, which)), view.Denominator);

        var roots = Roots(view, @class);
        var inclusive = Packages(_ => true);
        var floor = view.Units.Where(u => u.ProfileFloor(@class) && !Has(u, _ => true)).ToArray();
        var outcome = roots == 0 ? (view.Units.Any(u => u.Floor) ? Outcome.Floor : Outcome.NoData)
            : 10 * inclusive.Count > view.Denominator ? Outcome.Fail
            : 10 * (inclusive.Count + floor.Length) <= view.Denominator ? Outcome.Pass
            : Outcome.Floor;
        return new E2Result(@class, roots, inclusive, Packages(p => !Unseen(p)), Packages(Unseen), outcome,
            floor.Length, view.Units.Count(u => u.TruncatedClasses.Contains(@class)), label);
    }

    private static bool Reaches(PackageUnit unit, RootClass @class, Capability? capability, ReachLabel label) =>
        unit.Folders.Any(f => f.ReachOf(@class, capability) is { } r && (label == ReachLabel.Direct ? r.Direct : r.Roots) > 0);

    /// <summary>
    /// The verdict of every trigger class at <paramref name="label"/>, from E1 and E2 in both populations (R2's rule, and
    /// R2b's for the runtime classes). Only <see cref="RuntimeClasses"/> may be read off it in a single run
    /// (<see cref="JudgedInSingleRun"/>); HostContract and LoadTime are judged by <see cref="PallVerdicts"/> in
    /// <c>--combine</c>.
    /// </summary>
    public static IReadOnlyList<ClassVerdict> Verdicts(PopulationView plib, PopulationView pall, ReachLabel label = ReachLabel.ChaOnly) =>
        [.. ReachabilityChild.TriggerClasses.Select(k =>
            new ClassVerdict(k, E1(plib, k, label).Outcome, E2(plib, k, label).Outcome, E1(pall, k, label).Outcome, E2(pall, k, label).Outcome, label))];

    /// <summary>
    /// The P-all-only verdict of <see cref="CombineClasses"/> at <paramref name="label"/> (R2b "Pre-registered expectations"
    /// 2): over <paramref name="pall"/>, the union of C100 and C-build that <c>--combine</c> forms, with one denominator.
    /// </summary>
    public static IReadOnlyList<ClassVerdict> PallVerdicts(PopulationView pall, ReachLabel label) =>
        [.. CombineClasses.Select(k => new ClassVerdict(k, null, null, E1(pall, k, label).Outcome, E2(pall, k, label).Outcome, label))];

    /// <summary>Whether a single <c>--reachability</c> run gives <paramref name="class"/> a verdict: only the runtime classes.</summary>
    public static bool JudgedInSingleRun(RootClass @class) => RuntimeClasses.Contains(@class);

    /// <summary>Q2: per package, a class's roots over its own methods; median and p90 (nearest-rank) over the packages with own methods.</summary>
    public static RootShareStats RootShares(PopulationView view, RootClass @class)
    {
        var shares = view.Units
            .Select(u => (Own: u.Folders.Sum(f => f.OwnMethods), Roots: u.Folders.Sum(f => f.RootsOf(@class))))
            .Where(x => x.Own > 0)
            .Select(x => (double)x.Roots / x.Own)
            .Order()
            .ToArray();
        return new RootShareStats(@class, shares.Length, Median(shares), P90(shares));
    }

    /// <summary>Q3: the class's reached (package, capability) pairs, by the strongest tier any folder reaches them on.</summary>
    public static TierSplit Tiers(PopulationView view, RootClass @class)
    {
        var pairs = view.Units
            .SelectMany(u => Enum.GetValues<Capability>().Select(c => u.Folders.Select(f => f.ReachOf(@class, c)).OfType<ReachRecord>().ToArray()))
            .Where(r => r.Any(x => x.Roots > 0))
            .ToArray();
        var bound = pairs.Count(r => r.Any(x => x.Bound > 0));
        var instantiated = pairs.Count(r => !r.Any(x => x.Bound > 0) && r.Any(x => x.Instantiated > 0));
        return new TierSplit(@class, pairs.Length, bound, instantiated, pairs.Length - bound - instantiated);
    }

    /// <summary>
    /// Q4: packages where the class is Unknown in some folder; per reason category (<see cref="VerdictRecord.Categories"/>), the
    /// packages with an Unknown folder giving it; per end kind of the class's Unseen example paths, the packages with one;
    /// and the packages with load failures, which no verdict includes yet (R3 carry). An unmeasured package
    /// (<see cref="PackageReachResult.UnmeasuredFloor"/>) is Unknown for every class, with the reason
    /// <see cref="UnmeasuredReason"/>.
    /// </summary>
    public static UnknownSplit Unknown(PopulationView view, RootClass @class)
    {
        var unknown = view.Units
            .Select(u => (Unit: u, Folders: u.Folders.Where(f => f.Verdicts.Any(v => v.Class == @class && v.Verdict == RootClassVerdict.Unknown)).ToArray()))
            .Where(x => x.Folders.Length > 0 || x.Unit.Result.UnmeasuredFloor)
            .ToArray();
        var reasons = unknown
            .SelectMany(x => x.Unit.Result.UnmeasuredFloor ? new[] { UnmeasuredReason }
                : x.Folders.SelectMany(f => f.Verdicts.Where(v => v.Class == @class).SelectMany(v => v.Categories)).Distinct(StringComparer.Ordinal))
            .GroupBy(c => c, StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new NamedCount(g.Key, g.Count()))
            .ToArray();
        var ends = view.Units
            .SelectMany(u => u.Folders.SelectMany(f => f.Unseen?.ExampleEnds ?? []).Where(e => e.Class == @class).Select(e => e.End).Distinct(StringComparer.Ordinal))
            .GroupBy(e => e, StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new NamedCount(g.Key, g.Count()))
            .ToArray();
        return new UnknownSplit(@class, new Share(unknown.Length, view.Denominator), reasons, ends,
            view.Units.Count(u => u.Folders.Any(f => f.LoadFailures.Count > 0)));
    }

    /// <summary>
    /// Why no verdict may be read off the run (spec, "No verdict without a comparable population"; review W2), or null
    /// when it is comparable: the oracle must be a full MATCH, and no manifest entry may be <c>not-cached</c>.
    /// </summary>
    public static string? NotComparable(OracleComparison oracle, int notCached)
    {
        var why = new List<string>();
        if (!oracle.Full)
            why.Add("oracle not applicable: another manifest");
        else if (!oracle.Match)
            why.Add("oracle MISMATCH");
        if (notCached > 0)
            why.Add($"not-cached {notCached}");
        return why.Count == 0 ? null : $"not comparable ({string.Join("; ", why)})";
    }

    /// <summary>Q5: the parity of every loaded folder, in package then folder order.</summary>
    public static IReadOnlyList<FolderParity> Parity(IEnumerable<PackageReachResult> results) =>
        [.. results.Where(r => r.Measured)
            .OrderBy(r => r.Id, StringComparer.Ordinal).ThenBy(r => r.Version, StringComparer.Ordinal)
            .SelectMany(r => r.BuiltFolders.Where(f => f.Parity is not null).OrderBy(f => f.Folder, StringComparer.Ordinal)
                .Select(f => new FolderParity(r.Id, r.Version, f.Folder, f.Parity!)))];

    /// <summary>Section 11: every trigger-class x signal-capability reach of every loaded folder, with its first example.</summary>
    public static IReadOnlyList<Evidence> TriggerEvidence(IEnumerable<PackageReachResult> results) =>
        [.. results.Where(r => r.Measured)
            .SelectMany(r => r.BuiltFolders.SelectMany(f => f.Examples.Select(e => new Evidence(r.Id, r.Version, f.Folder, f.Role, f.IsPlib, e,
                f.ReachOf(e.Class, e.Capability) is { Direct: > 0 }))))
            .OrderBy(e => e.Example.Class).ThenBy(e => e.Example.Capability)
            .ThenBy(e => e.Package, StringComparer.Ordinal).ThenBy(e => e.Version, StringComparer.Ordinal)
            .ThenBy(e => e.Folder, StringComparer.Ordinal).ThenBy(e => e.Example.Root, StringComparer.Ordinal)];

    /// <summary>
    /// The regression oracle: P-lib presence, every finding kind, over the P-lib folders' <c>.dll</c> members (the
    /// baseline scanned <c>lib/&lt;tfm&gt;/*.dll</c>), against <paramref name="oracle"/>. On the oracle's manifest
    /// (<paramref name="manifestHash"/>) the denominator, assembly, method and finding totals, the per-capability package
    /// counts and totals, and every package are compared; on another manifest, only the packages both hold. An unmeasured
    /// P-lib package (crashed, timeout, incomplete) is a difference: its presence cannot reproduce the baseline.
    /// </summary>
    public static OracleComparison CompareOracle(PresenceOracle oracle, PopulationView plib, string manifestHash)
    {
        var full = string.Equals(manifestHash, oracle.ManifestHash, StringComparison.Ordinal);
        var measured = plib.Units.Select(u => (u.Result, Dlls: u.Folders.SelectMany(f => f.Presence)
                .Where(p => p.Ok && p.Assembly.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).ToArray()))
            .ToDictionary(x => (x.Result.Id, x.Result.Version));
        var expected = oracle.Packages.ToDictionary(p => (p.Id, p.Version));
        var differences = new List<string>();

        void Check<T>(string what, T want, T got)
        {
            if (!EqualityComparer<T>.Default.Equals(want, got))
                differences.Add($"{what}: expected {want}, measured {got}");
        }

        if (full)
        {
            Check("denominator (P-lib packages)", oracle.Denominator, measured.Count);
            Check("assemblies scanned", oracle.Assemblies, measured.Values.Sum(m => m.Dlls.Length));
            Check("methods analysed", oracle.MethodsAnalysed, measured.Values.Sum(m => m.Dlls.Sum(d => d.MethodsAnalyzed)));
            Check("total findings", oracle.TotalFindings, measured.Values.Sum(m => m.Dlls.Sum(d => d.Findings.Sum(f => f.Findings))));
            foreach (var c in oracle.Capabilities)
            {
                Check($"{c.Capability} packages", c.Packages, measured.Values.Count(m => m.Dlls.Sum(d => d.Of(c.Capability)) > 0));
                Check($"{c.Capability} findings", c.Total, measured.Values.Sum(m => m.Dlls.Sum(d => d.Of(c.Capability))));
            }
            differences.AddRange(expected.Keys.Except(measured.Keys).Select(k => $"{k.Id} {k.Version}: in the baseline, not in P-lib"));
            differences.AddRange(measured.Keys.Except(expected.Keys).Select(k => $"{k.Id} {k.Version}: in P-lib, not in the baseline"));
        }

        var common = expected.Keys.Intersect(measured.Keys).OrderBy(k => k.Id, StringComparer.Ordinal).ThenBy(k => k.Version, StringComparer.Ordinal).ToArray();
        foreach (var key in common)
        {
            var (want, got) = (expected[key], measured[key]);
            var name = $"{key.Id} {key.Version}";
            if (got.Result.UnmeasuredFloor)
            {
                differences.Add($"{name}: {got.Result.Status}, presence not measured");
                continue;
            }
            Check($"{name} TFM", want.Tfm, got.Result.LibTfm ?? "-");
            Check($"{name} assemblies", want.Assemblies, got.Dlls.Length);
            Check($"{name} methods analysed", want.MethodsAnalysed, got.Dlls.Sum(d => d.MethodsAnalyzed));
            foreach (var c in Enum.GetValues<Capability>())
                Check($"{name} {c} findings", want.ByCapability.GetValueOrDefault(c), got.Dlls.Sum(d => d.Of(c)));
        }

        return new OracleComparison(full, differences.Count == 0, common.Length, [.. differences.Order(StringComparer.Ordinal)]);
    }

    /// <summary>Median of an <b>ascending</b> list (mean of the two middles when even); 0 for an empty one.</summary>
    public static double Median(IReadOnlyList<double> ascending) =>
        ascending.Count == 0 ? 0
        : ascending.Count % 2 == 1 ? ascending[ascending.Count / 2]
        : (ascending[ascending.Count / 2 - 1] + ascending[ascending.Count / 2]) / 2.0;

    /// <summary>Nearest-rank p90 of an <b>ascending</b> list; 0 for an empty one.</summary>
    public static double P90(IReadOnlyList<double> ascending) =>
        ascending.Count == 0 ? 0 : ascending[Math.Min(ascending.Count - 1, (int)Math.Ceiling(0.9 * ascending.Count) - 1)];

    private static int Count(ReachRecord reach, Tier tier) => tier switch
    {
        Tier.Bound => reach.Bound,
        Tier.Instantiated => reach.Instantiated,
        _ => reach.Roots,
    };
    #endregion

    #region Fields
    /// <summary>Spec: a signal capability is judged in a population only when presence is at least 3 packages there.</summary>
    public const int MinimumJudgedPresence = 3;

    /// <summary>Both labels, in report order.</summary>
    public static readonly ReachLabel[] Labels = [ReachLabel.ChaOnly, ReachLabel.Direct];

    /// <summary>The trigger classes judged on the single C100 run, in P-lib and P-all, passing only when both pass (R2b 2).</summary>
    public static readonly RootClass[] RuntimeClasses = [RootClass.TypeInitializer, RootClass.Finalizer, RootClass.NativeEntry];

    /// <summary>The trigger classes judged on P-all only, over C100 and C-build, by <c>--combine</c> alone (R2b 2).</summary>
    public static readonly RootClass[] CombineClasses = [RootClass.LoadTime, RootClass.HostContract];

    /// <summary>Q4's reason for a package whose child crashed, timed out or stopped short: every class is Unknown there.</summary>
    public const string UnmeasuredReason = "unmeasured (crashed/timeout/incomplete)";
    #endregion
}
