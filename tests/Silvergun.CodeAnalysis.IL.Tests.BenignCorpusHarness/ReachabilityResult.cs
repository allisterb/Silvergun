namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// What identifies the build that produced a result: <see cref="Commit"/> is <c>git describe --always --dirty --abbrev=40</c>
/// (the HEAD commit, suffixed <c>-dirty</c> when the working tree has changes), read at run time by the parent, and a
/// SHA-256 over every top-level <c>.dll</c> of the harness's output directory (the harness, the <c>src</c> and <c>ext</c>
/// assemblies it references, and their packages). Results of two identities are never aggregated together.
/// </summary>
public sealed record BuildIdentity(string Commit, string AssembliesSha256)
{
    #region Methods
    public override string ToString() => $"commit {Commit}, assemblies {AssembliesSha256}";
    #endregion
}

/// <summary>An assembly of a folder that could not be loaded into its graph.</summary>
public sealed record LoadFailureRecord(string RelativePath, string Reason);

/// <summary>A count per name: an opacity kind, a capability, and the like.</summary>
public sealed record NamedCount(string Name, int Count);

/// <summary>A root gap of the facts (<see cref="RootGap"/>), by value.</summary>
public sealed record GapRecord(string Assembly, RootClass Class, string Reason);

/// <summary>
/// The coverage summary of one folder's graph: <see cref="GraphCoverage"/> flattened, the opacity records by kind, the
/// InternalCall, ComImport and NativeImport fact counts, and the facts' gaps.
/// </summary>
public sealed record CoverageRecord(
    bool Truncated,
    string? TruncatedBy,
    bool IndexComplete,
    int AssembliesUnreadable,
    int TypesSkipped,
    int IndexMethodsSkipped,
    int ForwardersUnreadable,
    int SupertypesUnresolved,
    int MethodsIndexed,
    int BodiesRead,
    int BodiesFailed,
    int CallSites,
    int DispatchSites,
    int DispatchEdges,
    int TokenSites,
    int ModuleInitializers,
    int RenamedImplementations,
    int ModulesUnreadable,
    IReadOnlyList<NamedCount> Opacities,
    int InternalCallMethods,
    int ComImportMethods,
    int NativeImportMethods,
    IReadOnlyList<GapRecord> Gaps);

/// <summary>
/// Q4's split of the <c>Unseen</c> sink: the distinct node sites of each opacity kind that makes a node unseen, the own
/// InternalCall nodes, the external nodes the map marks <c>unanalyzed</c>, and, per root class, how its Unseen example
/// paths end (<c>opacity:&lt;Kind&gt;</c>, <c>internal-call</c> or <c>unanalyzed</c>).
/// </summary>
public sealed record UnseenBreakdown(
    IReadOnlyList<NamedCount> OpacitySites,
    int InternalCallNodes,
    int UnanalyzedExternals,
    IReadOnlyList<UnseenEnd> ExampleEnds);

/// <summary>How many of one class's Unseen example paths end at one kind of unseen code.</summary>
public sealed record UnseenEnd(RootClass Class, string End, int Count);

/// <summary>The roots of one class in a folder.</summary>
public sealed record ClassCount(RootClass Class, int Roots);

/// <summary>One <see cref="CapabilityReach"/> by value; a null <see cref="Capability"/> is the Unseen sink.</summary>
public sealed record ReachRecord(RootClass Class, Capability? Capability, int Roots, int Bound, int Instantiated);

/// <summary>
/// One class's verdict and reasons (<see cref="RootClassStatus"/>), and the reasons' categories, computed by the child
/// from structured data (<see cref="ReachabilityChild.CategoriesOf"/>), never by parsing the reason text.
/// </summary>
public sealed record VerdictRecord(RootClass Class, RootClassVerdict Verdict, IReadOnlyList<string> Reasons, IReadOnlyList<string> Categories);

/// <summary>One <see cref="ReachProfile"/> by value.</summary>
public sealed record ProfileRecord(RootClass Class, IReadOnlyList<Capability> Capabilities, bool Unseen, int Roots, string ExampleRoot);

/// <summary>A list capped at <see cref="ReachabilityChild.MaxListed"/> items, with its true count.</summary>
public sealed record CappedList(int Count, IReadOnlyList<string> Items);

/// <summary>Presence parity (ADR 0037 decision 9) for one folder, as <c>PresenceParityTests</c> computes it.</summary>
public sealed record ParityRecord(int Matched, CappedList NameShadowed, CappedList ScannerOnly, CappedList GraphOnly)
{
    #region Properties
    /// <summary><c>EXACT</c>, <c>NAMED</c> (only the NameShadowed gap) or <c>DIFFERS</c> (an unexplained difference).</summary>
    [JsonIgnore]
    public string Verdict =>
        ScannerOnly.Count > 0 || GraphOnly.Count > 0 ? "DIFFERS" : NameShadowed.Count > 0 ? "NAMED" : "EXACT";
    #endregion
}

/// <summary>The number of findings of one capability and kind.</summary>
public sealed record PresenceCount(Capability Capability, ApiCallKind Kind, int Findings);

/// <summary>The presence scan (<see cref="CapabilityAnalysis"/>) of one assembly of a folder: every finding kind.</summary>
public sealed record AssemblyPresence(
    string Assembly, bool Ok, string? Failure, int MethodsAnalyzed, int MethodsSkipped, IReadOnlyList<PresenceCount> Findings)
{
    #region Methods
    /// <summary>The findings of <paramref name="capability"/>, all kinds.</summary>
    public int Of(Capability capability) => Findings.Where(f => f.Capability == capability).Sum(f => f.Findings);
    #endregion
}

/// <summary>One hop of an example path (<see cref="ReachHop"/>).</summary>
public sealed record HopRecord(string NodeId, string? Assembly, MethodEdgeKind? Via, uint Offset);

/// <summary>The first example path of one trigger-class x signal-capability reach (<see cref="ReachPath"/>).</summary>
public sealed record ExampleRecord(
    RootClass Class, Capability Capability, string Root, ReachEvidence Evidence, int Length, bool Truncated,
    OpacityKind? EndsInOpacity, IReadOnlyList<HopRecord> Hops);

/// <summary>Everything measured about one folder of a package. Deterministic: no time, no path outside the package.</summary>
public sealed record FolderResult(
    string Folder,
    string Role,
    bool IsPlib,
    IReadOnlyList<string> Assemblies,
    IReadOnlyList<LoadFailureRecord> LoadFailures,
    bool GraphBuilt,
    CoverageRecord? Coverage,
    int OwnMethods,
    IReadOnlyList<ClassCount> RootCounts,
    int PublicContractOnly,
    int HiddenOnly,
    IReadOnlyList<ReachRecord> Reaches,
    IReadOnlyList<VerdictRecord> Verdicts,
    IReadOnlyList<ProfileRecord> Profiles,
    IReadOnlyList<RootClass> ProfilesTruncatedClasses,
    bool ReachPartial,
    string? PartialReason,
    int EdgesIgnored,
    ParityRecord? Parity,
    IReadOnlyList<AssemblyPresence> Presence,
    UnseenBreakdown? Unseen,
    IReadOnlyList<ExampleRecord> Examples)
{
    #region Properties
    /// <summary>
    /// The assemblies presence scanned cleanly but the graph never loaded: their capabilities count in presence and can
    /// reach nothing, so this folder's reach numbers are a floor (instrument review W1).
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<string> PresenceOnly =>
        [.. Presence.Where(p => p.Ok && !Assemblies.Contains(p.Assembly, StringComparer.Ordinal)).Select(p => p.Assembly)];

    /// <summary>
    /// The assemblies the graph loaded whose presence scan failed (or is missing): their presence could not be measured,
    /// so this folder's presence is a floor (instrument review round 2).
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<string> PresenceUnmeasured =>
        [.. Assemblies.Where(a => !Presence.Any(p => p.Ok && string.Equals(p.Assembly, a, StringComparison.Ordinal)))];

    /// <summary>A folder with no graph whose presence scan still read an assembly: <see cref="PackageReachResult.GraphFailed"/>.</summary>
    [JsonIgnore]
    public bool GraphFailed => !GraphBuilt && Presence.Any(p => p.Ok);

    /// <summary>Either side read it: the graph loaded an assembly, or presence scanned one. Only such folders are in a population.</summary>
    [JsonIgnore]
    public bool Read => GraphBuilt || Presence.Any(p => p.Ok);

    /// <summary>The assemblies presence scanned only partly (<c>MethodsSkipped &gt; 0</c>): their presence is a floor (review round 3).</summary>
    [JsonIgnore]
    public IReadOnlyList<string> PresencePartial => [.. Presence.Where(p => p.Ok && p.MethodsSkipped > 0).Select(p => p.Assembly)];

    /// <summary>Some of this folder's presence could not be measured, or only partly: an unmeasured or a partial scan.</summary>
    [JsonIgnore]
    public bool PresenceIncomplete => PresenceUnmeasured.Count > 0 || PresencePartial.Count > 0;

    /// <summary>
    /// A floor folder (spec, "Floor"): reachability Partial, an assembly only presence saw (a graph-failed folder
    /// included), an assembly only the graph loaded, or an assembly presence scanned only partly.
    /// </summary>
    [JsonIgnore]
    public bool Floor => ReachPartial || PresenceOnly.Count > 0 || PresenceIncomplete;
    #endregion

    #region Methods
    /// <summary>The roots of <paramref name="class"/> in this folder.</summary>
    public int RootsOf(RootClass @class) => RootCounts.Where(c => c.Class == @class).Sum(c => c.Roots);

    /// <summary>The reach of <paramref name="class"/> to <paramref name="capability"/> (null = Unseen), if any.</summary>
    public ReachRecord? ReachOf(RootClass @class, Capability? capability) =>
        Reaches.FirstOrDefault(r => r.Class == @class && r.Capability == capability);

    /// <summary>The presence findings of <paramref name="capability"/> over this folder's assemblies, all kinds.</summary>
    public int PresenceOf(Capability capability) => Presence.Sum(p => p.Of(capability));

    /// <summary>The presence findings of <paramref name="capability"/> in the assemblies the graph loaded.</summary>
    public int PresenceSeenOf(Capability capability) =>
        Presence.Where(p => Assemblies.Contains(p.Assembly, StringComparer.Ordinal)).Sum(p => p.Of(capability));
    #endregion
}

/// <summary>What one folder cost to measure. Never part of the deterministic report.</summary>
public sealed record FolderCost(string Folder, long BuildMs, long AnalyzeMs, long PresenceMs, long WorkingSetAfterBytes);

/// <summary>What one package cost to measure. Never part of the deterministic report.</summary>
public sealed record PackageCost(long ChildWallMs, long ChildTotalMs, long OpenMs, long PeakWorkingSetBytes, IReadOnlyList<FolderCost> Folders)
{
    #region Properties
    public static PackageCost None { get; } = new(0, 0, 0, 0, []);
    #endregion
}

/// <summary>
/// The child's payload: the lib TFM chosen by <see cref="TfmSelection"/> (null when none), the lib TFMs on offer, every
/// folder, and the cost.
/// </summary>
public sealed record ChildPayload(string? LibTfm, IReadOnlyList<string> LibTfms, IReadOnlyList<FolderResult> Folders, PackageCost Cost);

/// <summary>
/// One manifest entry's reachability result, as cached in <c>--results</c>: the status, the build identity, and the
/// child's payload. <see cref="Status"/> is one of the <c>const</c>s below.
/// </summary>
public sealed record PackageReachResult(
    int Schema,
    string Id,
    string Version,
    string Status,
    string? Detail,
    int? ExitCode,
    BuildIdentity Identity,
    string? LibTfm,
    IReadOnlyList<string> LibTfms,
    IReadOnlyList<FolderResult> Folders,
    PackageCost Cost)
{
    #region Properties
    /// <summary>A child measured it: <see cref="Scanned"/> or <see cref="GraphFailed"/>, the statuses whose folders are read.</summary>
    [JsonIgnore]
    public bool Measured => Status is Scanned or GraphFailed;

    /// <summary>The folders with a loaded assembly.</summary>
    [JsonIgnore]
    public IEnumerable<FolderResult> BuiltFolders => Folders.Where(f => f.GraphBuilt);

    /// <summary>The P-lib folder(s): <c>lib/</c> + <see cref="TfmSelection"/>'s choice, normally one.</summary>
    [JsonIgnore]
    public IEnumerable<FolderResult> PlibFolders => Folders.Where(f => f.IsPlib);
    #endregion

    #region Methods
    /// <summary>A result with no child payload: not-cached, crashed, timeout, incomplete.</summary>
    public static PackageReachResult Without(ManifestEntry entry, string status, string detail, int? exitCode, BuildIdentity identity, PackageCost? cost = null) =>
        new(CurrentSchema, entry.Id, entry.Version, status, detail, exitCode, identity, null, [], [], cost ?? PackageCost.None);

    /// <summary>
    /// The result of a child that finished: <see cref="GraphFailed"/> when a folder has no graph but presence read one of
    /// its assemblies; else <see cref="Scanned"/> when any folder loaded an assembly; else <see cref="NoAssemblies"/>
    /// (neither side loaded anything). Any assembly only presence saw is named in the detail.
    /// </summary>
    public static PackageReachResult From(ManifestEntry entry, ChildPayload payload, BuildIdentity identity, long wallMs)
    {
        var status = payload.Folders.Any(f => f.GraphFailed) ? GraphFailed
            : payload.Folders.Any(f => f.GraphBuilt) ? Scanned
            : NoAssemblies;
        var presenceOnly = payload.Folders.Sum(f => f.PresenceOnly.Count);
        var detail = status == NoAssemblies
            ? payload.Folders.Count == 0 ? "the package ships no .dll or .exe"
                : $"{payload.Folders.Sum(f => f.LoadFailures.Count)} binar(ies) in {payload.Folders.Count} folder(s), none loadable as a managed assembly"
            : presenceOnly > 0 ? PresenceOnlyText(presenceOnly)
            : null;
        return new(CurrentSchema, entry.Id, entry.Version, status, detail, 0, identity, payload.LibTfm, payload.LibTfms, payload.Folders,
            payload.Cost with { ChildWallMs = wallMs });
    }

    /// <summary>The wording W1 asks for, in the detail and section 12.</summary>
    public static string PresenceOnlyText(int count) => $"{count} assembl(ies) scanned by presence but not in the graph";

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public static PackageReachResult FromJson(string json) =>
        JsonSerializer.Deserialize<PackageReachResult>(json, JsonOptions) ?? throw new InvalidDataException("empty result");

    /// <summary>The result file of <paramref name="entry"/> under <paramref name="resultsDir"/>.</summary>
    public static string PathOf(string resultsDir, ManifestEntry entry) => Path.Combine(resultsDir, $"{entry.Id}.{entry.Version}.json");

    /// <summary>Writes <paramref name="text"/> with <c>\n</c> line ends and no BOM, through a temp file so a half-written file is never read.</summary>
    public static void WriteAtomically(string path, string text)
    {
        var temp = path + ".partial";
        File.WriteAllText(temp, text.Replace("\r\n", "\n", StringComparison.Ordinal), new UTF8Encoding(false));
        File.Move(temp, path, overwrite: true);
    }
    #endregion

    #region Fields
    public const int CurrentSchema = 2;

    public const string Scanned = "scanned";
    public const string GraphFailed = "graph-failed";
    public const string NoAssemblies = "no-assemblies";
    public const string Crashed = "crashed";
    public const string Timeout = "timeout";
    public const string Incomplete = "incomplete";
    public const string NotCached = "not-cached";

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };
    #endregion
}
