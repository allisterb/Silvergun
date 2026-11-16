namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;

/// <summary>
/// One co-reach cell in one package (<c>docs/agent/tasks/recall-levers-1.md</c> §1): <paramref name="Class"/> reaches
/// <paramref name="Collection"/> and Network together, at <paramref name="Label"/> (<c>Direct</c> or <c>Deferred</c>).
/// <paramref name="Roots"/> sums the roots of its statements over the folders. <paramref name="Floor"/>: the "no" of an
/// unfired cell cannot be trusted here (see <see cref="LeversMeasure.Of"/>).
/// </summary>
public sealed record LeversCell(string Class, string Collection, string Label, bool Fired, int Roots, bool Floor);

/// <summary>One value signal in one package: its <paramref name="Sites"/> over the folders, and whether any folder's SSA was incomplete or absent.</summary>
public sealed record LeversSignalRow(string Signal, int Sites, bool Floor);

/// <summary>One site the summary lists with a signal: escaped and bounded as the summary made it.</summary>
public sealed record LeversExample(string Folder, string Signal, string Caller, string Callee, string Call);

/// <summary>
/// One package's <c>--levers</c> result, cached in the results directory. <see cref="Status"/> is "ok" or why there is no
/// report (every cell and signal is then a floor). <see cref="ConstantSinks"/> is the <c>--ssa</c> table's own rule (key
/// <c>Capability\tCalleeKey</c>: Analyzed sites with a Constant or OneOf argument), so folding's effect is a diff against
/// a committed <c>-constant-sinks.tsv</c>.
/// </summary>
public sealed record LeversPackageResult(
    int Schema,
    string Package,
    string Identity,
    string Configuration,
    string Status,
    long WallMs,
    int Folders,
    int StatementsDropped,
    List<LeversCell> Cells,
    List<LeversSignalRow> Signals,
    List<LeversExample> Examples,
    Dictionary<string, int> ConstantSinks);

/// <summary>
/// <c>--levers</c> (<c>docs/agent/tasks/recall-levers-1.md</c>, L2): per cached package, one
/// <see cref="PackageReachability.Analyze(NuGetPackage, PackageReachabilityOptions?)"/> pass through the real CLI worker beside
/// this harness with SSA on, then <see cref="ReachabilitySummary.From"/>; what the summary says of each co-reach cell and
/// value signal is the result, cached per package and reused, and the report is written once every manifest entry has one.
/// Offline: it never constructs a package cache.
/// </summary>
public static class LeversMeasure
{
    #region Properties
    /// <summary>The build configuration of this harness, and so of the worker and libraries beside it.</summary>
    public static string Configuration { get; } =
        typeof(LeversMeasure).Assembly.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration ?? "unknown";

    /// <summary>The presented classes, in the presentation's order.</summary>
    public static IReadOnlyList<RootClass> Classes { get; } =
        [RootClass.TypeInitializer, RootClass.Finalizer, RootClass.NativeEntry, RootClass.HostContract, RootClass.LoadTime];

    /// <summary>The capabilities a co-reach statement pairs with Network.</summary>
    public static IReadOnlyList<Capability> Collections { get; } = [Capability.EnvironmentProbe, Capability.FileSystem];
    #endregion

    #region Methods
    /// <summary>
    /// Measures the packages without a result (at most <paramref name="maxPackages"/>, none started after
    /// <paramref name="maxTime"/>), then reports when all have one. A result of another build is refused; one of an older
    /// schema is measured again.
    /// </summary>
    public static (IReadOnlyList<string> Paths, int Pending, int NotCached, int Problems) Run(
        CorpusManifest manifest, string cacheRoot, string results, string outputDirectory,
        DateOnly date, string identity, int maxPackages, TimeSpan maxTime, TextWriter progress,
        Func<string, string, LeversPackageResult>? measure = null)
    {
        Directory.CreateDirectory(results);
        measure ??= (name, nupkg) => Measure(name, nupkg, identity);
        var done = new List<LeversPackageResult>();
        var (pending, notCached, measured) = (0, 0, 0);
        var clock = Stopwatch.StartNew();
        foreach (var (entry, number) in manifest.Entries.Select((e, i) => (e, i + 1)))
        {
            var name = $"{entry.Id} {entry.Version}";
            var path = PathOf(results, entry);
            if (File.Exists(path))
            {
                var cached = JsonSerializer.Deserialize<LeversPackageResult>(File.ReadAllText(path), PackageReachResult.JsonOptions)!;
                if (cached.Identity != identity)
                    throw new InvalidOperationException($"{path} is from another build ({cached.Identity}, not {identity}); use another --results directory.");
                if (cached.Schema == CurrentSchema)
                {
                    done.Add(cached);
                    continue;
                }
            }
            var nupkg = CachedNupkg.PathOf(cacheRoot, entry);
            if (!File.Exists(nupkg))
            {
                notCached++;
                continue;
            }
            if (measured >= maxPackages || clock.Elapsed >= maxTime)
            {
                pending++;
                continue;
            }

            progress.Write($"[{number}/{manifest.Entries.Count}] {name} ... ");
            var result = measure(name, nupkg);
            PackageReachResult.WriteAtomically(path, JsonSerializer.Serialize(result, PackageReachResult.JsonOptions));
            done.Add(result);
            measured++;
            // The package's report is garbage now; give the memory back before the next, so the guard sees one package's peak.
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            progress.WriteLine($"{result.Status} {result.WallMs} ms; folders {result.Folders}; co-reach fired {result.Cells.Count(c => c.Fired)}; signal sites {result.Signals.Sum(s => s.Sites)}");
        }

        if (pending > 0 || notCached > 0)
            return ([], pending, notCached, 0);
        var (paths, problems) = LeversReport.Write(manifest, cacheRoot, results, outputDirectory, date, identity, done);
        return (paths, 0, 0, problems);
    }

    /// <summary>Where <paramref name="entry"/>'s result is cached under <paramref name="results"/>.</summary>
    public static string PathOf(string results, ManifestEntry entry) => Path.Combine(results, $"{entry.Id}.{entry.Version}.levers.json");

    /// <summary>
    /// What one package's report says. <paramref name="report"/> null: there was none, and everything is a floor.
    /// <list type="bullet">
    /// <item><description>A cell fires when some folder's summary has a co-reach statement of its class, collection and
    /// label; roots sum over folders (a SameAs copy lists none). Its floor: some folder was not analysed, or the summary
    /// dropped statements, or some analysed folder had its class Unknown or its profiles cut for it.</description></item>
    /// <item><description>A signal's sites sum the folders' counts (listed or not). Its floor: some folder has no SSA facts or
    /// SSA left it incomplete (<see cref="FolderSsaSummary.Incomplete"/>).</description></item>
    /// </list>
    /// </summary>
    public static LeversPackageResult Of(string package, string identity, string status, long wallMs, PackageReachabilityReport? report)
    {
        if (report is null)
            return new(CurrentSchema, package, identity, Configuration, status, wallMs, 0, 0,
                [.. CellKeys().Select(k => new LeversCell(k.Class.ToString(), k.Collection.ToString(), k.Label, false, 0, true))],
                [.. Enum.GetValues<SsaSignal>().Select(s => new LeversSignalRow(s.ToString(), 0, true))], [], []);

        var summary = ReachabilitySummary.From(report);
        var folders = summary.Folders;
        var anyNotAnalysed = folders.Any(f => f.Outcome != FolderOutcome.Analyzed);
        bool ClassFloor(RootClass cls) =>
            anyNotAnalysed || summary.StatementsDropped > 0
            || folders.Any(f => f.Outcome == FolderOutcome.Analyzed
                && (f.Classes.Any(c => c.Class == cls && c.Verdict == RootClassVerdict.Unknown)
                    || f.Notes.Any(n => n.StartsWith($"{cls}: more capability sets", StringComparison.Ordinal))));

        var cells = CellKeys().Select(k =>
        {
            var statements = folders.SelectMany(f => f.Statements)
                .Where(s => s.Class == k.Class && s.Capability == k.Collection && s.With == Capability.Network && s.Direct == (k.Label == DirectLabel))
                .ToArray();
            return new LeversCell(k.Class.ToString(), k.Collection.ToString(), k.Label, statements.Length > 0, statements.Sum(s => s.Roots), ClassFloor(k.Class));
        }).ToList();

        var signalFloor = folders.Any(f => f.Ssa is null || f.Ssa.Incomplete());
        var signals = Enum.GetValues<SsaSignal>()
            .Select(s => new LeversSignalRow(s.ToString(), folders.Sum(f => f.Ssa?.Signals?.OfType<SsaSignalCount>().Where(c => c.Signal == s).Sum(c => c.Sites) ?? 0), signalFloor))
            .ToList();

        var examples = folders
            .SelectMany(f => (f.Ssa?.Sites ?? []).OfType<SsaSiteSummary>().Where(s => s.Signals is { Count: > 0 })
                .SelectMany(s => s.Signals!.Select(g => new LeversExample(Program.Redact(f.Folder), g.ToString(), Program.Redact(s.Caller), Program.Redact(s.Callee), Program.Redact(s.Call)))))
            .ToList();

        return new(CurrentSchema, package, identity, Configuration, status, wallMs, folders.Count, summary.StatementsDropped, cells, signals, examples, ConstantSinks(report));
    }

    // The --ssa table's rule: per folder, Analyzed sites with a Constant or OneOf argument, by "Capability<TAB>CalleeKey".
    private static Dictionary<string, int> ConstantSinks(PackageReachabilityReport report) =>
        report.Folders.Where(f => f is not null)
            .SelectMany(f => f.Ssa?.Facts?.Sites ?? [])
            .Where(s => s.Status == SsaSiteStatus.Analyzed && s.Arguments.Any(a => a.Kind is SsaValueKind.Constant or SsaValueKind.OneOf))
            .GroupBy(s => $"{s.Site.Capability}\t{s.Site.CalleeKey}", StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

    private static IEnumerable<(RootClass Class, Capability Collection, string Label)> CellKeys() =>
        from cls in Classes
        from collection in Collections
        from label in new[] { DirectLabel, DeferredLabel }
        select (cls, collection, label);

    private static LeversPackageResult Measure(string name, string nupkg, string identity)
    {
        var opened = NuGetPackage.Open(nupkg);
        if (!opened.IsSuccess)
            return Of(name, identity, "open-failed", 0, null);
        using var package = opened.Value;
        var clock = Stopwatch.StartNew();
        var report = PackageReachability.Analyze(package, PackageReachabilityOptions.Default with { Ssa = SsaFactBounds.Default });
        return Of(name, identity, "ok", clock.ElapsedMilliseconds, report);
    }
    #endregion

    #region Fields
    /// <summary>The cached result's layout; one of another is measured again.</summary>
    public const int CurrentSchema = 1;

    public const string DirectLabel = "Direct";

    public const string DeferredLabel = "Deferred";
    #endregion
}
