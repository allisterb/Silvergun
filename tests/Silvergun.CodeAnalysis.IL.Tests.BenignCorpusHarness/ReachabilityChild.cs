namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

using global::NuGet.Packaging;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// The child half of <c>--reachability</c> (reachability R2): measures <b>one</b> cached <c>.nupkg</c> in its own process
/// (ADR-0021: a CCI <c>FailFast</c> costs one package, not the run). It opens the package with
/// <see cref="NuGetPackage.Open"/> (offline: a temp extraction, no network), walks <see cref="PackageGraphs.Build(NuGetPackage, GraphBudget?, CapabilityMap?)"/>
/// one folder at a time, and per folder runs <see cref="Reachability.Analyze"/>, the presence scan
/// (<see cref="CapabilityAnalysis"/> over each of the folder's assemblies) and <see cref="ReachabilityParity"/>.
/// <para>
/// Protocol: <c>&lt;harness&gt; reach &lt;nupkg&gt; &lt;out-json&gt;</c> writes a <see cref="ChildPayload"/> to
/// <c>out-json</c>, then prints <c>DONE</c>. Exit codes: 0 done; 1 a catchable failure (the package did not open, a
/// managed exception); 2 bad usage. Never 35 on purpose, so a <c>FailFast</c> is told apart by exit code alone.
/// </para>
/// </summary>
public static class ReachabilityChild
{
    #region Methods
    /// <summary>Child entry point, dispatched from <see cref="Program.Main"/>.</summary>
    public static int Execute(string[] args)
    {
        try
        {
            if (args.Length != 3)
            {
                Console.Error.WriteLine($"USAGE: <harness> {Verb} <nupkg> <out-json>");
                return 2;
            }

            // Null logging: a library warning must not pollute the stdout protocol.
            Runtime.Initialize("Silvergun", "CORPUS");
            var payload = Measure(args[1], dir => Console.Error.WriteLine($"{ExtractionMarker}\t{dir}"));
            PackageReachResult.WriteAtomically(args[2], System.Text.Json.JsonSerializer.Serialize(payload, PackageReachResult.JsonOptions));
            Console.WriteLine("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAILED {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Measures the package at <paramref name="nupkgPath"/>. In-process and unguarded against <c>FailFast</c>: the parent
    /// only ever calls it in a child. Throws when the package cannot be opened. <paramref name="reportExtraction"/> is
    /// told the package's extraction directory as soon as it exists.
    /// </summary>
    public static ChildPayload Measure(string nupkgPath, Action<string>? reportExtraction = null)
    {
        var total = Stopwatch.StartNew();

        // The same file list and rule the default mode applies (PackageCache.AcquireAsync), so P-lib is its folder.
        TfmChoice choice;
        using (var reader = new PackageArchiveReader(nupkgPath))
            choice = TfmSelection.Choose(reader.GetFiles());

        var open = Stopwatch.StartNew();
        var opened = NuGetPackage.Open(nupkgPath);
        if (!opened.IsSuccess)
            throw new InvalidOperationException($"the package could not be opened: {opened.Message}");
        var openMs = open.ElapsedMilliseconds;

        using var package = opened.Value;
        // Told to the parent, so that if this process dies before Dispose deletes it, the parent removes exactly this
        // directory (instrument review N6). Console.Error autoflushes, so the line survives a FailFast.
        reportExtraction?.Invoke(package.ExtractionDir);
        var fullPaths = package.Assemblies
            .GroupBy(a => a.RelativePath, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().FullPath, StringComparer.Ordinal);

        var folders = new List<FolderResult>();
        var costs = new List<FolderCost>();
        using (var graphs = PackageGraphs.Build(package).GetEnumerator())
        {
            while (true)
            {
                var build = Stopwatch.StartNew();
                if (!graphs.MoveNext())
                    break;
                var buildMs = build.ElapsedMilliseconds;
                var (folder, cost) = MeasureFolder(graphs.Current, choice.Tfm, fullPaths, buildMs);
                folders.Add(folder);
                costs.Add(cost);
            }
        }

        using var self = Process.GetCurrentProcess();
        self.Refresh();
        return new ChildPayload(choice.Tfm, choice.Available, folders,
            new PackageCost(0, total.ElapsedMilliseconds, openMs, self.PeakWorkingSet64, costs));
    }

    /// <summary>
    /// The role of a folder: its first path segment as NuGet reads it, in NuGet's spelling for the known roles
    /// (<c>lib</c>, <c>buildTransitive</c>, ...), else lower-cased; <c>(root)</c> for the package root.
    /// </summary>
    public static string RoleOf(string folder)
    {
        var name = NuGetName(folder);
        if (name.Length == 0)
            return RootRole;
        var first = name.Split('/')[0];
        return knownRoles.FirstOrDefault(r => r.Equals(first, StringComparison.OrdinalIgnoreCase)) ?? first.ToLowerInvariant();
    }

    /// <summary>
    /// Whether <paramref name="folder"/> (a <see cref="PackageGraph.Folder"/>: <c>/</c>-separated, possibly
    /// percent-encoded) is <c>lib/</c> + <paramref name="libTfm"/>, compared as <see cref="TfmSelection.LibFolderOf"/>
    /// reads NuGet's (unescaped) entry names: <c>lib</c> case-insensitively, the TFM ordinally, exactly two segments.
    /// </summary>
    public static bool IsPlibFolder(string folder, string? libTfm)
    {
        if (libTfm is null)
            return false;
        var parts = NuGetName(folder).Split('/');
        return parts.Length == 2
            && parts[0].Equals("lib", StringComparison.OrdinalIgnoreCase)
            && string.Equals(parts[1], libTfm, StringComparison.Ordinal);
    }

    /// <summary>
    /// The classes whose profile list <see cref="Reachability"/> cut at <see cref="MaxProfiles"/>: the report says only
    /// that some class was cut, so a class is taken as cut when the report is and the class holds exactly that many.
    /// Conservative: a class with exactly 64 uncut profiles beside a cut one is a floor too.
    /// </summary>
    public static IReadOnlyList<RootClass> TruncatedClasses(ReachabilityReport report) =>
        report.ProfilesTruncated ? [.. AllClasses.Where(k => report.Profiles.Count(p => p.Class == k) == MaxProfiles)] : [];

    /// <summary>
    /// Why <paramref name="class"/> is Unknown, by category, from structured data only - the facts' gaps by their
    /// <see cref="RootGap.Class"/> and fixed <see cref="RootGap.Reason"/> (never by the assembly name, which a package
    /// controls), the report's Unseen reach, and the coverage - mirroring the reasons <see cref="Reachability"/> writes.
    /// A failed analysis (Partial without truncation) is <c>analysis-failed</c> alone, as its reasons are.
    /// </summary>
    public static IReadOnlyList<string> CategoriesOf(RootClass @class, ReachabilityReport report, IReadOnlyList<RootGap> gaps)
    {
        var coverage = report.Graph;
        if (report.Partial && !coverage.Truncated)
            return ["analysis-failed"];

        var categories = gaps.Where(g => (g.Class & @class) != 0).Select(g => GapCategory(g.Reason)).ToList();
        if (report.Reaches.Any(r => r.Class == @class && r.Capability is null && r.Roots > 0))
            categories.Add("unseen");
        if (coverage.Truncated)
            categories.Add("truncated");
        if (!coverage.Index.IsComplete)
            categories.Add("index-incomplete");
        if (coverage.ModulesUnreadable > 0)
            categories.Add("modules-unreadable");
        if (coverage.RenamedImplementations > 0)
            categories.Add("renamed-implementations");
        return [.. categories.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }

    /// <summary>
    /// The category of a <see cref="RootGap.Reason"/>, which the library writes from fixed text with only counts or an
    /// exception message after it: matched on its start. An unknown phrase is <c>other</c>, so it shows in the report.
    /// </summary>
    public static string GapCategory(string reason) =>
        reason.StartsWith("<Module>..cctor runs at load", StringComparison.Ordinal) ? "module-initializer"
        : reason.StartsWith("module metadata unreadable", StringComparison.Ordinal) ? "module-metadata-unreadable"
        : reason.StartsWith("visibility unknown for ", StringComparison.Ordinal) ? "visibility-unknown"
        : reason.StartsWith("root facts unreadable for ", StringComparison.Ordinal) ? "root-facts-unreadable"
        : reason.StartsWith("root facts could not be collected", StringComparison.Ordinal) ? "root-facts-failed"
        : reason.StartsWith("dispatch work budget reached", StringComparison.Ordinal) ? "dispatch-budget"
        : reason.StartsWith("slot work budget reached", StringComparison.Ordinal) ? "slot-budget"
        : "other";

    // An entry name as NuGet reads it: '%xx' unescaped when the name holds a '%'. The same rule as the internal
    // Silvergun.PackageAnalysis.NuGet.NuGetPackage.NuGetName, and as NuGet's ZipArchiveExtensions.UnescapePath, which
    // is what PackageArchiveReader.GetFiles (and so TfmSelection) sees.
    private static string NuGetName(string entry) => entry.Contains('%') ? Uri.UnescapeDataString(entry) : entry;

    private static (FolderResult Folder, FolderCost Cost) MeasureFolder(
        PackageGraph pg, string? libTfm, IReadOnlyDictionary<string, string> fullPaths, long buildMs)
    {
        var role = RoleOf(pg.Folder);
        var isPlib = IsPlibFolder(pg.Folder, libTfm);
        var loaded = pg.Assemblies.ToHashSet(StringComparer.Ordinal);
        var members = pg.Assemblies.Concat(pg.LoadFailures.Select(f => f.RelativePath))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var failures = pg.LoadFailures
            .Select(f => new LoadFailureRecord(f.RelativePath, f.Reason))
            .OrderBy(f => f.RelativePath, StringComparer.Ordinal).ThenBy(f => f.Reason, StringComparer.Ordinal)
            .ToArray();

        // Presence over every member, loadable into the graph or not: the baseline scanned every lib/<tfm>/*.dll.
        var presenceClock = Stopwatch.StartNew();
        var scanned = members.Select(m => (Member: m, Scan: ScanPresence(m, fullPaths))).ToArray();
        var presenceMs = presenceClock.ElapsedMilliseconds;
        var presence = scanned.Select(s => s.Scan.Presence).ToArray();

        long analyzeMs = 0;
        FolderResult result;
        if (pg.Graph is not { } graph)
            result = new FolderResult(pg.Folder, role, isPlib, [.. pg.Assemblies], failures, false, null, 0, [], 0, 0, [], [], [], [], false, null,
                0, null, presence, null, []);
        else
        {
            var analyze = Stopwatch.StartNew();
            var report = Reachability.Analyze(graph);
            analyzeMs = analyze.ElapsedMilliseconds;

            var own = graph.Facts.Methods.Where(f => graph.Node(f.NodeId) is not null).ToArray();
            var parity = ReachabilityParity.Compare(scanned.Where(s => loaded.Contains(s.Member)).SelectMany(s => s.Scan.Findings), graph);

            result = new FolderResult(
                pg.Folder, role, isPlib, [.. pg.Assemblies], failures, true,
                Coverage(graph, own),
                own.Length,
                [.. report.Classes.Select(s => new ClassCount(s.Class, s.Roots))],
                own.Count(f => f.Roots == RootClass.PublicContract),
                own.Count(f => f.Roots == RootClass.Hidden),
                [.. report.Reaches.Select(r => new ReachRecord(r.Class, r.Capability, r.Roots, r.Bound, r.Instantiated))],
                [.. report.Classes.Select(s => new VerdictRecord(s.Class, s.Verdict, [.. s.Reasons], CategoriesOf(s.Class, report, graph.Facts.Gaps)))],
                [.. report.Profiles.Select(p => new ProfileRecord(p.Class, [.. p.Capabilities], p.Unseen, p.Roots, p.ExampleRoot))],
                TruncatedClasses(report),
                report.Partial,
                report.PartialReason,
                report.EdgesIgnored,
                parity,
                presence,
                Unseen(graph, own, report),
                [.. report.Reaches
                    .Where(r => TriggerClasses.Contains(r.Class) && r.Capability is { } c && SignalCapabilities.Contains(c) && r.Examples.Count > 0)
                    .Select(r => (Reach: r, Path: r.Examples[0]))
                    .Select(x => new ExampleRecord(x.Reach.Class, x.Reach.Capability!.Value, x.Path.Root, x.Path.Evidence, x.Path.Length, x.Path.Truncated,
                        x.Path.EndsInOpacity, [.. x.Path.Hops.Select(h => new HopRecord(h.NodeId, h.Assembly, h.Via, h.Offset))]))]);
        }

        using var self = Process.GetCurrentProcess();
        self.Refresh();
        return (result, new FolderCost(pg.Folder, buildMs, analyzeMs, presenceMs, self.WorkingSet64));
    }

    private static CoverageRecord Coverage(MethodGraph graph, IReadOnlyList<OwnMethodFacts> own)
    {
        var c = graph.Coverage;
        return new CoverageRecord(
            c.Truncated, c.TruncatedBy, c.Index.IsComplete,
            c.Index.AssembliesUnreadable, c.Index.TypesSkipped, c.Index.MethodsSkipped, c.Index.ForwardersUnreadable, c.Index.SupertypesUnresolved,
            c.MethodsIndexed, c.BodiesRead, c.BodiesFailed, c.CallSites, c.DispatchSites, c.DispatchEdges, c.TokenSites,
            c.ModuleInitializers, c.RenamedImplementations, c.ModulesUnreadable,
            [.. graph.Opacities.GroupBy(o => o.Kind).OrderBy(g => g.Key).Select(g => new NamedCount(g.Key.ToString(), g.Count()))],
            own.Count(f => f.InternalCall),
            own.Count(f => f.ComImport),
            own.Count(f => f.NativeImport),
            [.. graph.Facts.Gaps.Select(g => new GapRecord(g.Assembly, g.Class, g.Reason))]);
    }

    private static UnseenBreakdown Unseen(MethodGraph graph, IReadOnlyList<OwnMethodFacts> own, ReachabilityReport report) =>
        new(
            [.. graph.Opacities
                .Where(o => UnseenOpacityKinds.Contains(o.Kind) && graph.Node(o.Site) is not null)
                .GroupBy(o => o.Kind)
                .OrderBy(g => g.Key)
                .Select(g => new NamedCount(g.Key.ToString(), g.Select(o => o.Site).Distinct(StringComparer.Ordinal).Count()))],
            own.Count(f => f.InternalCall),
            graph.Nodes.Count(n => n.Kind == MethodNodeKind.External && CapabilityMap.Default.Classify(n.ClassificationKey).Class == CapabilityClass.Unanalyzed),
            [.. report.Reaches
                .Where(r => r.Capability is null)
                .SelectMany(r => r.Examples.Select(p => (r.Class, End: EndOf(graph, p))))
                .GroupBy(x => (x.Class, x.End))
                .OrderBy(g => g.Key.Class).ThenBy(g => g.Key.End, StringComparer.Ordinal)
                .Select(g => new UnseenEnd(g.Key.Class, g.Key.End, g.Count()))]);

    // What an Unseen example path ends at: an opacity site, an External node the map marks unanalyzed, or an own
    // InternalCall (the three kinds of unseen sink Reachability knows).
    private static string EndOf(MethodGraph graph, ReachPath path) =>
        path.EndsInOpacity is { } kind ? $"opacity:{kind}"
        : path.Hops.Count > 0 && graph.Node(path.Hops[^1].NodeId) is { Kind: MethodNodeKind.External } ? "unanalyzed"
        : "internal-call";

    // One member of a folder through the raw-CCI scanner, every finding kind. Load or analysis failure is a recorded
    // failure, never an exception.
    private static (AssemblyPresence Presence, IReadOnlyList<ApiCallFinding> Findings) ScanPresence(string member, IReadOnlyDictionary<string, string> fullPaths)
    {
        if (!fullPaths.TryGetValue(member, out var path))
            return (new AssemblyPresence(member, false, "not in the package's assembly inventory", 0, 0, []), []);

        var loaded = AssemblyAnalyzer.Load(path);
        if (!loaded.IsSuccess)
            return (new AssemblyPresence(member, false, $"load failed: {loaded.Message}", 0, 0, []), []);

        using var analyzer = loaded.Value;
        var analysis = new CapabilityAnalysis(analyzer).Analyze();
        if (!analysis.IsSuccess)
            return (new AssemblyPresence(member, false, $"capability analysis failed: {analysis.Message}", 0, 0, []), []);

        var report = analysis.Value;
        var counts = report.Findings
            .GroupBy(f => (f.Capability, f.Kind))
            .OrderBy(g => g.Key.Capability).ThenBy(g => g.Key.Kind)
            .Select(g => new PresenceCount(g.Key.Capability, g.Key.Kind, g.Count()))
            .ToArray();
        return (new AssemblyPresence(member, true, null, report.MethodsAnalyzed, report.MethodsSkipped, counts), report.Findings);
    }
    #endregion

    #region Fields
    public const string Verb = "reach";

    /// <summary>The most items a parity list keeps; its true count is always recorded.</summary>
    public const int MaxListed = 50;

    public const string RootRole = "(root)";

    /// <summary>The most profiles <see cref="Reachability"/> keeps per class (its private <c>MaxProfiles</c>; pinned by a test).</summary>
    public const int MaxProfiles = 64;

    /// <summary>The stderr line that names the child's extraction directory: <c>EXTRACTION\t&lt;dir&gt;</c>.</summary>
    public const string ExtractionMarker = "EXTRACTION";

    /// <summary>The trigger classes of ADR 0037 (E1, E2).</summary>
    public static readonly RootClass[] TriggerClasses = [RootClass.LoadTime, RootClass.HostContract, RootClass.RuntimeInvoked];

    /// <summary>All six single root classes, strongest first, as <see cref="Reachability"/> orders them.</summary>
    public static readonly RootClass[] AllClasses =
        [RootClass.LoadTime, RootClass.HostContract, RootClass.RuntimeInvoked, RootClass.PublicApi, RootClass.PublicContract, RootClass.Hidden];

    /// <summary>The signal capabilities of ADR 0037 decision 10, in enum order.</summary>
    public static readonly Capability[] SignalCapabilities =
        [Capability.FileSystem, Capability.Network, Capability.ProcessExecution, Capability.Registry, Capability.NativeInterop];

    // NuGet's spelling of the folder roles it knows (PackageItemRole, plus native and ref).
    private static readonly string[] knownRoles = ["analyzers", "build", "buildTransitive", "content", "contentFiles", "lib", "native", "ref", "runtimes", "tools"];

    /// <summary>The opacity kinds <see cref="Reachability"/> treats as unseen sinks (its private <c>unseenKinds</c>; pinned by a test).</summary>
    public static readonly IReadOnlySet<OpacityKind> UnseenOpacityKinds =
        new HashSet<OpacityKind> { OpacityKind.IndirectCall, OpacityKind.Unresolved, OpacityKind.Ambiguous, OpacityKind.BodyUnreadable };
    #endregion
}
