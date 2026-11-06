namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

#if WINDOWS
/// <summary>
/// The graph pass through the REAL net10.0-windows CLI apphost (<c>Silvergun.CLI.exe __worker graph --protocol 1</c>, in
/// this test bin by the CLI ProjectReference; <c>docs/agent/tasks/graph-worker.md</c> S2): <see cref="PackageReachability"/>
/// over a staged package equals the in-process <see cref="PackageGraphs"/> build plus <see cref="Reachability"/>, run after
/// run; identical folders share one result; the cap holds; and the hidden verb's argument errors are one graph
/// <c>fatal</c> and exit 3.
/// </summary>
public sealed class GraphWorkerCliTests : IDisposable
{
    #region Constructors
    public GraphWorkerCliTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        root = Directory.CreateTempSubdirectory("silvergun-graphcli-").FullName;
        Assert.True(File.Exists(CliExe), $"the net10.0-windows CLI apphost is not at '{CliExe}'");
    }
    #endregion

    #region Methods: the graph pass, end to end
    /// <summary>
    /// lib/net10.0 (the mechanism fixture plus its Dependency), lib/net8.0 (the shared fixture) and lib/net9.0 (garbage):
    /// every folder's outcome, assemblies, load failures, graph size and serialized report are the in-process ones.
    /// </summary>
    [Fact]
    public void Analyze_ThroughTheRealCli_EqualsTheInProcessPass()
    {
        using var package = Open("Parity",
            ($"lib/net10.0/{GraphStage.MechanismFixture}", GraphStage.Mechanism),
            ($"lib/net10.0/{GraphStage.MechanismDependency}", GraphStage.Dependency),
            ($"lib/net8.0/{GraphStage.SharedFixture}", GraphStage.Shared),
            ("lib/net9.0/garbage.dll", Encoding.UTF8.GetBytes("not a portable executable")));

        var worker = PackageReachability.Analyze(package);
        var inProcess = PackageGraphs.Build(package).Select(g => (Graph: g, Report: g.Graph is { } graph ? Reachability.Analyze(graph) : null)).ToArray();

        Assert.Equal(inProcess.Select(p => p.Graph.Folder), worker.Folders.Select(f => f.Folder));
        Assert.Equal([FolderOutcome.Analyzed, FolderOutcome.Analyzed, FolderOutcome.NothingLoaded], worker.Folders.Select(f => f.Outcome));
        foreach (var (expected, actual) in inProcess.Zip(worker.Folders))
        {
            Assert.Equal(expected.Graph.Graph is null ? FolderOutcome.NothingLoaded : FolderOutcome.Analyzed, actual.Outcome);
            Assert.Equal(expected.Graph.Assemblies, actual.Assemblies);
            Assert.Equal(expected.Graph.LoadFailures, actual.LoadFailures);
            Assert.Equal(expected.Graph.Graph?.Nodes.Count ?? 0, actual.Nodes);
            Assert.Equal(expected.Graph.Graph?.Edges.Count ?? 0, actual.Edges);
            Assert.Equal(GraphJson.Of(expected.Report), GraphJson.Of(actual.Report));
            Assert.Null(actual.Reason);
            Assert.Null(actual.SameAs);
        }
        Assert.True(worker.Folders[0].Nodes > 0 && worker.Folders[0].Edges > 0);
    }

    /// <summary>Two runs over one package give identical results, field for field and report byte for byte.</summary>
    [Fact]
    public void Analyze_ThroughTheRealCli_IsDeterministic()
    {
        using var package = Open("Twice",
            ($"lib/net10.0/{GraphStage.MechanismFixture}", GraphStage.Mechanism),
            ($"lib/net10.0/{GraphStage.MechanismDependency}", GraphStage.Dependency),
            ("lib/net9.0/native.dll", NupkgBuilder.NotManagedBytes));

        var first = PackageReachability.Analyze(package);
        var second = PackageReachability.Analyze(package);

        Assert.Equal(Flatten(first), Flatten(second));
    }

    /// <summary>
    /// lib/net8.0 and lib/net9.0 hold identical files: net8.0 is Analyzed, net9.0 shares its result (SameAs, its own paths,
    /// the same report). That only one was built is pinned against the fake worker
    /// (<see cref="GraphWorkerParentTests.IdenticalFolders_AreBuiltOnce_AndTheCopyHasItsOwnPaths"/>), which can count.
    /// </summary>
    [Fact]
    public void Analyze_ThroughTheRealCli_SharesIdenticalFolders()
    {
        using var package = Open("Dedup",
            ($"lib/net8.0/{GraphStage.MechanismFixture}", GraphStage.Mechanism),
            ($"lib/net8.0/{GraphStage.MechanismDependency}", GraphStage.Dependency),
            ($"lib/net9.0/{GraphStage.MechanismFixture}", GraphStage.Mechanism),
            ($"lib/net9.0/{GraphStage.MechanismDependency}", GraphStage.Dependency));

        var report = PackageReachability.Analyze(package);

        var (first, copy) = (report.Folders[0], report.Folders[1]);
        Assert.Equal(("lib/net8.0", FolderOutcome.Analyzed, (string?)null), (first.Folder, first.Outcome, first.SameAs));
        Assert.Equal(("lib/net9.0", FolderOutcome.Analyzed, (string?)"lib/net8.0"), (copy.Folder, copy.Outcome, copy.SameAs));
        Assert.Equal([$"lib/net9.0/{GraphStage.MechanismDependency}", $"lib/net9.0/{GraphStage.MechanismFixture}"], copy.Assemblies);
        Assert.Equal(GraphJson.Of(first.Report), GraphJson.Of(copy.Report));

        // The shared report is the copy's own as well: a report depends on the bytes, not the paths.
        var own = PackageGraphs.Build(package).Single(g => g.Folder == "lib/net9.0");
        Assert.Equal(GraphJson.Of(Reachability.Analyze(own.Graph!)), GraphJson.Of(copy.Report));
    }

    /// <summary>MaxFolders 1: the first distinct folder is built, the second NotRun with the cap as its reason.</summary>
    [Fact]
    public void Analyze_ThroughTheRealCli_HoldsTheFolderCap()
    {
        using var package = Open("Cap",
            ($"lib/net10.0/{GraphStage.MechanismDependency}", GraphStage.Dependency),
            ($"lib/net8.0/{GraphStage.SharedFixture}", GraphStage.Shared));

        var report = PackageReachability.Analyze(package, PackageReachabilityOptions.Default with { MaxFolders = 1 });

        Assert.Equal([FolderOutcome.Analyzed, FolderOutcome.NotRun], report.Folders.Select(f => f.Outcome));
        Assert.Contains("more than 1 distinct folders", report.Folders[1].Reason, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: review round 1
    /// <summary>
    /// W3 end to end: one package with a corrupt DLL and an identical copy of its folder, opened twice (two extraction
    /// directories) and analysed through the real CLI each time. Every load-failure reason and every
    /// <see cref="FolderReachability.Reason"/> is byte-identical across the two runs and names neither extraction directory.
    /// </summary>
    [Fact]
    public void Analyze_TwoExtractionsOfOnePackage_GiveByteIdenticalReasons_WithNoExtractionPath()
    {
        var corrupt = Encoding.UTF8.GetBytes("not a portable executable");
        using var first = Open("TwoExtractions",
            ("lib/net8.0/corrupt.dll", corrupt), ($"lib/net8.0/{GraphStage.MechanismDependency}", GraphStage.Dependency),
            ("lib/net9.0/corrupt.dll", corrupt), ($"lib/net9.0/{GraphStage.MechanismDependency}", GraphStage.Dependency),
            ("lib/net7.0/native.dll", NupkgBuilder.NotManagedBytes));
        using var second = NuGetPackage.Open(Path.Combine(root, "TwoExtractions.1.0.0.nupkg")).Value;
        Assert.NotEqual(first.ExtractionDir, second.ExtractionDir);

        var a = PackageReachability.Analyze(first);
        var b = PackageReachability.Analyze(second);

        Assert.Equal(Reasons(a), Reasons(b));
        Assert.Equal(3, Reasons(a).Count(r => r.Contains("corrupt.dll", StringComparison.Ordinal) || r.Contains("native.dll", StringComparison.Ordinal)));
        Assert.All(Reasons(a).Concat(Reasons(b)), r =>
        {
            Assert.DoesNotContain(first.ExtractionDir, r, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(second.ExtractionDir, r, StringComparison.OrdinalIgnoreCase);
        });
        Assert.Equal("lib/net8.0", a.Folders.Single(f => f.Folder == "lib/net9.0").SameAs);
        Assert.Contains("lib/net9.0/corrupt.dll", a.Folders.Single(f => f.Folder == "lib/net9.0").LoadFailures.Single().Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// W4 through the real worker loop: under an 8 MiB GC heap the mechanism folder's build runs out of memory inside
    /// PackageGraphs.BuildFolder (measured 3 of 3), so the worker answers <c>ready</c> and then <c>fatal</c> naming the failed
    /// build, exit 3, never a folder record that loaded nothing.
    /// </summary>
    [Fact]
    public void Verb_ABuildThatFailsAsAWhole_IsFatal_AndExitThree()
    {
        var request = GraphJson.Line(GraphJson.Request(("lib/a", new[]
        {
            new PackageAssembly($"lib/a/{GraphStage.MechanismDependency}", GraphStage.Beside(GraphStage.MechanismDependency), null, PackageItemRole.Lib, ""),
            new PackageAssembly($"lib/a/{GraphStage.MechanismFixture}", GraphStage.Beside(GraphStage.MechanismFixture), null, PackageItemRole.Lib, ""),
        })));

        var run = Run(WorkerArgs, request, closeStdin: false, new Dictionary<string, string> { ["DOTNET_GCHeapHardLimit"] = "0x800000" });

        Assert.Equal(3, run.Exit);
        var lines = Lines(run);
        Assert.Equal(2, lines.Length);
        Assert.Equal("{\"type\":\"ready\",\"protocol\":1,\"folders\":1}", lines[0]);
        var reason = FatalReason(lines[1]);
        Assert.StartsWith("the folder's graph could not be built: ", reason, StringComparison.Ordinal);
        Assert.Contains("OutOfMemoryException", reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The same 8 MiB GC heap over Model.NET6.dll (a real, loadable assembly) runs out of memory while the assembly is being
    /// LOADED. A folder that could not be analysed for lack of memory must not read as one that loaded nothing (W4, G4), so
    /// the worker must answer <c>fatal</c> as for any failed build. The control shows the assembly loads with no limit.
    /// </summary>
    [Fact]
    public void Verb_AnAssemblyThatRunsOutOfMemoryWhileLoading_IsFatal_NotALoadFailure()
    {
        var model = Path.Combine(AppContext.BaseDirectory, "Model.NET6.dll");
        var request = GraphJson.Line(GraphJson.Request(("lib/x", new[] { new PackageAssembly("lib/x/Model.NET6.dll", model, null, PackageItemRole.Lib, "") })));

        var limited = Run(WorkerArgs, request, closeStdin: false, new Dictionary<string, string> { ["DOTNET_GCHeapHardLimit"] = "0x800000" });
        var control = Run(WorkerArgs, request, closeStdin: false);

        var record = (GraphWorkerFolder)JsonSerializer.Deserialize(Lines(control)[1], GraphWorkerJsonContext.Default.GraphWorkerMessage)!;
        Assert.Equal(["lib/x/Model.NET6.dll"], record.Assemblies);
        Assert.True(limited.Exit == 3, $"under the limit the worker exited {limited.Exit} with: {limited.Stdout.Trim()}");
        Assert.Contains("OutOfMemoryException", FatalReason(Lines(limited)[^1]), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the hidden verb
    /// <summary>A genuine session over the real verb: ready, the record, done, exit 0, nothing but protocol on stdout.</summary>
    [Fact]
    public void Verb_AGenuineSession_IsReadyRecordDone_AndExitZero()
    {
        var request = Request($"lib/net10.0/{GraphStage.MechanismDependency}", GraphStage.Beside(GraphStage.MechanismDependency));

        var run = Run(WorkerArgs, request, closeStdin: false);

        Assert.Equal(0, run.Exit);
        var lines = Lines(run);
        Assert.Equal(3, lines.Length);
        Assert.Equal("{\"type\":\"ready\",\"protocol\":1,\"folders\":1}", lines[0]);
        Assert.Equal(GraphJson.Of(GraphJson.InProcess(0, "lib/net10.0", [($"lib/net10.0/{GraphStage.MechanismDependency}", GraphStage.Beside(GraphStage.MechanismDependency))])), lines[1]);
        Assert.Equal("{\"type\":\"done\",\"count\":1}", lines[2]);
    }

    /// <summary>The cross-platform half of "a worker never outlives its parent": stdin closed after the request is exit 4, promptly.</summary>
    [Fact]
    public void Verb_StdinClosedAfterTheRequest_ExitsFour()
    {
        var mechanism = GraphStage.Beside(GraphStage.MechanismFixture);
        var folders = string.Join(",", Enumerable.Range(0, 20).Select(i =>
            $"{{\"folder\":\"lib/f{i}\",\"assemblies\":[{{\"relativePath\":\"lib/f{i}/m.dll\",\"fullPath\":{JsonSerializer.Serialize(mechanism)}}}]}}"));
        var request = Encoding.UTF8.GetBytes($"{{\"protocol\":1,\"budget\":{{\"maxNodes\":100000,\"maxEdges\":1000000,\"maxDispatchWork\":10000000}},\"folders\":[{folders}]}}\n");
        var clock = Stopwatch.StartNew();

        var run = Run(WorkerArgs, request, closeStdin: true);

        // "Promptly" is pinned by what the worker wrote, not by the wall clock: it was stopped mid-session, before building
        // all 20 folders (measured in isolation 2026-11-05: exit 4 after 0.2 s, against 2.8 s for the whole session with stdin
        // open). Under the full suite's start-up load the wall time reached 57 s once, so the clock bound is only a backstop.
        Assert.Equal(GraphWorkerProtocol.ExitParentGone, run.Exit);
        Assert.DoesNotContain("\"type\":\"done\"", run.Stdout, StringComparison.Ordinal);
        Assert.True(run.Stdout.Split('\n').Count(l => l.StartsWith("{\"type\":\"folder\"", StringComparison.Ordinal)) < 20, "every folder was built before the worker exited");
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(100), $"took {clock.Elapsed}");
    }

    /// <summary>No request at all (stdin closed at once) is a fatal, not a hang.</summary>
    [Fact]
    public void Verb_NoRequest_IsOneFatal_AndExitThree()
    {
        var run = Run(WorkerArgs, [], closeStdin: true);

        Assert.Equal(3, run.Exit);
        Assert.Equal("no request line (Eof)", FatalReason(Assert.Single(Lines(run))));
    }

    public static TheoryData<string, string[], string> VerbArgumentErrors() => new()
    {
        { "--help", ["__worker", "graph", "--help"], ParseError },
        { "-h after valid arguments", ["__worker", "graph", "--protocol", "1", "-h"], ParseError },
        { "a repeated --protocol", ["__worker", "graph", "--protocol", "1", "--protocol", "1"], ParseError },
        { "an unknown option", ["__worker", "graph", "--protocol", "1", "--timeout", "5"], ParseError },
        { "an unknown token", ["__worker", "graph", "--protocol", "1", "extra"], ParseError },
        { "--protocol without its value", ["__worker", "graph", "--protocol"], ParseError },
        { "a bad protocol", ["__worker", "graph", "--protocol", "2"], "^unsupported protocol '2'; this build speaks 1$" },
        { "no protocol", ["__worker", "graph"], "^missing --protocol; this build speaks 1$" },
    };

    /// <summary>Every argument error under <c>__worker graph</c> is exactly one graph-protocol <c>fatal</c> on stdout (no help text) and exit 3.</summary>
    [Theory]
    [MemberData(nameof(VerbArgumentErrors))]
    public void Verb_AnArgumentError_IsOneGraphFatal_AndExitThree(string what, string[] args, string reason)
    {
        var run = Run(args, Request("lib/a.dll", @"C:\none\a.dll"), closeStdin: true);

        Assert.True(run.Exit == 3, $"{what}: exit {run.Exit}");
        Assert.Matches(reason, FatalReason(Assert.Single(Lines(run))));
        Assert.DoesNotContain("Usage", run.Stdout, StringComparison.Ordinal);
    }

    /// <summary>The yara worker's misparse keeps the yara reason (the full yara verb suite pins the rest).</summary>
    [Fact]
    public void Verb_AYaraMisparse_StillGetsTheYaraFatal()
    {
        var run = Run(["__worker", "yara", "--protocol", "1", "--protocol", "1"], [], closeStdin: true);

        Assert.Equal(3, run.Exit);
        Assert.EndsWith("expected __worker yara --protocol 1 [--timeout <seconds>]", FatalReason(Assert.Single(Lines(run))), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: helpers
    public void Dispose() => GraphFiles.DeleteTree(root);

    // Every load-failure reason and every folder Reason of a pass, in folder order.
    private static string[] Reasons(PackageReachabilityReport report) =>
        [.. report.Folders.SelectMany(f => f.LoadFailures.Select(l => $"{f.Folder}|{l.RelativePath}|{l.Reason}").Append($"{f.Folder}|reason|{f.Reason}"))];

    private const string ParseError = @"^the worker's arguments (did not parse \([0-9]+ error\(s\)\)|asked for something other than a worker session); expected __worker graph --protocol 1$";

    // Every field of every folder, the report serialized: equal exactly when two passes agree.
    private static string[] Flatten(PackageReachabilityReport report) =>
        [.. report.Folders.Select(f => string.Join("|", f.Folder, f.Outcome, string.Join(",", f.Assemblies),
            string.Join(",", f.LoadFailures.Select(l => l.RelativePath + ":" + l.Reason)), GraphJson.Of(f.Report), f.Reason, f.SameAs, f.Nodes, f.Edges))];

    private static byte[] Request(string relativePath, string fullPath) => GraphJson.Line(new GraphWorkerRequest(1, GraphWorkerBudget.Of(GraphBudget.Default),
        [new GraphWorkerFolderRequest(relativePath.Contains('/') ? relativePath[..relativePath.LastIndexOf('/')] : "", [new GraphWorkerAssembly(relativePath, fullPath)])]));

    private NuGetPackage Open(string id, params (string Name, byte[] Bytes)[] payload)
    {
        var path = Path.Combine(root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path,
            [($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(id, "1.0.0", "Silvergun Tests", "Graph worker test package.", "net8.0", []))), .. payload]);
        var open = NuGetPackage.Open(path);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    private static string FatalReason(string line)
    {
        using var doc = JsonDocument.Parse(line);
        Assert.Equal("fatal", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal(2, doc.RootElement.EnumerateObject().Count());
        return doc.RootElement.GetProperty("reason").GetString()!;
    }

    private static string[] Lines(CliRun run)
    {
        Assert.False(run.StdoutBytes is [0xEF, 0xBB, 0xBF, ..], "stdout starts with a BOM");
        Assert.True(run.StdoutBytes.Length > 0 && run.StdoutBytes[^1] == (byte)'\n', "stdout does not end with a newline: " + run.Stderr);
        var text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(run.StdoutBytes);
        Assert.DoesNotContain('\r', text);
        return text[..^1].Split('\n');
    }

    // One CLI child. stdin gets `stdin` and is then closed, or (closeStdin false) kept open until stdout ends, as the parent does.
    private CliRun Run(IReadOnlyList<string> args, byte[] stdin, bool closeStdin, IReadOnlyDictionary<string, string>? env = null)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = root,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");
        foreach (var (key, value) in env ?? new Dictionary<string, string>())
            psi.Environment[key] = value;

        using var process = Process.Start(psi)!;
        var stdout = new MemoryStream();
        var readOut = process.StandardOutput.BaseStream.CopyToAsync(stdout);
        var readErr = process.StandardError.ReadToEndAsync();
        var write = Task.Run(() =>
        {
            try
            {
                process.StandardInput.BaseStream.Write(stdin);
                process.StandardInput.BaseStream.Flush();
                if (closeStdin)
                    process.StandardInput.Close();
            }
            catch (IOException) { /* the worker stopped reading (fatal) and exited */ }
        });

        if (!closeStdin)
            readOut.Wait(120_000);
        if (!process.WaitForExit(120_000))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail("the CLI did not exit within 120 s and was killed");
        }
        process.WaitForExit();
        readOut.GetAwaiter().GetResult();
        write.GetAwaiter().GetResult();
        if (!closeStdin)
            try { process.StandardInput.Close(); } catch (IOException) { }
        return new CliRun(process.ExitCode, stdout.ToArray(), readErr.GetAwaiter().GetResult());
    }
    #endregion

    #region Nested types
    private sealed record CliRun(int Exit, byte[] StdoutBytes, string Stderr)
    {
        public string Stdout => Encoding.UTF8.GetString(StdoutBytes);
    }
    #endregion

    #region Fields
    private static readonly string[] WorkerArgs = ["__worker", "graph", "--protocol", "1"];

    private static readonly string CliExe = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.exe");

    private readonly string root;
    #endregion
}
#else
/// <summary>
/// The cross-platform NuGet test build has no CLI next to it (the CLI is referenced by the net10.0-windows build only), so
/// the production entry point must report every folder NotRun with the reason, and never fall back to in-process analysis
/// (<c>docs/agent/tasks/graph-worker.md</c> G4).
/// </summary>
public sealed class GraphWorkerNoCliTests : IDisposable
{
    public GraphWorkerNoCliTests() => stage = new GraphStage("nocli");

    [Fact]
    public void Analyze_WithoutTheCliBesideIt_IsNotRun_WithTheReason()
    {
        var cli = Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "Silvergun.CLI.exe" : "Silvergun.CLI");
        Assert.False(File.Exists(cli), $"this test assumes no CLI apphost in '{AppContext.BaseDirectory}'");

        var report = PackageReachability.Analyze(stage.Mechanisms("lib/net10.0"));

        var folder = Assert.Single(report.Folders);
        Assert.Equal(FolderOutcome.NotRun, folder.Outcome);
        Assert.Contains("there is no graph worker executable", folder.Reason, StringComparison.Ordinal);
        Assert.Null(folder.Report);
    }

    public void Dispose() => stage.Dispose();

    private readonly GraphStage stage;
}
#endif
