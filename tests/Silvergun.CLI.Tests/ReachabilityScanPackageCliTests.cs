namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

using Xunit;

/// <summary>
/// <c>scan-package --reachability</c> through the real CLI, in child processes (<c>docs/agent/tasks/reachability-r3.md</c>
/// S2, acceptance criteria 4, 5 and 6). The child is the CLI apphost, so its graph worker is itself (<c>__worker graph</c>,
/// found by <c>GraphWorkerLaunch.Cli</c> from the child's own process path): these runs use the real worker.
/// <para>
/// Two packages, built once per class (<see cref="Packages"/>). <b>Mixed</b> has the findings-free benign fixture in
/// <c>lib/net10.0</c> and ten bytes that are not a PE in <c>lib/netstandard2.0</c>: the second folder cannot be analysed,
/// so the reachability summary is Incomplete. <b>Benign</b> has only the benign fixture, whose summary is Completed.
/// Every run is <c>--no-vulns --no-yara</c>, offline. Each CLI run is cached by its arguments, so a test asks for what it
/// compares and no run is repeated (the determinism test asks for its second run under a different key).
/// </para>
/// <para>Two runs differ only by the extraction directory (<c>pkg-</c> plus a random name), wall-clock timestamps and the
/// console log lines; <see cref="Normalize"/> masks the first two and the human comparisons drop the log lines.</para>
/// </summary>
public sealed class ReachabilityScanPackageCliTests : IClassFixture<ReachabilityScanPackageCliTests.Packages>
{
    #region Constructors
    public ReachabilityScanPackageCliTests(Packages packages) => this.packages = packages;
    #endregion

    #region Methods: without the flag (criterion 5)
    // No section, no note, neither JSON key: the run without the flag is today's.
    [Fact]
    public void ScanPackage_WithoutFlag_OutputUnchanged()
    {
        var human = packages.Run("mixed-human", packages.Mixed);
        var json = packages.Run("mixed-json", packages.Mixed, "--json");

        Assert.DoesNotContain("Reachability (informational", human.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("trigger(s)", human.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("not analysed", human.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("reachability", human.Error, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("reachability", json.Error, StringComparison.OrdinalIgnoreCase);
        var root = JsonNode.Parse(json.Output)!.AsObject();
        Assert.False(root.ContainsKey("Reachability"), "the --json without the flag has a Reachability key");
        Assert.False(root.ContainsKey("ReachabilityStatus"), "the --json without the flag has a ReachabilityStatus key");
        Assert.DoesNotContain("Reachability", json.Output, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: with the flag, nothing that gates moves (criterion 6)
    // The exit code, the --strict exit code (with and without --allow-incomplete), the completeness footer and the
    // --snapshot file are the same with and without --reachability, over an Incomplete reachability summary.
    [Fact]
    public void ScanPackage_WithFlag_ExitCodeAndCompletenessUnchanged()
    {
        var without = packages.Run("mixed-human", packages.Mixed);
        var with = packages.Run("mixed-human-reach", packages.Mixed, "--reachability");
        var strictWithout = packages.Run("mixed-strict", packages.Mixed, "--strict");
        var strictWith = packages.Run("mixed-strict-reach", packages.Mixed, "--strict", "--reachability");
        var allowedWithout = packages.Run("mixed-strict-allow", packages.Mixed, "--strict", "--allow-incomplete");
        var allowedWith = packages.Run("mixed-strict-allow-reach", packages.Mixed, "--strict", "--allow-incomplete", "--reachability");

        // The premise: the summary is Incomplete, so this compares an undecided pass against none.
        Assert.Equal("Incomplete", ReachabilityStatus(packages.Run("mixed-json-reach", packages.Mixed, "--json", "--reachability")));
        // The baselines, so equal-but-both-wrong cannot pass: no-vulns and the unanalysable file make the scan
        // incomplete (3); the benign fixture has nothing that gates, so --allow-incomplete gives 0.
        Assert.Equal(3, without.Exit);
        Assert.Equal(3, strictWithout.Exit);
        Assert.Equal(0, allowedWithout.Exit);

        Assert.Equal(without.Exit, with.Exit);
        Assert.Equal(strictWithout.Exit, strictWith.Exit);
        Assert.Equal(allowedWithout.Exit, allowedWith.Exit);
        Assert.Equal(Footer(without.Output), Footer(with.Output));
        Assert.Equal(Footer(strictWithout.Output), Footer(strictWith.Output));
        Assert.Equal(FooterHeadline.Of(without.Output), FooterHeadline.Of(with.Output));
        Assert.Equal(Normalize(File.ReadAllText(without.Snapshot!)), Normalize(File.ReadAllText(with.Snapshot!)));
    }

    // The completeness disclosure on stderr (ReportIncompleteness) is the same; the flag adds only its own note. This
    // compares stderr's non-log lines only: console log lines ("[HH:mm:ss LVL] ...", see StderrLines) are dropped from
    // both runs, so a log line the flag adds or changes is not checked here.
    [Fact]
    public void ScanPackage_WithFlag_StderrNonLogLinesUnchangedButTheReachabilityNote()
    {
        var without = packages.Run("mixed-human", packages.Mixed);
        var with = packages.Run("mixed-human-reach", packages.Mixed, "--reachability");

        Assert.Equal(StderrLines(without.Error), StderrLines(with.Error).Where(l => !l.StartsWith(NotePrefix, StringComparison.Ordinal)).ToList());
    }

    // The human report with the flag is the report without it plus the section (title through the line before the
    // Assemblies section): nothing else in the text moves.
    [Fact]
    public void ScanPackage_WithFlag_HumanReportUnchangedButTheSection()
    {
        var without = ReportLines(packages.Run("mixed-human", packages.Mixed).Output);
        var with = ReportLines(packages.Run("mixed-human-reach", packages.Mixed, "--reachability").Output);

        var start = with.FindIndex(l => l.Contains("Reachability (informational", StringComparison.Ordinal));
        var end = start < 0 ? -1 : with.FindIndex(start, l => l.Contains("Assemblies", StringComparison.Ordinal));
        Assert.True(start >= 0 && end > start, $"no section found (start {start}, end {end}):\n{string.Join("\n", with)}");
        Assert.Equal(without, with.Take(start).Concat(with.Skip(end)).ToList());
    }

    // The JSON with the flag is the JSON without it once its two keys and AnalyzedAt are removed (and the extraction
    // directory masked): the summary is purely additive.
    [Fact]
    public void ScanPackage_WithFlag_JsonUnchangedButTheTwoKeys()
    {
        var without = JsonNode.Parse(packages.Run("mixed-json", packages.Mixed, "--json").Output)!.AsObject();
        var with = JsonNode.Parse(packages.Run("mixed-json-reach", packages.Mixed, "--json", "--reachability").Output)!.AsObject();

        Assert.True(with.ContainsKey("Reachability"), "the --json with the flag has no Reachability key");
        Assert.Equal("Incomplete", with["ReachabilityStatus"]!.GetValue<string>());
        foreach (var key in new[] { "Reachability", "ReachabilityStatus", "AnalyzedAt" })
        {
            with.Remove(key);
            without.Remove(key);
        }
        Assert.Equal(Normalize(without.ToJsonString()), Normalize(with.ToJsonString()));
    }
    #endregion

    #region Methods: the section and the real worker
    // The flag does something: the section is in the human report, and the folder the worker could read was analysed by
    // the real worker (the child is the CLI apphost, so GraphWorkerLaunch.Cli finds it), while the non-PE folder was not.
    [Fact]
    public void ScanPackage_WithFlag_RunsTheRealWorker_AndShowsTheSection()
    {
        var human = packages.Run("mixed-human-reach", packages.Mixed, "--reachability");
        var json = packages.Run("mixed-json-reach", packages.Mixed, "--json", "--reachability");

        Assert.Contains("Reachability (informational; does not affect the exit code)", human.Output, StringComparison.Ordinal);
        Assert.Contains("1 folder(s) not analysed", human.Output, StringComparison.Ordinal);
        var folders = Folders(json);
        var lib = Assert.Single(folders, f => f.GetProperty("Folder").GetString() == "lib/net10.0");
        Assert.True(Name(lib.GetProperty("Outcome")) == "Analyzed", $"lib/net10.0 was not analysed by the worker: {lib}");
        Assert.Equal(JsonValueKind.Null, lib.GetProperty("Reason").ValueKind);
        // Ten bytes that are not a PE do not load; the worker says so and survives (Crashed would mean it died on them).
        var bad = Assert.Single(folders, f => f.GetProperty("Folder").GetString() == "lib/netstandard2.0");
        Assert.Equal("NothingLoaded", Name(bad.GetProperty("Outcome")));
        Assert.Contains("lib/netstandard2.0/notmanaged.dll", bad.GetProperty("Reason").GetString(), StringComparison.Ordinal);
        Assert.Contains("[!] not analysed: NothingLoaded: ", human.Output, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the stderr note
    // Exactly one note, with the counts from the folders, and the exit code is the run without the flag's.
    [Fact]
    public void ScanPackage_IncompleteReachability_WritesOneStderrNote()
    {
        var with = packages.Run("mixed-human-reach", packages.Mixed, "--reachability");
        var json = packages.Run("mixed-json-reach", packages.Mixed, "--json", "--reachability");
        var folders = Folders(json);
        // Not analysed: a Reason, or an outcome other than Analyzed. Unknown verdicts count only in the other folders
        // (S2 review N1 and N2), the ones the human section lists.
        bool IsNotAnalysed(JsonElement f) => f.GetProperty("Reason").ValueKind == JsonValueKind.String || Name(f.GetProperty("Outcome")) != "Analyzed";
        var notAnalysed = folders.Count(IsNotAnalysed);
        var unknown = folders.Where(f => !IsNotAnalysed(f)).Sum(f => f.GetProperty("Classes").EnumerateArray().Count(c => Name(c.GetProperty("Verdict")) == "Unknown"));
        var expected = $"{NotePrefix}{notAnalysed} folder(s) not analysed, {unknown} class verdict(s) Unknown); see the report.";

        // Only the non-PE folder is not analysed. Its classes are [] (a non-Analyzed folder has a Reason and nothing
        // else), and lib/net10.0 is the benign package's folder, which is Completed on its own: no Unknown verdict.
        Assert.Equal(1, notAnalysed);
        Assert.Equal(0, unknown);
        Assert.Equal(expected, Assert.Single(StderrLines(with.Error), l => l.StartsWith(NotePrefix, StringComparison.Ordinal)));
        Assert.Equal(expected, Assert.Single(StderrLines(json.Error), l => l.StartsWith(NotePrefix, StringComparison.Ordinal)));
        Assert.Equal(packages.Run("mixed-human", packages.Mixed).Exit, with.Exit);
    }

    [Fact]
    public void ScanPackage_WithoutFlag_WritesNoReachabilityNote()
    {
        var without = packages.Run("mixed-human", packages.Mixed);

        Assert.DoesNotContain(StderrLines(without.Error), l => l.Contains("reachability", StringComparison.OrdinalIgnoreCase));
    }

    // A Completed summary (every folder analysed, no Unknown verdict) writes no note.
    [Fact]
    public void ScanPackage_CompleteReachability_WritesNoNote()
    {
        var run = packages.Run("benign-json-reach", packages.Benign, "--json", "--reachability");

        Assert.True(ReachabilityStatus(run) == "Completed", $"the premise: the benign package's summary is Completed:\n{Reachability(run)}\nstderr:\n{run.Error}");
        Assert.DoesNotContain(StderrLines(run.Error), l => l.Contains("reachability", StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Methods: determinism (criterion 4, the CLI half)
    [Fact]
    public void ScanPackage_TwoRuns_GiveTheSameReachabilityJson()
    {
        var first = packages.Run("mixed-json-reach", packages.Mixed, "--json", "--reachability");
        var second = packages.Run("mixed-json-reach-again", packages.Mixed, "--json", "--reachability");

        Assert.Equal(Reachability(first), Reachability(second));
    }
    #endregion

    #region Methods: helpers
    private static string? ReachabilityStatus(CliRun run) =>
        JsonNode.Parse(run.Output)!.AsObject()["ReachabilityStatus"]?.GetValue<string>();

    private static string Reachability(CliRun run) =>
        JsonNode.Parse(run.Output)!.AsObject()["Reachability"]?.ToJsonString() ?? "(no Reachability key)";

    private static List<JsonElement> Folders(CliRun run)
    {
        using var doc = JsonDocument.Parse(run.Output);
        return [.. doc.RootElement.GetProperty("Reachability").GetProperty("Folders").EnumerateArray().Select(f => f.Clone())];
    }

    // An enum value (the report's JSON writes enums by name, JsonStringEnumConverter).
    private static string Name(JsonElement value) => value.GetString()!;

    // The Assessment section to the end, normalized.
    private static List<string> Footer(string output)
    {
        var lines = ReportLines(output);
        var at = lines.FindLastIndex(l => l.Contains("Assessment", StringComparison.Ordinal));
        Assert.True(at >= 0, $"no Assessment section:\n{output}");
        return [.. lines.Skip(at)];
    }

    // The report's lines, normalized, without console log lines ("[HH:mm:ss LVL] ...").
    private static List<string> ReportLines(string output) =>
        [.. Normalize(output).Split('\n').Select(l => l.TrimEnd('\r', ' ')).Where(l => !LogLine.IsMatch(l))];

    private static List<string> StderrLines(string error) =>
        [.. error.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0 && !LogLine.IsMatch(l)).Select(Normalize)];

    // Masks the extraction directory and wall-clock timestamps.
    private static string Normalize(string text) => Iso8601.Replace(ExtractionDir.Replace(text, "pkg-MASKED"), "TIMESTAMP");
    #endregion

    #region Nested types
    /// <summary>A CLI run: exit code, stdout, stderr, and the --snapshot file it wrote (human runs only).</summary>
    public sealed record CliRun(int Exit, string Output, string Error, string? Snapshot);

    /// <summary>The two packages, and every CLI run over them, cached by key. Deletes its files on dispose.</summary>
    public sealed class Packages : IDisposable
    {
        #region Constructors
        public Packages()
        {
            var benign = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.BenignFixture.dll"));
            Mixed = BuildNupkg("SilvergunReachMixed", ("lib/net10.0/Benign.dll", benign), ("lib/netstandard2.0/notmanaged.dll", NotManagedBytes));
            Benign = BuildNupkg("SilvergunReachBenign", ("lib/net10.0/Benign.dll", benign));
        }
        #endregion

        #region Properties
        public string Mixed { get; }

        public string Benign { get; }
        #endregion

        #region Methods
        /// <summary>
        /// The run of <c>scan-package {nupkg} --no-vulns --no-yara {flags}</c> under <paramref name="key"/>. A run
        /// without --json also writes a --snapshot file. Fails the test if the child does not exit in time.
        /// </summary>
        public CliRun Run(string key, string nupkg, params string[] flags)
        {
            var run = runs.GetOrAdd(key, _ => new Lazy<CliRun>(() => Start(nupkg, flags))).Value;
            Assert.True(run.Exit >= 0, $"{key}: the CLI did not exit within {TimeoutMs} ms and was killed");
            Assert.True(run.Exit is 0 or 2 or 3, $"{key}: unexpected exit {run.Exit}\nstderr:\n{run.Error}\nstdout:\n{run.Output}");
            return run;
        }

        public void Dispose()
        {
            foreach (var file in new[] { Mixed, Benign }.Concat(snapshots))
                try { if (File.Exists(file)) File.Delete(file); } catch { /* best-effort temp cleanup */ }
        }

        private CliRun Start(string nupkg, string[] flags)
        {
            var snapshot = flags.Contains("--json") ? null : Path.Combine(Path.GetTempPath(), $"silvergun-reach-{Guid.NewGuid():N}.json");
            if (snapshot is not null)
                snapshots.Add(snapshot);
            var psi = new ProcessStartInfo(CliExe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                UseShellExecute = false,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            foreach (var arg in new[] { "scan-package", nupkg, "--no-vulns", "--no-yara" }.Concat(flags)
                         .Concat(snapshot is null ? [] : new[] { "--snapshot", snapshot }))
                psi.ArgumentList.Add(arg);
            psi.Environment["NO_COLOR"] = "1";
            psi.Environment.Remove("DOTNET_STARTUP_HOOKS");

            using var process = Process.Start(psi)!;
            process.StandardInput.Close();
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(TimeoutMs))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                return new CliRun(-1, string.Empty, string.Empty, null);
            }
            process.WaitForExit();
            return new CliRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), snapshot);
        }

        // A minimal valid .nupkg: the nuspec plus the given entries. Pure BCL zip.
        private static string BuildNupkg(string id, params (string Entry, byte[] Bytes)[] entries)
        {
            var nuspec = $"""
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="{NuspecNamespace}">
                  <metadata>
                    <id>{id}</id>
                    <version>1.0.0</version>
                    <authors>Silvergun Tests</authors>
                    <description>reachability R3 S2 test package.</description>
                  </metadata>
                </package>
                """;

            var path = Path.Combine(Path.GetTempPath(), $"silvergun-reach-{Guid.NewGuid():N}.nupkg");
            using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
            using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
            {
                Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
                foreach (var (entry, bytes) in entries)
                    Write(zip, entry, bytes);
            }
            return path;

            static void Write(ZipArchive zip, string name, byte[] bytes)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(bytes, 0, bytes.Length);
            }
        }
        #endregion

        #region Fields
        private readonly ConcurrentDictionary<string, Lazy<CliRun>> runs = new(StringComparer.Ordinal);

        private readonly ConcurrentBag<string> snapshots = [];
        #endregion
    }
    #endregion

    #region Fields
    private readonly Packages packages;

    private const string NotePrefix = "scan-package: reachability INCOMPLETE (";

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";

    private const int TimeoutMs = 300_000;

    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    private static readonly byte[] NotManagedBytes = [0x00, 0x01, 0x02, 0x03, 0x2A, 0x7F, 0x55, 0xAA, 0x13, 0x37];

    private static readonly Regex LogLine = new(@"^\[\d{2}:\d{2}:\d{2} [A-Z]{3}\]", RegexOptions.Compiled);

    private static readonly Regex ExtractionDir = new(@"pkg-[A-Za-z0-9_\-]+", RegexOptions.Compiled);

    private static readonly Regex Iso8601 = new(@"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)?", RegexOptions.Compiled);
    #endregion
}
