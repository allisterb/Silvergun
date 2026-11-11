namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using System.Text.RegularExpressions;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;

/// <summary>
/// One package folder as <see cref="R3Measure"/> measured it. <see cref="RawBytes"/> is the folder's
/// <see cref="GraphWorkerFolder"/> record line (without its <c>\n</c>), null when no record exists (Crashed, TimedOut,
/// NotRun); <see cref="RawCounted"/> whether it counted against <see cref="PackageReachabilityOptions.MaxReportBytes"/>
/// (a SameAs copy is never sent, so its size is the record it would have been). <see cref="SummaryBytes"/> is its
/// <see cref="FolderReachSummary"/> serialized standalone with the <c>--json</c> options; <see cref="JsonBytes"/> the
/// same object's span in the CLI's <c>--json</c> stdout, deeper-indented there.
/// </summary>
public sealed record R3FolderRow(
    int Position, string Folder, string Outcome, string? SameAs, int Nodes, int Edges,
    long? RawBytes, bool RawCounted, long? SummaryBytes, long? JsonBytes, int Triggers, int Informational, int Unknown);

/// <summary>The in-process half: the folder rows, the summary's package fields, the elapsed times and how raw bytes were measured.</summary>
public sealed record R3Library(
    IReadOnlyList<R3FolderRow> Folders, int SummaryFolders, int StatementsDropped, bool Complete, string Status,
    long OpenMs, long AnalyzeMs, long SummaryMs, bool RawExact, int ReplicaAgrees, int ReplicaCompared);

/// <summary>
/// One <c>scan-package</c> child: <see cref="Status"/> is <c>ok</c>, <c>timeout</c>, <c>not-started</c>,
/// <c>output-incomplete</c> (it exited, but its output did not finish copying) or <c>unparsable</c>. Byte counts are of
/// the raw stdout; the Reachability and Completeness members are measured as their exact byte spans in it and kept only
/// as lengths and SHA-256 hashes, and only when the status is <c>ok</c>. <see cref="StdoutPath"/> is where stdout was written.
/// </summary>
public sealed record R3CliRun(
    string Name, string Status, int? ExitCode, long WallMs, long StdoutBytes, long? ReachabilityBytes,
    IReadOnlyList<long> FolderBytes, string? ReachabilityStatus, string? Note, string? ReachabilityHash, string? CompletenessHash, string StdoutPath);

/// <summary>
/// The <c>r3-measure</c> mode (<c>docs/agent/tasks/reachability-r3.md</c>, S3, "Raw versus summary size"): over
/// <b>one</b> cached <c>.nupkg</c>, the raw <see cref="PackageReachability"/> report's per-folder wire size next to its
/// <see cref="ReachabilitySummary"/> size, measured in this process, then the product itself, <c>Silvergun.CLI
/// scan-package --json --no-vulns --no-yara</c>, with and without <c>--reachability</c> and with it again (determinism,
/// acceptance 4; the exit code, acceptance 6), each in its own killable child.
/// <para>
/// Protocol: <c>&lt;harness&gt; r3-measure &lt;nupkg&gt; &lt;out-dir&gt; [--timeout &lt;seconds&gt;]</c> (per CLI child,
/// default 900, a number over 0). Writes <c>&lt;stem&gt;.r3.md</c>, <c>.r3.tsv</c> (folders and a TOTAL row),
/// <c>.r3-facts.tsv</c> and the three runs' stdout and stderr into out-dir, the stem being the <c>.nupkg</c>'s file name.
/// Offline. Each CLI child gets a temp directory of its own (TMP, TEMP), removed after it. Exit codes: 0 written and
/// every check held; 4 written, but a check failed, a CLI run did not finish, or the raw bytes are only approximate
/// (<c>FLAG</c> lines on stderr); 1 nothing written; 2 bad usage.
/// </para>
/// </summary>
public static class R3Measure
{
    #region Methods
    public static int Execute(string[] args)
    {
        TimeSpan? timeout = args.Length switch
        {
            3 => TimeSpan.FromSeconds(DefaultTimeoutSeconds),
            5 when args[3] == "--timeout" => ParseTimeout(args[4]),
            _ => null,
        };
        if (timeout is not { } perRun)
        {
            Console.Error.WriteLine($"USAGE: <harness> {Verb} <nupkg> <out-dir> [--timeout <seconds>]  (seconds: a number over 0, at most {MaxTimeoutSeconds})");
            return 2;
        }

        try
        {
            var nupkg = Path.GetFullPath(args[1]);
            var outDir = Path.GetFullPath(args[2]);
            var cli = Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "Silvergun.CLI.exe" : "Silvergun.CLI");
            if (!File.Exists(nupkg))
            {
                Console.Error.WriteLine($"FAILED no such package: {Program.DisplayPath(nupkg)}");
                return 1;
            }
            if (!File.Exists(cli))
            {
                Console.Error.WriteLine($"FAILED {Verb} needs the CLI beside the harness, and there is no {Program.DisplayPath(cli)}.");
                return 1;
            }

            Directory.CreateDirectory(outDir);
            var stem = Path.GetFileNameWithoutExtension(nupkg);
            Runtime.Initialize("Silvergun", "CORPUS");
            Console.WriteLine($"package {Program.DisplayPath(nupkg)}");

            var library = MeasureLibrary(nupkg);
            Console.WriteLine($"library analyze={library.AnalyzeMs} ms summary={library.SummaryMs} ms folders={library.Folders.Count}");
            // The raw report is gone now; collect it so the CLI children's peak is not this process's leftovers.
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            var with = RunCli(cli, nupkg, true, outDir, stem, "with", perRun);
            Console.WriteLine($"cli with {with.Status} exit={Num(with.ExitCode)} wall={with.WallMs} ms");
            var without = RunCli(cli, nupkg, false, outDir, stem, "without", perRun);
            Console.WriteLine($"cli without {without.Status} exit={Num(without.ExitCode)} wall={without.WallMs} ms");
            var repeat = RunCli(cli, nupkg, true, outDir, stem, "with-repeat", perRun);
            Console.WriteLine($"cli with-repeat {repeat.Status} exit={Num(repeat.ExitCode)} wall={repeat.WallMs} ms");

            var rows = WithJsonBytes(library.Folders, with.FolderBytes);
            var stripped = with.Status == "ok" && without.Status == "ok"
                ? StrippedOutputsEqual(File.ReadAllBytes(with.StdoutPath), File.ReadAllBytes(without.StdoutPath))
                : (false, $"not compared: with {with.Status}, without {without.Status}");
            var checks = Checks(library, with, without, repeat, stripped);
            var md = Path.Combine(outDir, stem + ".r3.md");
            var tsv = Path.Combine(outDir, stem + ".r3.tsv");
            var facts = Path.Combine(outDir, stem + ".r3-facts.tsv");
            ReachabilityCorpusReport.WriteLines(tsv, TsvLines(stem, rows));
            ReachabilityCorpusReport.WriteLines(facts, FactLines(library, rows, with, without, repeat, checks));
            ReachabilityCorpusReport.WriteLines(md, Markdown(stem, nupkg, library, rows, with, without, repeat, checks));
            Console.WriteLine($"wrote {Program.DisplayPath(md)}");
            Console.WriteLine($"wrote {Program.DisplayPath(tsv)}");
            Console.WriteLine($"wrote {Program.DisplayPath(facts)}");
            Console.WriteLine(TotalsLine(rows, library, with));

            foreach (var failed in checks.Where(c => !c.Held))
                Console.Error.WriteLine($"FLAG {failed.Name}: {failed.Detail}");
            return checks.All(c => c.Held) ? 0 : CheckFailedExitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAILED {ex.GetType().Name}: {Program.Redact(ex.Message)}");
            return 1;
        }
    }

    /// <summary>
    /// The request index each folder's record carried, or null for a folder with no record. A worker numbers its records
    /// from 0 over the folders it was sent; a Crashed or TimedOut folder ends that worker, and the next one starts again
    /// at 0 with the folders after it. SameAs copies, and NotRun folders, were never sent. Exact unless a worker failed
    /// after its last record (its records are kept and the next run is not affected).
    /// </summary>
    public static IReadOnlyList<int?> WireIndexes(IEnumerable<(FolderOutcome Outcome, bool IsCopy)> folders)
    {
        var next = 0;
        return [.. folders.Select(f =>
        {
            if (f.IsCopy)
                return (int?)null;
            if (f.Outcome is FolderOutcome.Analyzed or FolderOutcome.NothingLoaded)
                return next++;
            if (f.Outcome is FolderOutcome.Crashed or FolderOutcome.TimedOut)
                next = 0;
            return null;
        })];
    }

    /// <summary>
    /// The exact byte span of the top-level member <paramref name="name"/>'s value in the JSON object
    /// <paramref name="json"/> (a leading UTF-8 BOM skipped), or null when it is absent or the JSON is not an object.
    /// </summary>
    public static (int Start, int Length)? MemberSpan(ReadOnlySpan<byte> json, string name)
    {
        var offset = json.StartsWith(Bom) ? Bom.Length : 0;
        var reader = new Utf8JsonReader(json[offset..], new JsonReaderOptions { MaxDepth = MaxJsonDepth });
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            return null;
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            var match = reader.ValueTextEquals(name);
            reader.Read();
            var start = (int)reader.TokenStartIndex;
            reader.Skip();
            if (match)
                return (offset + start, (int)reader.BytesConsumed - start);
        }
        return null;
    }

    /// <summary>The byte length of each element of the array member <paramref name="name"/> of the JSON object <paramref name="json"/>; empty when there is none.</summary>
    public static IReadOnlyList<long> ElementLengths(ReadOnlySpan<byte> json, string name)
    {
        if (MemberSpan(json, name) is not { } span)
            return [];
        var reader = new Utf8JsonReader(json.Slice(span.Start, span.Length), new JsonReaderOptions { MaxDepth = MaxJsonDepth });
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray)
            return [];
        var lengths = new List<long>();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            var begin = reader.TokenStartIndex;
            reader.Skip();
            lengths.Add(reader.BytesConsumed - begin);
        }
        return lengths;
    }

    /// <summary><paramref name="raw"/> over <paramref name="summary"/> to one decimal, with an <c>x</c>; <c>-</c> when either is missing or the summary is empty.</summary>
    public static string Ratio(long? raw, long? summary) =>
        raw is { } r && summary is > 0 and { } s ? (r / (double)s).ToString("0.0", CultureInfo.InvariantCulture) + "x" : "-";

    /// <summary>A markdown table cell from package-controlled text: cut to <paramref name="max"/> chars, then escaped (<see cref="ReachabilityCorpusReport.Escape"/>); empty for null.</summary>
    public static string Cell(string? text, int max = MaxCellChars) =>
        text is null ? string.Empty : ReachabilityCorpusReport.Escape(text.Length > max ? text[..max] + "..." : text);

    /// <summary>The <c>--timeout</c> value: invariant-culture seconds over 0 and at most <see cref="MaxTimeoutSeconds"/>, else null.</summary>
    public static TimeSpan? ParseTimeout(string text) =>
        double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) && seconds > 0 && seconds <= MaxTimeoutSeconds
            ? TimeSpan.FromSeconds(seconds)
            : null;

    /// <summary>
    /// <paramref name="json"/>, a JSON object (a leading UTF-8 BOM kept), with each top-level member in
    /// <paramref name="names"/> removed in turn: name, value and one separating comma, the whitespace between the member
    /// before it and the comma included, so what is left is what a serializer that never wrote the member writes. Every
    /// other byte is kept. Null when a member is absent or the JSON is not an object. Throws <see cref="JsonException"/>
    /// on malformed JSON.
    /// </summary>
    public static byte[]? WithoutMembers(byte[] json, params string[] names)
    {
        var bytes = json;
        foreach (var name in names)
        {
            if (MemberCut(bytes, name) is not { } cut)
                return null;
            var rest = new byte[bytes.Length - cut.Length];
            bytes.AsSpan(0, cut.Start).CopyTo(rest);
            bytes.AsSpan(cut.Start + cut.Length).CopyTo(rest.AsSpan(cut.Start));
            bytes = rest;
        }
        return bytes;
    }

    /// <summary>
    /// <paramref name="json"/> with what differs between two runs of the same scan masked: each <c>"AnalyzedAt"</c>
    /// member's ISO-8601 value (wall clock), the extraction directory's random name (<c>pkg-</c> and 12 of a-z0-9) and the
    /// CLI child's own temp directory (<see cref="RunTempPrefix"/> and 32 hex digits). Nothing else is touched.
    /// </summary>
    public static string MaskVolatile(string json) =>
        RunTempName.Replace(ExtractionName.Replace(AnalyzedAtValue.Replace(json, "${1}TIMESTAMP${2}"), "pkg-MASKED"), RunTempPrefix + "MASKED");

    /// <summary>
    /// Acceptance 5 and 6 at full strength: whether the <c>with</c> run's stdout, less its <c>Reachability</c>,
    /// <c>ReachabilityStatus</c> and <c>AnalyzedAt</c> members, equals the <c>without</c> run's less its
    /// <c>AnalyzedAt</c>, both masked by <see cref="MaskVolatile"/> and otherwise exactly; with a detail naming the first
    /// difference (escaped, profile paths redacted) or a missing member.
    /// </summary>
    public static (bool Held, string Detail) StrippedOutputsEqual(byte[] with, byte[] without)
    {
        try
        {
            var a = WithoutMembers(with, nameof(PackageCapabilityReport.Reachability), nameof(PackageCapabilityReport.ReachabilityStatus), AnalyzedAtMember);
            var b = WithoutMembers(without, AnalyzedAtMember);
            if (a is null)
                return (false, "the with run's stdout lacks a top-level Reachability, ReachabilityStatus or AnalyzedAt member");
            if (b is null)
                return (false, "the without run's stdout lacks a top-level AnalyzedAt member");
            var (x, y) = (MaskVolatile(Encoding.UTF8.GetString(a)), MaskVolatile(Encoding.UTF8.GetString(b)));
            if (string.Equals(x, y, StringComparison.Ordinal))
                return (true, $"{x.Length} chars equal, masked");
            var at = Enumerable.Range(0, Math.Min(x.Length, y.Length)).FirstOrDefault(i => x[i] != y[i], Math.Min(x.Length, y.Length));
            string Around(string s) => Cell(Program.Redact(s[Math.Max(0, at - 40)..Math.Min(s.Length, at + 40)]), 80);
            return (false, $"they differ at char {at} of {x.Length} (with) / {y.Length} (without): with \"{Around(x)}\", without \"{Around(y)}\"");
        }
        catch (JsonException ex)
        {
            return (false, $"a stdout is not JSON: {ex.Message}");
        }
    }

    // The bytes removing top-level member `name` takes out of the object `json`: from the end of the value before it
    // through its own value (`, "name": value`), or, for the first member, from its name to the next member's name
    // (`"name": value, `), or, for the only one, everything between the braces. Null when it is absent or json is no object.
    private static (int Start, int Length)? MemberCut(ReadOnlySpan<byte> json, string name)
    {
        var offset = json.StartsWith(Bom) ? Bom.Length : 0;
        var reader = new Utf8JsonReader(json[offset..], new JsonReaderOptions { MaxDepth = MaxJsonDepth });
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            return null;
        var open = reader.BytesConsumed;
        var previousEnd = open;
        (long NameStart, long ValueEnd)? first = null;
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            var nameStart = reader.TokenStartIndex;
            if (first is { } f)
                return ((int)(offset + f.NameStart), (int)(nameStart - f.NameStart));
            var match = reader.ValueTextEquals(name);
            reader.Read();
            reader.Skip();
            var valueEnd = reader.BytesConsumed;
            if (match && previousEnd == open)
                first = (nameStart, valueEnd);
            else if (match)
                return ((int)(offset + previousEnd), (int)(valueEnd - previousEnd));
            previousEnd = valueEnd;
        }
        return first is not null && reader.TokenType == JsonTokenType.EndObject
            ? ((int)(offset + open), (int)(reader.TokenStartIndex - open))
            : null;
    }

    // The in-process half: open, the graph pass through the real worker, the summary, and each folder's sizes, one
    // folder at a time into a counting stream so no record's text is kept.
    private static R3Library MeasureLibrary(string nupkg)
    {
        var open = Stopwatch.StartNew();
        var opened = NuGetPackage.Open(nupkg);
        if (!opened.IsSuccess)
            throw new InvalidOperationException($"the package could not be opened: {opened.Message}");
        var openMs = open.ElapsedMilliseconds;
        using var package = opened.Value;

        var analyze = Stopwatch.StartNew();
        var raw = PackageReachability.Analyze(package);
        var analyzeMs = analyze.ElapsedMilliseconds;
        var summarize = Stopwatch.StartNew();
        var summary = ReachabilitySummary.From(raw);
        var summaryMs = summarize.ElapsedMilliseconds;

        var wire = WireTypeInfo();
        var indexes = WireIndexes(raw.Folders.Select(f => (f.Outcome, f.SameAs is not null)));
        // A whole-pass summary failure gives one folder for the package: then no folder has a summary of its own.
        var matched = summary.Folders.Count == raw.Folders.Count;
        var measured = raw.Folders.Select((f, i) =>
        {
            var (rawBytes, replica) = f.Outcome is FolderOutcome.Analyzed or FolderOutcome.NothingLoaded
                ? RecordBytes(new GraphWorkerFolder(indexes[i] ?? 0, f.Folder, f.Assemblies, f.LoadFailures, f.Report, f.Nodes, f.Edges), wire)
                : ((long?)null, (long?)null);
            var folder = matched ? summary.Folders[i] : null;
            var row = new R3FolderRow(i + 1, f.Folder, f.Outcome.ToString(), f.SameAs, f.Nodes, f.Edges,
                rawBytes, rawBytes is not null && f.SameAs is null,
                folder is null ? null : Count(stream => JsonSerializer.Serialize(stream, folder, SummaryOptions)),
                null,
                folder?.Statements.Count(t => t.Kind == ReachStatementKind.Trigger) ?? 0,
                folder?.Statements.Count(t => t.Kind == ReachStatementKind.Informational) ?? 0,
                folder?.Classes.Count(c => c.Verdict == RootClassVerdict.Unknown) ?? 0);
            return (Row: row, Compared: replica is not null, Agrees: replica is not null && replica == rawBytes);
        }).ToList();

        return new R3Library([.. measured.Select(m => m.Row)], summary.Folders.Count, summary.StatementsDropped, summary.Complete, summary.Status().ToString(),
            openMs, analyzeMs, summaryMs, wire is not null, measured.Count(m => m.Agrees), measured.Count(m => m.Compared));
    }

    /// <summary>
    /// The protocol's own source-generated metadata (<c>GraphWorkerJsonContext.Default.GraphWorkerMessage</c>), reached by
    /// reflection because the context is internal and the harness is not in the library's InternalsVisibleTo. Null when
    /// it cannot be reached (the context renamed or moved, or <c>Default</c> no longer static): then the replica options
    /// stand in, the run is labelled APPROXIMATE and its <c>raw-exact</c> check fails. Public so a test breaks first.
    /// </summary>
    public static JsonTypeInfo<GraphWorkerMessage>? WireTypeInfo()
    {
        try
        {
            var context = typeof(GraphWorkerMessage).Assembly.GetType(WireContextName);
            var instance = context?.GetProperty("Default", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)?.GetValue(null);
            return context?.GetProperty(nameof(GraphWorkerMessage), BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)?.GetValue(instance) as JsonTypeInfo<GraphWorkerMessage>;
        }
        catch (Exception ex) when (ex is TargetException or TargetInvocationException or MemberAccessException or AmbiguousMatchException)
        {
            return null;
        }
    }

    /// <summary>
    /// A record's line bytes (no <c>\n</c>): with <paramref name="wire"/> when given (exact for <see cref="WireTypeInfo"/>),
    /// else the replica's; and the replica options' bytes, for comparison.
    /// </summary>
    public static (long? Bytes, long? Replica) RecordBytes(GraphWorkerMessage line, JsonTypeInfo<GraphWorkerMessage>? wire)
    {
        var replica = Count(stream => JsonSerializer.Serialize(stream, line, ReplicaWireOptions));
        return (wire is null ? replica : Count(stream => JsonSerializer.Serialize(stream, line, wire)), replica);
    }

    private static long Count(Action<Stream> write)
    {
        using var counter = new CountingStream();
        write(counter);
        return counter.Length;
    }

    // One scan-package child, its stdout and stderr streamed to files in outDir, killed with its tree on timeout or when
    // anything throws before its wait came back. Its TMP and TEMP are a directory of the harness's own, so its extraction
    // (<that>/silvergun/pkg-*) and anything else it leaves there is removed afterwards, a kill included: the CLI names its
    // extraction directory only in its --json stdout, written last, which a killed child has normally not written.
    private static R3CliRun RunCli(string cli, string nupkg, bool reachability, string outDir, string stem, string name, TimeSpan timeout)
    {
        var stdoutPath = Path.Combine(outDir, $"{stem}.{name}.json");
        var stderrPath = Path.Combine(outDir, $"{stem}.{name}.stderr.txt");
        var runTemp = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), RunTempPrefix + Guid.NewGuid().ToString("N"))).FullName;
        var psi = new ProcessStartInfo(cli)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = outDir,
        };
        psi.Environment["TMP"] = runTemp;
        psi.Environment["TEMP"] = runTemp;
        foreach (var argument in CliArguments(nupkg, reachability))
            psi.ArgumentList.Add(argument);

        try
        {
            var clock = Stopwatch.StartNew();
            int? exitCode;
            string status;
            using (var stdout = File.Create(stdoutPath))
            using (var stderr = File.Create(stderrPath))
            {
                using var process = Process.Start(psi);
                if (process is null)
                    return new R3CliRun(name, "not-started", null, 0, 0, null, [], null, null, null, null, stdoutPath);
                try
                {
                    process.StandardInput.Close();
                    var copyOut = process.StandardOutput.BaseStream.CopyToAsync(stdout);
                    var copyErr = process.StandardError.BaseStream.CopyToAsync(stderr);
                    if (process.WaitForExit(ReachabilityChildRunner.TimeoutMilliseconds(timeout)))
                    {
                        process.WaitForExit();
                        (exitCode, status) = (process.ExitCode, "ok");
                    }
                    else
                    {
                        KillTree(process);
                        process.WaitForExit(10_000);
                        (exitCode, status) = (null, "timeout");
                    }
                    // Output not fully copied is not parsed: a timeout stays a timeout, and an exit whose pipes did not
                    // drain (a grandchild holding them, or a copy that failed) is output-incomplete.
                    if (!CopiesDrained(copyOut, copyErr) && status == "ok")
                        status = OutputIncomplete;
                }
                finally
                {
                    KillTree(process);   // a no-op once it has exited; else anything above threw while it ran
                }
            }
            var wallMs = clock.ElapsedMilliseconds;

            var note = File.ReadLines(stderrPath).FirstOrDefault(l => l.StartsWith(NotePrefix, StringComparison.Ordinal));
            var bytes = File.ReadAllBytes(stdoutPath);
            if (status != "ok")
                return new R3CliRun(name, status, exitCode, wallMs, bytes.LongLength, null, [], null, note, null, null, stdoutPath);
            try
            {
                var reach = MemberSpan(bytes, nameof(PackageCapabilityReport.Reachability));
                var completeness = MemberSpan(bytes, CompletenessMember);
                var reachStatus = MemberSpan(bytes, nameof(PackageCapabilityReport.ReachabilityStatus)) is { } st
                    ? JsonSerializer.Deserialize<string>(bytes.AsSpan(st.Start, st.Length)) : null;
                return new R3CliRun(name, status, exitCode, wallMs, bytes.LongLength, reach?.Length,
                    reach is { } r ? ElementLengths(bytes.AsSpan(r.Start, r.Length), nameof(ReachabilitySummary.Folders)) : [],
                    reachStatus, note, Hash(bytes, reach), Hash(bytes, completeness), stdoutPath);
            }
            catch (JsonException)
            {
                return new R3CliRun(name, "unparsable", exitCode, wallMs, bytes.LongLength, null, [], null, note, null, null, stdoutPath);
            }
        }
        finally
        {
            RemoveRunTemp(runTemp);
        }
    }

    // Best effort, as everywhere in the harness: Kill(entireProcessTree) throws AggregateException when part of the tree
    // could not be killed, and InvalidOperationException or Win32Exception for a process already gone.
    private static void KillTree(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch { /* best-effort */ }
    }

    // Whether both copies finished, unfaulted, within 30 s.
    private static bool CopiesDrained(Task copyOut, Task copyErr)
    {
        try
        {
            return Task.WaitAll([copyOut, copyErr], TimeSpan.FromSeconds(30));
        }
        catch (AggregateException)
        {
            return false;   // a pipe broken (by the kill, or otherwise): what was copied is all there is
        }
    }

    // Deletes the child's own temp directory, which the harness created; a few tries, since a killed tree can hold files
    // for a moment. One that stays is said on stderr, not hidden.
    private static void RemoveRunTemp(string runTemp)
    {
        for (var attempt = 0; attempt < 5 && Directory.Exists(runTemp); attempt++)
        {
            try
            {
                Directory.Delete(runTemp, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(500);
            }
        }
        if (Directory.Exists(runTemp))
            Console.Error.WriteLine($"WARN could not remove the CLI child's temp directory {Program.DisplayPath(runTemp)}");
    }

    private static IEnumerable<string> CliArguments(string nupkg, bool reachability) =>
        reachability ? ["scan-package", nupkg, "--json", "--no-vulns", "--no-yara", "--reachability"] : ["scan-package", nupkg, "--json", "--no-vulns", "--no-yara"];

    private static string? Hash(byte[] bytes, (int Start, int Length)? span) =>
        span is { } s ? Convert.ToHexStringLower(SHA256.HashData(bytes.AsSpan(s.Start, s.Length))) : null;

    // The library rows with the CLI's per-folder --json spans, matched by position (only when the counts agree).
    private static IReadOnlyList<R3FolderRow> WithJsonBytes(IReadOnlyList<R3FolderRow> rows, IReadOnlyList<long> json) =>
        json.Count == rows.Count ? [.. rows.Select((r, i) => r with { JsonBytes = json[i] })] : rows;

    private static IReadOnlyList<(string Name, bool Held, string Detail)> Checks(R3Library library, R3CliRun with, R3CliRun without, R3CliRun repeat,
        (bool Held, string Detail) stripped) =>
    [
        ("cli-runs-finished", new[] { with, without, repeat }.All(r => r.Status == "ok"),
            string.Join(", ", new[] { with, without, repeat }.Select(r => $"{r.Name} {r.Status}"))),
        ("exit-code-equal (acceptance 6)", with.ExitCode is not null && with.ExitCode == without.ExitCode && repeat.ExitCode == with.ExitCode,
            $"with {Num(with.ExitCode)}, without {Num(without.ExitCode)}, repeat {Num(repeat.ExitCode)}"),
        ("completeness-json-equal (acceptance 6)", with.CompletenessHash is not null && with.CompletenessHash == without.CompletenessHash,
            $"with {with.CompletenessHash ?? "absent"}, without {without.CompletenessHash ?? "absent"}"),
        ("reachability-deterministic (acceptance 4)",
            with.ReachabilityHash is not null && with.ReachabilityHash == repeat.ReachabilityHash
            && with.ReachabilityStatus is not null && with.ReachabilityStatus == repeat.ReachabilityStatus,
            $"first {with.ReachabilityHash ?? "absent"} {with.ReachabilityStatus ?? "(no status)"}, repeat {repeat.ReachabilityHash ?? "absent"} {repeat.ReachabilityStatus ?? "(no status)"}"),
        ("no-reachability-without-flag (acceptance 5)", without.Status == "ok" && without.ReachabilityBytes is null && without.ReachabilityStatus is null,
            without.Status != "ok" ? $"not measured: without {without.Status}"
            : without.ReachabilityBytes is not null ? $"a Reachability member of {without.ReachabilityBytes} bytes"
            : without.ReachabilityStatus is not null ? $"a ReachabilityStatus member {without.ReachabilityStatus}" : "absent"),
        ("output-equal-but-reachability (acceptance 5/6)", stripped.Held, stripped.Detail),
        ("folders-match", with.FolderBytes.Count == library.SummaryFolders,
            $"library summary {library.SummaryFolders} folder(s), CLI --json {with.FolderBytes.Count}"),
        ("raw-exact", library.RawExact, RawMethod(library)),
    ];

    private static IEnumerable<string> TsvLines(string stem, IReadOnlyList<R3FolderRow> rows)
    {
        yield return string.Join('\t', TsvColumns);
        foreach (var r in rows)
            yield return Tsv(stem, Num(r.Position), r.Folder, r.Outcome, r.SameAs ?? "", Num(r.Nodes), Num(r.Edges), Num(r.RawBytes), r.RawCounted ? "yes" : "no",
                Num(r.SummaryBytes), Num(r.JsonBytes), Ratio(r.RawBytes, r.SummaryBytes), Num(r.Triggers), Num(r.Informational), Num(r.Unknown));
        var t = Totals(rows);
        yield return Tsv(stem, "TOTAL", Num(rows.Count), "", Num(t.SameAs), Num(t.Nodes), Num(t.Edges), Num(t.RawCounted), "counted",
            Num(t.Summary), Num(t.Json), Ratio(t.RawCounted, t.Summary), Num(t.Triggers), Num(t.Informational), Num(t.Unknown));
    }

    private static IEnumerable<string> FactLines(R3Library library, IReadOnlyList<R3FolderRow> rows, R3CliRun with, R3CliRun without, R3CliRun repeat,
        IReadOnlyList<(string Name, bool Held, string Detail)> checks) =>
        Facts(library, rows, with, without, repeat, checks).Select(f => Tsv(f.Key, f.Value)).Prepend("fact\tvalue");

    private static IEnumerable<(string Key, string Value)> Facts(R3Library library, IReadOnlyList<R3FolderRow> rows, R3CliRun with, R3CliRun without, R3CliRun repeat,
        IReadOnlyList<(string Name, bool Held, string Detail)> checks)
    {
        var t = Totals(rows);
        yield return ("raw_method", RawMethod(library));
        yield return ("raw_replica_agrees", $"{library.ReplicaAgrees}/{library.ReplicaCompared}");
        yield return ("raw_bytes_counted", Num(t.RawCounted));
        yield return ("raw_bytes_all_records", Num(t.RawAll));
        yield return ("raw_largest_record", Num(t.RawLargest));
        yield return ("max_report_bytes", Num(PackageReachabilityOptions.Default.MaxReportBytes));
        yield return ("max_record_line_bytes", Num(GraphWorkerProtocol.MaxRecordLineBytes));
        yield return ("summary_bytes", Num(t.Summary));
        yield return ("summary_statements_dropped", Num(library.StatementsDropped));
        yield return ("summary_complete", library.Complete ? "true" : "false");
        yield return ("summary_status", library.Status);
        yield return ("library_open_ms", Num(library.OpenMs));
        yield return ("library_analyze_ms", Num(library.AnalyzeMs));
        yield return ("library_summary_ms", Num(library.SummaryMs));
        foreach (var run in new[] { with, without, repeat })
        {
            yield return ($"cli_{run.Name}_status", run.Status);
            yield return ($"cli_{run.Name}_exit", Num(run.ExitCode));
            yield return ($"cli_{run.Name}_wall_ms", Num(run.WallMs));
            yield return ($"cli_{run.Name}_stdout_bytes", Num(run.StdoutBytes));
            yield return ($"cli_{run.Name}_reachability_bytes", Num(run.ReachabilityBytes));
            yield return ($"cli_{run.Name}_reachability_status", run.ReachabilityStatus ?? "");
            yield return ($"cli_{run.Name}_note", run.Note is null ? "" : Program.Redact(run.Note));
        }
        foreach (var check in checks)
            yield return ($"check {check.Name}", check.Held ? "yes" : $"NO: {check.Detail}");
    }

    private static IEnumerable<string> Markdown(string stem, string nupkg, R3Library library, IReadOnlyList<R3FolderRow> rows, R3CliRun with, R3CliRun without, R3CliRun repeat,
        IReadOnlyList<(string Name, bool Held, string Detail)> checks)
    {
        var t = Totals(rows);
        yield return $"# R3 raw versus summary size: {Cell(stem)}";
        yield return "";
        yield return "Measured by the benign-corpus harness `r3-measure` (docs/agent/tasks/reachability-r3.md, S3, \"Raw versus summary size\").";
        yield return "";
        yield return $"- package: {Cell(Program.DisplayPath(nupkg), 400)}";
        yield return $"- measured: {DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC; default `PackageReachabilityOptions`";
        yield return $"- raw bytes: {RawMethod(library)}; replica options agree on {library.ReplicaAgrees}/{library.ReplicaCompared} record(s)";
        yield return "- summary bytes: the folder's `FolderReachSummary` serialized alone with the `--json` options (indented, enum names, nulls written), " +
            "at depth 0; \"in --json\" is the same object's exact byte span in the CLI run's stdout, where it is indented 6 spaces deeper";
        yield return "- statements and Unknown come from the summary (after the package-wide statement cap); Unknown counts presented classes only";
        yield return $"- each CLI child ran with TMP and TEMP set to a directory of its own (`{RunTempPrefix}<guid>`, removed afterwards, so a killed child leaves no extraction); " +
            "`output-equal-but-reachability` compares the with and without stdout less `Reachability`, `ReachabilityStatus` and `AnalyzedAt`, masking only each " +
            "`AnalyzedAt` value, the `pkg-` extraction name and that directory's name";
        if (checks.Where(c => !c.Held).ToList() is { Count: > 0 } failed)
            foreach (var check in failed)
                yield return $"- **FLAG {Cell(check.Name)}**: {Cell(Program.Redact(check.Detail), 400)}";
        yield return "";
        yield return "## Folders";
        yield return "";
        yield return "| # | Folder | Outcome | SameAs | Nodes | Edges | Raw bytes | Counted | Summary bytes | In --json bytes | Ratio raw/summary | Statements T/I | Unknown |";
        yield return "|---:|---|---|---|---:|---:|---:|---|---:|---:|---:|---:|---:|";
        foreach (var r in rows)
            yield return $"| {r.Position} | {Cell(r.Folder)} | {r.Outcome} | {Cell(r.SameAs)} | {Num(r.Nodes)} | {Num(r.Edges)} | {Num(r.RawBytes)} | {(r.RawCounted ? "yes" : "no")} " +
                $"| {Num(r.SummaryBytes)} | {Num(r.JsonBytes)} | {Ratio(r.RawBytes, r.SummaryBytes)} | {r.Triggers}/{r.Informational} | {r.Unknown} |";
        yield return "";
        yield return "## Package totals";
        yield return "";
        yield return "| Folders | Analyzed | SameAs | Nodes | Edges | Raw bytes counted | Raw bytes, all records | Largest record | Summary bytes | Reachability member in --json | Ratio raw/summary | Statements T/I | Dropped | Unknown | Complete |";
        yield return "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|";
        yield return $"| {rows.Count} | {t.Analyzed} | {t.SameAs} | {Num(t.Nodes)} | {Num(t.Edges)} | {Num(t.RawCounted)} | {Num(t.RawAll)} | {Num(t.RawLargest)} | {Num(t.Summary)} " +
            $"| {Num(with.ReachabilityBytes)} | {Ratio(t.RawCounted, t.Summary)} | {t.Triggers}/{t.Informational} | {library.StatementsDropped} | {t.Unknown} | {(library.Complete ? "yes" : "no")} |";
        yield return "";
        yield return $"Raw bytes counted are {Percent(t.RawCounted, PackageReachabilityOptions.Default.MaxReportBytes)} of `MaxReportBytes` ({Num(PackageReachabilityOptions.Default.MaxReportBytes)}); " +
            $"the largest record is {Percent(t.RawLargest, GraphWorkerProtocol.MaxRecordLineBytes)} of the 16 MiB record limit.";
        yield return "";
        yield return "## Run facts";
        yield return "";
        yield return "| Fact | Value |";
        yield return "|---|---|";
        yield return $"| library: open | {library.OpenMs} ms |";
        yield return $"| library: `PackageReachability.Analyze` | {library.AnalyzeMs} ms |";
        yield return $"| library: `ReachabilitySummary.From` | {library.SummaryMs} ms |";
        yield return $"| library: summary status | {library.Status} |";
        foreach (var run in new[] { with, without, repeat })
        {
            yield return $"| CLI {run.Name}: {Cell(string.Join(' ', CliArguments("<nupkg>", run.Name != "without")))} | {run.Status}, exit {Num(run.ExitCode)}, wall {run.WallMs} ms |";
            yield return $"| CLI {run.Name}: stdout bytes / Reachability member bytes (exact span) | {Num(run.StdoutBytes)} / {Num(run.ReachabilityBytes)} |";
            yield return $"| CLI {run.Name}: ReachabilityStatus | {(run.ReachabilityStatus is null ? "(absent)" : Cell(run.ReachabilityStatus))} |";
            yield return $"| CLI {run.Name}: stderr reachability note | {(run.Note is null ? "(none)" : Cell(Program.Redact(run.Note), 400))} |";
        }
        foreach (var check in checks)
            yield return $"| check: {Cell(check.Name)} | {(check.Held ? "yes" : "**NO**: " + Cell(Program.Redact(check.Detail), 400))} |";
        yield return "";
        yield return "Peak memory is the guard's (the whole tree: this process, its graph workers and the CLI children), not measured here.";
    }

    private static string RawMethod(R3Library library) => library.RawExact
        ? "exact: each folder's `GraphWorkerFolder` record re-serialized with the protocol's own `GraphWorkerJsonContext` (reached by reflection), " +
          "compact, the bytes `GraphWorkerRun.AnsweredBytes` counts (no `\\n`); its `index` rebuilt from the outcomes (`R3Measure.WireIndexes`)"
        : "APPROXIMATE: `GraphWorkerJsonContext` could not be reached, so records are serialized with replica options (camelCase, nulls written, " +
          "read-only properties left out, enum names via `JsonStringEnumConverter`, compact); differs only for an aliased or flags enum value";

    private static string TotalsLine(IReadOnlyList<R3FolderRow> rows, R3Library library, R3CliRun with)
    {
        var t = Totals(rows);
        return $"TOTALS folders={rows.Count} analyzed={t.Analyzed} sameas={t.SameAs} raw_counted={t.RawCounted} raw_all={t.RawAll} raw_largest={t.RawLargest} " +
            $"summary={t.Summary} json_reachability={Num(with.ReachabilityBytes)} ratio={Ratio(t.RawCounted, t.Summary)} statements={t.Triggers}/{t.Informational} " +
            $"dropped={library.StatementsDropped} unknown={t.Unknown} complete={library.Complete} raw={(library.RawExact ? "exact" : "approximate")}";
    }

    private static (int Analyzed, int SameAs, long Nodes, long Edges, long RawCounted, long RawAll, long RawLargest, long Summary, long? Json, int Triggers, int Informational, int Unknown) Totals(IReadOnlyList<R3FolderRow> rows) =>
        (rows.Count(r => r.Outcome == nameof(FolderOutcome.Analyzed)), rows.Count(r => r.SameAs is not null),
            rows.Sum(r => (long)r.Nodes), rows.Sum(r => (long)r.Edges),
            rows.Where(r => r.RawCounted).Sum(r => r.RawBytes ?? 0), rows.Sum(r => r.RawBytes ?? 0), rows.Max(r => r.RawBytes) ?? 0,
            rows.Sum(r => r.SummaryBytes ?? 0), rows.All(r => r.JsonBytes is not null) ? rows.Sum(r => r.JsonBytes ?? 0) : null,
            rows.Sum(r => r.Triggers), rows.Sum(r => r.Informational), rows.Sum(r => r.Unknown));

    private static string Percent(long part, long whole) =>
        whole > 0 ? (100.0 * part / whole).ToString("0.000", CultureInfo.InvariantCulture) + "%" : "-";

    private static string Tsv(params string[] cells) => string.Join('\t', cells.Select(ReachabilityCorpusReport.Tab));

    private static string Num(long? value) => value?.ToString(CultureInfo.InvariantCulture) ?? "";
    #endregion

    #region Fields
    public const string Verb = "r3-measure";

    /// <summary>Written, but a check failed or a CLI run did not finish.</summary>
    public const int CheckFailedExitCode = 4;

    /// <summary>The longest <c>--timeout</c>: what <see cref="Process.WaitForExit(int)"/> can wait, in whole seconds.</summary>
    public const int MaxTimeoutSeconds = int.MaxValue / 1000;

    /// <summary>The name prefix of a CLI child's own temp directory, under the harness's temp directory.</summary>
    public const string RunTempPrefix = "silvergun-r3-";

    /// <summary>The status of a CLI run that exited but whose output did not finish copying.</summary>
    public const string OutputIncomplete = "output-incomplete";

    private const string AnalyzedAtMember = "AnalyzedAt";
    private const int DefaultTimeoutSeconds = 900;
    private const int MaxCellChars = 160;
    private const int MaxJsonDepth = 256;
    private const string NotePrefix = "scan-package: reachability";
    private const string CompletenessMember = "Completeness";
    private const string WireContextName = "Silvergun.PackageAnalysis.NuGet.Graph.GraphWorkerJsonContext";

    private static readonly byte[] Bom = [0xEF, 0xBB, 0xBF];

    // An "AnalyzedAt" member's ISO-8601 string value, the quotes kept as groups 1 and 2. Inside a JSON string the quotes
    // would be escaped, so only a real member matches.
    private static readonly Regex AnalyzedAtValue =
        new("(\"AnalyzedAt\":\\s*\")\\d{4}-\\d{2}-\\d{2}T[0-9:.+Z-]*(\")", RegexOptions.CultureInvariant);

    // NuGetPackage.Open's extraction directory name: "pkg-" and Runtime.RandomString(12) (a-z0-9).
    private static readonly Regex ExtractionName = new(@"\bpkg-[a-z0-9]{12}\b", RegexOptions.CultureInvariant);

    private static readonly Regex RunTempName = new(Regex.Escape(RunTempPrefix) + "[0-9a-f]{32}", RegexOptions.CultureInvariant);

    private static readonly string[] TsvColumns =
        ["package", "position", "folder", "outcome", "same_as", "nodes", "edges", "raw_bytes", "raw_counted", "summary_bytes", "json_bytes", "ratio_raw_summary", "triggers", "informational", "unknown"];

    // PackageCapabilityReport's own --json options.
    private static readonly JsonSerializerOptions SummaryOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    // GraphWorkerJsonContext's writing options as far as they shape the bytes; the exact converters are internal.
    private static readonly JsonSerializerOptions ReplicaWireOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        IgnoreReadOnlyProperties = true,
        Converters = { new JsonStringEnumConverter() },
    };
    #endregion

    #region Nested types
    // A write-only stream that keeps only the count of bytes written to it.
    private sealed class CountingStream : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => written;
        public override long Position { get => written; set => throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count) => written += count;
        public override void Write(ReadOnlySpan<byte> buffer) => written += buffer.Length;
        public override void WriteByte(byte value) => written++;
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        private long written;
    }
    #endregion
}
