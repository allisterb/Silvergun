namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using global::NuGet.Packaging;

/// <summary>
/// Where a pinned package sits in the benign-corpus cache: <c>&lt;cache&gt;/packages/&lt;Id&gt;.&lt;Version&gt;.nupkg</c>.
/// One rule for both modes; <see cref="PackageCache.AcquireAsync"/> downloads to this path, <c>--reachability</c> only
/// ever looks at it.
/// </summary>
public static class CachedNupkg
{
    #region Methods
    public static string PathOf(string cacheRoot, ManifestEntry entry) =>
        Path.Combine(cacheRoot, "packages", $"{entry.Id}.{entry.Version}.nupkg");
    #endregion
}

/// <summary>Computes the <see cref="BuildIdentity"/> of the running harness.</summary>
public static class BuildIdentities
{
    #region Methods
    /// <summary>
    /// The identity of this build: <see cref="Describe"/> of <paramref name="repositoryRoot"/>, and
    /// <see cref="HashAssemblies"/> over <paramref name="outputDirectory"/>.
    /// </summary>
    public static BuildIdentity Current(string repositoryRoot, string outputDirectory) =>
        new(Describe(repositoryRoot), HashAssemblies(outputDirectory));

    /// <summary>
    /// SHA-256 over the top-level <c>*.dll</c> of <paramref name="directory"/>, in ordinal file-name order: each file
    /// contributes its name, a NUL, its own SHA-256 (hex) and a newline. The harness, every <c>src</c> and <c>ext</c>
    /// assembly it references, and their package dependencies are all top-level files of the output directory.
    /// </summary>
    public static string HashAssemblies(string directory)
    {
        var text = new StringBuilder();
        foreach (var file in Directory.GetFiles(directory, "*.dll", SearchOption.TopDirectoryOnly).Order(StringComparer.Ordinal))
        {
            using var stream = File.OpenRead(file);
            text.Append(Path.GetFileName(file)).Append('\0').Append(Convert.ToHexStringLower(SHA256.HashData(stream))).Append('\n');
        }
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));
    }

    /// <summary>
    /// <c>git describe --always --dirty --abbrev=40</c> in <paramref name="repositoryRoot"/>, run at run time: the full
    /// HEAD commit (or the nearest tag's description), suffixed <c>-dirty</c> when the working tree has uncommitted
    /// changes; <c>unknown</c> when git cannot answer. <see cref="WithUntracked"/> then adds <c>-dirty</c> when
    /// <c>git status --porcelain --untracked-files=all -- src ext tests</c> lists anything, untracked files included,
    /// which <c>describe --dirty</c> ignores (review N-a). Both are child processes with fixed arguments. The corpus run is
    /// made on committed code (spec, W5).
    /// </summary>
    public static string Describe(string repositoryRoot) =>
        Git(repositoryRoot, "describe", "--always", "--dirty", "--abbrev=40")?.Trim() is { Length: > 0 } described
            ? WithUntracked(described, Git(repositoryRoot, "status", "--porcelain", "--untracked-files=all", "--", "src", "ext", "tests"))
            : Unknown;

    /// <summary>
    /// <paramref name="described"/> with <see cref="DirtySuffix"/> when <paramref name="porcelain"/> lists any path, or when
    /// it is null (the status could not be read, so the tree is not known to be clean). Never suffixed twice.
    /// </summary>
    public static string WithUntracked(string described, string? porcelain) =>
        described.EndsWith(DirtySuffix, StringComparison.Ordinal) || (porcelain is not null && porcelain.Trim().Length == 0)
            ? described
            : described + DirtySuffix;

    // git with fixed arguments in the repository root: its stdout, or null when it cannot run, fails or hangs.
    private static string? Git(string repositoryRoot, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo("git") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, WorkingDirectory = repositoryRoot };
            foreach (var arg in args)
                psi.ArgumentList.Add(arg);
            using var git = Process.Start(psi);
            if (git is null)
                return null;
            var stdout = git.StandardOutput.ReadToEndAsync();
            var stderr = git.StandardError.ReadToEndAsync();
            if (!git.WaitForExit(30_000))
            {
                try { git.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                return null;
            }
            _ = stderr.GetAwaiter().GetResult();
            var output = stdout.GetAwaiter().GetResult();
            return git.ExitCode == 0 ? output : null;
        }
        catch (Exception)
        {
            return null;
        }
    }
    #endregion

    #region Fields
    public const string Unknown = "unknown";

    public const string DirtySuffix = "-dirty";
    #endregion
}

/// <summary>Thrown when the results directory holds a result of another build, or of another package.</summary>
public sealed class MixedBuildException(string message) : Exception(message);

/// <summary>What one invocation of the reachability driver did.</summary>
public sealed record ReachabilityRun(IReadOnlyList<PackageReachResult> Results, IReadOnlyList<ManifestEntry> Pending, int ChildrenRun)
{
    #region Properties
    /// <summary>True when every manifest entry has a result, so the report can be rendered.</summary>
    public bool Complete => Pending.Count == 0;
    #endregion
}

/// <summary>
/// The parent half of <c>--reachability</c>. Offline by construction: it never constructs a <see cref="PackageCache"/>
/// (whose <see cref="PackageCache.AcquireAsync"/> would download a missing package); a package not at
/// <see cref="CachedNupkg.PathOf"/> is <see cref="PackageReachResult.NotCached"/> and contributes nothing.
/// <para>
/// One child per package (<paramref name="runChild"/>; <see cref="ReachabilityChildRunner"/> in production). Each
/// result is cached as <c>&lt;results&gt;/&lt;Id&gt;.&lt;Version&gt;.json</c>; a rerun reuses it, and at most
/// <paramref name="maxChildren"/> new children run per invocation. Every cached result must carry
/// <paramref name="identity"/>: one that does not is a <see cref="MixedBuildException"/> before any child runs.
/// <c>not-cached</c> is re-checked on every invocation and never written.
/// </para>
/// </summary>
public sealed class ReachabilityDriver(
    string cacheRoot,
    string resultsDir,
    int maxChildren,
    BuildIdentity identity,
    Func<ManifestEntry, string, PackageReachResult> runChild)
{
    #region Methods
    public ReachabilityRun Run(CorpusManifest manifest, TextWriter progress)
    {
        Directory.CreateDirectory(resultsDir);
        // Every cached result is read and checked before any child runs, so a mixed directory refuses the run up front.
        var cached = manifest.Entries.Distinct().ToDictionary(e => e, Load);

        var results = new List<PackageReachResult>();
        var pending = new List<ManifestEntry>();
        var children = 0;
        foreach (var (entry, index) in manifest.Entries.Select((e, i) => (e, i + 1)))
        {
            var nupkg = CachedNupkg.PathOf(cacheRoot, entry);
            PackageReachResult? result;
            if (!File.Exists(nupkg))
                result = PackageReachResult.Without(entry, PackageReachResult.NotCached, $"no {Path.GetFileName(nupkg)} in the cache", null, identity);
            else if (cached[entry] is { } existing)
                result = existing;
            else if (children >= maxChildren)
                result = null;
            else
            {
                progress.Write($"[{index}/{manifest.Entries.Count}] {entry.Id} {entry.Version} ... ");
                result = runChild(entry, nupkg);
                children++;
                PackageReachResult.WriteAtomically(PackageReachResult.PathOf(resultsDir, entry), result.ToJson());
                progress.WriteLine($"{result.Status} folders={result.Folders.Count} {result.Detail ?? string.Empty}".TrimEnd());
            }

            if (result is null)
                pending.Add(entry);
            else
                results.Add(result);
        }
        return new ReachabilityRun(results, pending, children);
    }

    // The cached result of one entry, or null (none, or of another schema: re-measured). A result of another build, or
    // naming another package, refuses the run.
    private PackageReachResult? Load(ManifestEntry entry) =>
        CachedResults.Load(resultsDir, entry) is not { } result ? null
        : result.Identity == identity ? result
        : throw new MixedBuildException(
            $"Refusing to mix builds: {PackageReachResult.PathOf(resultsDir, entry)} was measured by {result.Identity}, but this harness is {identity}. " +
            "Use a fresh --results directory, or delete the stale results.");
    #endregion
}

/// <summary>
/// Reads a cached result of <c>--results</c>, for <see cref="ReachabilityDriver"/> and <see cref="ReachabilityCombine"/>
/// alike. A missing file, or one of another <see cref="PackageReachResult.Schema"/>, is <b>not cached</b> (null): its
/// schema is read before the rest, so an older result is never misread as this schema (R2b, d). One that is not a result,
/// or names another package, is a <see cref="MixedBuildException"/>. The build identity is the caller's to check.
/// </summary>
public static class CachedResults
{
    #region Methods
    public static PackageReachResult? Load(string resultsDir, ManifestEntry entry)
    {
        var path = PackageReachResult.PathOf(resultsDir, entry);
        if (!File.Exists(path))
            return null;

        PackageReachResult result;
        try
        {
            var text = File.ReadAllText(path);
            if (SchemaOf(text) != PackageReachResult.CurrentSchema)
                return null;
            result = PackageReachResult.FromJson(text);
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException)
        {
            throw new MixedBuildException($"{path} is not a reachability result ({ex.Message}); delete it to re-measure the package.");
        }
        return string.Equals(result.Id, entry.Id, StringComparison.Ordinal) && string.Equals(result.Version, entry.Version, StringComparison.Ordinal)
            ? result
            : throw new MixedBuildException($"{path} holds {result.Id} {result.Version}, not {entry.Id} {entry.Version}.");
    }

    // The integer Schema property of a result's JSON object; a JsonException when there is none.
    private static int SchemaOf(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.ValueKind == JsonValueKind.Object
            && document.RootElement.TryGetProperty(nameof(PackageReachResult.Schema), out var schema)
            && schema.ValueKind == JsonValueKind.Number && schema.TryGetInt32(out var value)
                ? value
                : throw new JsonException("no integer Schema property");
    }
    #endregion
}

/// <summary>
/// Spawns <see cref="ReachabilityChild"/> for one package and turns its exit code, its <c>DONE</c> sentinel and its JSON
/// into a <see cref="PackageReachResult"/>: non-zero exit is <c>crashed</c>, a kill on timeout <c>timeout</c>, exit 0
/// without <c>DONE</c> or without a readable payload <c>incomplete</c>. Never throws for an abnormal child.
/// </summary>
public static class ReachabilityChildRunner
{
    #region Methods
    public static PackageReachResult Run(string harnessExecutable, string resultsDir, ManifestEntry entry, string nupkg, TimeSpan timeout, BuildIdentity identity)
    {
        var payloadPath = Path.Combine(resultsDir, $"{entry.Id}.{entry.Version}.child.json");
        File.Delete(payloadPath);

        var psi = new ProcessStartInfo(harnessExecutable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(ReachabilityChild.Verb);
        psi.ArgumentList.Add(nupkg);
        psi.ArgumentList.Add(payloadPath);

        var clock = Stopwatch.StartNew();
        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start '{harnessExecutable}'.");
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(TimeoutMilliseconds(timeout)))
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            process.WaitForExit(10_000);
            File.Delete(payloadPath);
            RemoveExtraction(stderr.Wait(10_000) ? stderr.Result : string.Empty);
            return WithLibTfm(PackageReachResult.Without(entry, PackageReachResult.Timeout,
                $"child timed out after {timeout.TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)} s and was killed", null, identity,
                PackageCost.None with { ChildWallMs = clock.ElapsedMilliseconds }), nupkg);
        }
        var wallMs = clock.ElapsedMilliseconds;

        var errors = stderr.GetAwaiter().GetResult();
        var result = Classify(entry, process.ExitCode, stdout.GetAwaiter().GetResult(), errors,
            File.Exists(payloadPath) ? File.ReadAllText(payloadPath) : null, identity, wallMs);
        File.Delete(payloadPath);
        if (result.Status is not (PackageReachResult.Scanned or PackageReachResult.GraphFailed or PackageReachResult.NoAssemblies))
            RemoveExtraction(errors);
        return WithLibTfm(result, nupkg);
    }

    /// <summary>
    /// An <see cref="PackageReachResult.UnmeasuredFloor"/> result with the lib TFM <see cref="TfmSelection"/> picks over
    /// <paramref name="nupkg"/>'s file list, so it is a P-lib floor exactly when the package has a P-lib folder; any other
    /// result unchanged. Reads the archive's file names only: nothing is extracted or loaded. An unreadable archive keeps
    /// <see cref="PackageReachResult.LibTfmUnknown"/> (a floor in P-lib as well as P-all) and says so in the detail.
    /// <para>
    /// <b>The listing is unbounded</b> and runs in the parent, outside any child: the child already performed the same
    /// read first (<see cref="ReachabilityChild.Measure"/>), in a process under the guard, so an archive whose central
    /// directory is too costly to list has already shown itself there. No cap is applied. <b>Do not replace this with a
    /// TFM line the child prints on stderr:</b> zip entry names may contain LF, and the child echoes package-derived text
    /// (exception messages, paths) to stderr, so a crafted entry name could forge such a marker line and steer P-lib
    /// membership. The parent reads the archive itself.
    /// </para>
    /// </summary>
    public static PackageReachResult WithLibTfm(PackageReachResult result, string nupkg)
    {
        if (!result.UnmeasuredFloor)
            return result;
        try
        {
            using var reader = new PackageArchiveReader(nupkg);
            return result.WithLibTfm(TfmSelection.Choose(reader.GetFiles()));
        }
        catch (Exception ex)
        {
            return result with { LibTfm = null, LibTfms = [], LibTfmUnknown = true, Detail = $"{result.Detail}; lib TFM unknown, the .nupkg file list is unreadable ({ex.GetType().Name}: {ex.Message})" };
        }
    }

    /// <summary><paramref name="timeout"/> as <see cref="Process.WaitForExit(int)"/> takes it: clamped to [1, int.MaxValue] ms.</summary>
    public static int TimeoutMilliseconds(TimeSpan timeout) =>
        (int)Math.Clamp(timeout.TotalMilliseconds, 1, int.MaxValue);

    /// <summary>
    /// The extraction directory a child named on stderr (<see cref="ReachabilityChild.ExtractionMarker"/>), or null unless
    /// it is exactly <c>&lt;temp&gt;/silvergun/pkg-&lt;12 of a-z0-9&gt;</c> (<c>Runtime.RandomString</c>'s pool), the only shape
    /// <see cref="Silvergun.PackageAnalysis.NuGet.NuGetPackage.Open"/> creates.
    /// </summary>
    public static string? ExtractionDirOf(string stderr)
    {
        var named = stderr.Split('\n').Select(l => l.TrimEnd('\r'))
            .Where(l => l.StartsWith(ReachabilityChild.ExtractionMarker + "\t", StringComparison.Ordinal))
            .Select(l => l[(ReachabilityChild.ExtractionMarker.Length + 1)..])
            .FirstOrDefault();
        if (named is null || !Path.IsPathFullyQualified(named))
            return null;
        var full = Path.GetFullPath(named);
        var parent = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "silvergun"));
        return string.Equals(Path.GetDirectoryName(full), parent, StringComparison.OrdinalIgnoreCase)
            && extractionName.IsMatch(Path.GetFileName(full))
                ? full
                : null;
    }

    /// <summary>Deletes exactly the extraction directory a dead child named (<see cref="ExtractionDirOf"/>); never a glob.</summary>
    public static void RemoveExtraction(string stderr)
    {
        if (ExtractionDirOf(stderr) is not { } dir || !Directory.Exists(dir))
            return;
        try { Directory.Delete(dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    /// <summary>The status rule for a child that exited: pure, so it is tested without a process.</summary>
    public static PackageReachResult Classify(ManifestEntry entry, int exitCode, string stdout, string stderr, string? payloadJson, BuildIdentity identity, long wallMs)
    {
        var cost = PackageCost.None with { ChildWallMs = wallMs };
        if (exitCode != 0)
            return PackageReachResult.Without(entry, PackageReachResult.Crashed,
                $"child exited {exitCode}" + (exitCode == 35 ? " (35 = Environment.FailFast - uncatchable, see ADR-0021)" : string.Empty) +
                (FirstLine(stderr) is { } line ? $": {line}" : string.Empty),
                exitCode, identity, cost);

        var done = stdout.Split('\n').Select(l => l.TrimEnd('\r')).Contains("DONE");
        if (!done)
            return PackageReachResult.Without(entry, PackageReachResult.Incomplete, "child exited 0 without printing DONE (cut short)", 0, identity, cost);

        try
        {
            var payload = payloadJson is null ? null : JsonSerializer.Deserialize<ChildPayload>(payloadJson, PackageReachResult.JsonOptions);
            return payload is null
                ? PackageReachResult.Without(entry, PackageReachResult.Incomplete, "child printed DONE but wrote no payload", 0, identity, cost)
                : PackageReachResult.From(entry, payload, identity, wallMs);
        }
        catch (JsonException ex)
        {
            return PackageReachResult.Without(entry, PackageReachResult.Incomplete, $"child payload unreadable: {ex.Message}", 0, identity, cost);
        }
    }

    // The first line of the child's own diagnostics, past its extraction-directory line.
    private static string? FirstLine(string text) =>
        text.Split('\n').Select(l => l.Trim())
            .FirstOrDefault(l => l.Length > 0 && !l.StartsWith(ReachabilityChild.ExtractionMarker + "\t", StringComparison.Ordinal));
    #endregion

    #region Fields
    private static readonly System.Text.RegularExpressions.Regex extractionName =
        new(@"^pkg-[a-z0-9]{12}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    #endregion
}
