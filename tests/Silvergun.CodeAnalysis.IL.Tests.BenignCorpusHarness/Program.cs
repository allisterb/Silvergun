namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Globalization;
using System.IO;
using System.Linq;

/// <summary>
/// Resolved run configuration. Every default is chosen so that a bare <c>run</c> is a small, bounded, repeatable
/// measurement: 25 pinned packages, a cache outside the repository, and output into
/// <c>docs/agent/measurements</c>.
/// </summary>
public sealed record HarnessOptions(
    string Manifest,
    int Take,
    string CacheRoot,
    string OutputDirectory,
    TimeSpan ChildTimeout);

/// <summary>
/// Benign-corpus harness - <b>a measurement instrument, not a shipped feature and not a unit test</b>. It scans a
/// pinned set of ordinary, widely-used NuGet packages and reports which capabilities appear in what share of them,
/// so that a later risk-scoring ADR can calibrate a gate against evidence instead of intuition. It changes nothing
/// about how Silvergun scores or gates; it only measures.
/// <para>
/// Two roles in one executable. Without arguments (or with options) it is the <b>driver</b>. With
/// <c>scan &lt;assembly&gt;</c> it is the <b>child</b> (<see cref="ChildScan"/>) that analyses exactly one assembly
/// in its own process - the driver re-invokes itself per assembly, so a CCI <c>FailFast</c> (ADR-0021, exit 35,
/// uncatchable) costs one assembly instead of the whole corpus run.
/// </para>
/// <para>Options: <c>--manifest &lt;path&gt;</c>, <c>--take &lt;n&gt;</c> (0 = all, default 25),
/// <c>--cache &lt;dir&gt;</c>, <c>--out &lt;dir&gt;</c>, <c>--timeout &lt;seconds&gt;</c> (per child, default 300).
/// </para>
/// <para>Exit codes: <c>0</c> the instrument ran and wrote its report (packages it could not scan are *data*,
/// reported in the report, not a tool failure); <c>1</c> the run could not produce a report; <c>2</c> bad usage.
/// </para>
/// </summary>
public static class Program
{
    #region Methods
    public static int Main(string[] args)
    {
        if (args.Length > 0 && string.Equals(args[0], ChildScan.Verb, StringComparison.Ordinal))
            return ChildScan.Execute(args);

        try
        {
            if (args.Contains("--help") || args.Contains("-h"))
            {
                Console.WriteLine(Usage);
                return 0;
            }

            var options = Parse(args);
            var manifest = CorpusManifest.Load(options.Manifest, options.Take);
            var date = DateOnly.FromDateTime(DateTime.Now);

            if (IsInsideRepository(options.CacheRoot))
            {
                Console.Error.WriteLine(
                    $"Refusing to cache .nupkg files inside the repository: {options.CacheRoot}. Pass --cache.");
                return 1;
            }

            Directory.CreateDirectory(options.OutputDirectory);
            Console.WriteLine($"manifest {manifest.Path}");
            Console.WriteLine($"manifest-hash {manifest.Hash} ({manifest.Entries.Count} package(s))");
            Console.WriteLine($"cache {options.CacheRoot}");

            var driver = new CorpusDriver(
                new PackageCache(options.CacheRoot), HarnessExecutable(), options.ChildTimeout);
            var results = driver.Run(manifest, Console.Out);

            var tsv = Path.Combine(options.OutputDirectory, $"benign-corpus-{date:yyyy-MM-dd}.tsv");
            var md = Path.Combine(options.OutputDirectory, $"benign-corpus-{date:yyyy-MM-dd}.md");
            CorpusReport.WriteFindingsTsv(tsv, results);
            CorpusReport.WriteMarkdown(md, Path.GetFileName(tsv), date, manifest, options.CacheRoot, results);

            Console.WriteLine($"wrote {tsv}");
            Console.WriteLine($"wrote {md}");
            Console.WriteLine(
                $"counted {results.Count(r => r.Counted)}/{results.Count} package(s); " +
                $"{results.Count(r => r.Status == PackageResult.Scanned)} complete");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAILED {ex}");
            return 1;
        }
    }

    private static HarnessOptions Parse(string[] args)
    {
        string Value(string name, string fallback)
        {
            var index = Array.IndexOf(args, name);
            return index >= 0 && index + 1 < args.Length ? args[index + 1] : fallback;
        }

        var take = int.Parse(Value("--take", "25"), CultureInfo.InvariantCulture);
        var timeout = double.Parse(Value("--timeout", "300"), CultureInfo.InvariantCulture);

        return new HarnessOptions(
            Path.GetFullPath(Value("--manifest", Path.Combine(AppContext.BaseDirectory, ManifestFileName))),
            take,
            Path.GetFullPath(Value("--cache", DefaultCacheRoot())),
            Path.GetFullPath(Value("--out", Path.Combine(RepositoryRoot(), "docs", "agent", "measurements"))),
            TimeSpan.FromSeconds(timeout));
    }

    // Outside the repository by construction: the machine's local app-data, never a path under the checkout.
    private static string DefaultCacheRoot() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify)
                is { Length: > 0 } local ? local : Path.GetTempPath(),
            "Silvergun",
            "benign-corpus");

    // The .exe/apphost of THIS harness, which the driver re-invokes per assembly. Environment.ProcessPath is the
    // apphost for a built binary but is 'dotnet' under 'dotnet run', which would make the child a no-op - so prefer
    // the apphost sitting next to the managed assembly whenever it exists.
    private static string HarnessExecutable()
    {
        var name = typeof(Program).Assembly.GetName().Name!;
        var apphost = Path.Combine(
            AppContext.BaseDirectory, OperatingSystem.IsWindows() ? $"{name}.exe" : name);
        return File.Exists(apphost) ? apphost : Environment.ProcessPath
            ?? throw new InvalidOperationException("Could not locate this harness's own executable.");
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (Directory.Exists(Path.Combine(dir.FullName, ".git")) || File.Exists(Path.Combine(dir.FullName, ".git")))
                return dir.FullName;

        return Directory.GetCurrentDirectory();
    }

    private static bool IsInsideRepository(string path) =>
        path.StartsWith(RepositoryRoot() + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    #endregion

    #region Fields
    public const string ManifestFileName = "benign-corpus.manifest";

    private const string Usage = """
        Benign-corpus harness (measurement instrument; changes no scoring).

          <harness> [--manifest <path>] [--take <n>] [--cache <dir>] [--out <dir>] [--timeout <seconds>]
          <harness> scan <assembly-path>     (child mode - one assembly, one process; see ADR-0021)

          --manifest  pinned 'id,version' list. Default: benign-corpus.manifest next to the executable.
          --take      keep the first n manifest entries; 0 keeps all. Default 25.
          --cache     .nupkg/extraction cache. Default %LOCALAPPDATA%/Silvergun/benign-corpus.
                      MUST be outside the repository - a .nupkg is never committed.
          --out       report directory. Default <repo>/docs/agent/measurements.
          --timeout   per-child-process timeout in seconds. Default 300.
        """;
    #endregion
}
