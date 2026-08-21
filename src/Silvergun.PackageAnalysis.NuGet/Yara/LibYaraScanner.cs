#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara;

using System.Reflection;

// libyara.NET is a Windows-only mixed-mode C++/CLI wrapper over native libyara 4.5. Its public API
// (YaraContext / Compiler / Rules / Scanner / ScanResult / Rule / Match) was learned from the package's
// headers under reference/projects/libyara.NET/*.h (read-only reference; we consume the shipped public
// API, informed by those headers — CLAUDE.md, user approved 2026-07-17). These types are kept ENTIRELY
// inside this #if WINDOWS file so the net10.0 (Linux) build never references libyara (ADR 0016).
using libyaraNET;

/// <summary>
/// The Windows in-process <see cref="IYaraScanner"/>: compiles the embedded ReversingLabs + custom
/// <c>.yara</c> ruleset once via libyara.NET's <see cref="Compiler"/>, then scans files with a shared
/// <see cref="Scanner"/> (classic libyara 4.5, <c>yr_rules_scan_fd</c> under the hood), mapping each
/// <see cref="ScanResult"/> to a backend-neutral <see cref="YaraMatch"/> POCO.
///
/// Contract: <b>never throws</b> (ADR 0016). All package content is hostile. The <see cref="YaraContext"/>,
/// compiled <see cref="Rules"/> and <see cref="Scanner"/> are created once and shared; a ruleset that will
/// not compile, a missing/unreadable file, or any native/engine error logs a warning and yields no matches
/// for that unit — the scan always continues.
/// </summary>
public sealed class LibYaraScanner : Runtime, IYaraScanner
{
    #region Properties
    /// <summary>
    /// <c>true</c> when the in-process engine actually initialized — the native <c>libyara.NET</c> dependency
    /// loaded and at least one embedded rule compiled (<see cref="sharedEngine"/> / <see cref="BuildEngine"/>);
    /// <c>false</c> when it did not (ADR 0027 decision 4). Reading this for the first time can itself throw:
    /// forcing <see cref="sharedEngine"/>'s <c>Lazy&lt;T&gt;.Value</c> here JITs this getter, which references the
    /// same <c>libyaraNET</c> types as <see cref="ScanFile"/> — if the native dependency's assembly cannot load,
    /// that failure surfaces at THIS call site exactly as it can from <see cref="ScanFile"/>'s. That is precisely
    /// why <c>PackageScanner.ScanYara</c> keeps a try/catch around this property as defense in depth, not as its
    /// primary detection mechanism.
    /// </summary>
    public bool Available => sharedEngine.Value is not null;
    #endregion

    #region Methods
    /// <summary>
    /// Scans <paramref name="fullPath"/> against the compiled ruleset and maps the hits to
    /// <see cref="YaraMatch"/>. Returns empty when the ruleset is unavailable, the file is missing, or a
    /// native error occurs. Never throws.
    /// </summary>
    public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
    {
        var engine = sharedEngine.Value;
        if (engine is null)
            return Array.Empty<YaraMatch>();

        try
        {
            if (string.IsNullOrEmpty(fullPath) || !File.Exists(fullPath))
            {
                Warn("Skipping YARA scan for {0}: file not found on disk.", fullPath);
                return Array.Empty<YaraMatch>();
            }

            var (_, rules, scanner) = engine.Value;   // engine is a non-null value tuple here
            // Scanner is documented threadsafe; Rules/Scanner are shared across files.
            var results = scanner.ScanFile(fullPath, rules);
            return results is null ? Array.Empty<YaraMatch>() : results.Select(MapMatch).ToArray();
        }
        catch (Exception ex)
        {
            Warn("YARA scan failed for {0}: {1}", fullPath, ex.Message);
            return Array.Empty<YaraMatch>();
        }
    }

    // Maps a libyara.NET ScanResult to our POCO. Namespace is not surfaced by libyara.NET's Rule wrapper,
    // so it is null for the in-process backend. Reads every field defensively.
    private static YaraMatch MapMatch(ScanResult result)
    {
        var rule = result?.MatchingRule;
        var tags = rule?.Tags?.ToArray() ?? Array.Empty<string>();
        var strings = (result?.Matches ?? new())
            .SelectMany(kv => (kv.Value ?? new List<Match>())
                .Select(m => new YaraStringMatch(kv.Key ?? string.Empty, (long)m.Offset)))
            .ToArray();

        return new YaraMatch(rule?.Identifier ?? string.Empty, null, tags, strings);
    }

    // Initializes libyara once and compiles the embedded ruleset. Keeps the YaraContext rooted for the
    // process lifetime (yr_initialize/yr_finalize is per-process). Returns null if nothing compiled, so the
    // scanner degrades to "no matches" rather than throwing.
    private static (YaraContext Context, Rules Rules, Scanner Scanner)? BuildEngine()
    {
        try
        {
            var context = new YaraContext();     // yr_initialize; rooted below, never finalized (process life)
            var compiler = new Compiler();

            var assembly = typeof(LibYaraScanner).Assembly;
            var resources = assembly.GetManifestResourceNames()
                .Where(n => n.Contains(RuleResourceMarker) && n.EndsWith(".yara", StringComparison.OrdinalIgnoreCase));

            var loaded = 0;
            foreach (var resource in resources)
            {
                try
                {
                    using var stream = assembly.GetManifestResourceStream(resource);
                    if (stream is null) continue;
                    using var reader = new StreamReader(stream);
                    compiler.AddRuleString(reader.ReadToEnd());
                    loaded++;
                }
                catch (Exception ex)
                {
                    // A rule file that fails to compile (e.g. a module the native lib lacks) is skipped.
                    Warn("Failed to compile embedded YARA rules {0}: {1}", resource, ex.Message);
                }
            }

            if (loaded == 0)
            {
                Warn("No YARA rules compiled; in-process malware-signature scanning is disabled.");
                return null;
            }

            var rules = compiler.GetRules();
            var scanner = new Scanner();
            Info("Compiled {0} embedded YARA rule file(s) for in-process malware-signature scanning.", loaded);
            return (context, rules, scanner);
        }
        catch (Exception ex)
        {
            Warn("Failed to initialize the in-process YARA engine: {0}", ex.Message);
            return null;
        }
    }
    #endregion

    #region Fields
    // Substring identifying the embedded YARA rule resources (ReversingLabs + Custom) under Resources/YaraRules.
    private const string RuleResourceMarker = ".Resources.YaraRules.";

    // Compiled once, reused across files and packages (ADR 0016); null when nothing compiled. The rooted
    // YaraContext in the tuple keeps yr_finalize from running for the process lifetime.
    private static readonly Lazy<(YaraContext Context, Rules Rules, Scanner Scanner)?> sharedEngine = new(BuildEngine);
    #endregion
}
#endif
