#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara;

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
/// Contract (the <see cref="IYaraScanner"/> one, ADR 0032): an empty result is a scan that happened and matched
/// nothing, or there is no engine at all (<see cref="Available"/>). All package content is hostile. The
/// <see cref="YaraContext"/>, compiled <see cref="Rules"/> and <see cref="Scanner"/> are created once and shared; a
/// ruleset that will not compile logs a warning and leaves the engine unbuilt (<see cref="Available"/> is
/// <c>false</c>). A file that was not scanned — missing, unopenable, a native fault, a result that would not map —
/// is logged and throws <see cref="YaraScanIncompleteException"/> for that file; the interface's default
/// <c>ScanDirectory</c> isolates it, keeps scanning the other files, and carries their hits out (ADR 0032 decisions
/// 5 and 6). The remaining exits are enumerated on <see cref="ScanFile"/>.
///
/// Timeout: <c>libyaraNET.Scanner</c> hardcodes its own native <c>yr_rules_scan_fd</c> timeout at 10000
/// SECONDS (~166 minutes; see <c>reference/projects/libyara.NET/Scanner.h</c>) with no way to lower it from
/// the shipped public API (it is a private const, not a constructor parameter) — so it is not a usable
/// DoS bound (ADR 0016 decision 7, "timeout-bounded / hostile-input"). Scans of ordinary files (a NuGet
/// package's few-KB <c>.signature.p7s</c>) were once observed to burn minutes of pure CPU inside
/// <c>yr_rules_scan_fd</c>. That was NOT combinatorial rule cost, as previously assumed here; the measured
/// root cause is <b>compiler poisoning</b> (ADR 0028). <see cref="BuildEngine"/> used to add all 310 embedded
/// rule files to ONE <see cref="Compiler"/>, log the <c>CompilationException</c> thrown by the single file
/// this native build cannot compile (<c>ReversingLabs.virus.Linux.Virus.Vit.yara</c> —
/// <c>unknown module "elf"</c>, no ELF module in <c>Microsoft.O365.Security.Native.libyara.NET.Core</c>) and
/// then call <c>GetRules()</c> on that same errored compiler. libyara's compiler is unusable after an error:
/// the <c>YR_RULES</c> it hands back is not a valid ruleset, and walking it is undefined behaviour, not merely
/// slow. Measured (yara-inprocess-timing-2026-08-21.tsv, 120 s probe watchdog): against a poisoned ruleset a
/// <b>4-byte</b> all-zero input did not complete within the watchdog (&gt; 120,000 ms; no upper bound was
/// established) while a <b>2-byte</b> one completed in 6 ms; against a cleanly built 302-file ruleset a
/// 26,653 B input scanned in 5 ms. Rule count, rule content, input size and the file-vs-memory entrypoint
/// were all measured and ruled out. <see cref="BuildEngine"/> therefore compiles in two passes and never asks
/// an errored compiler for rules (ADR 0028 decision 8) and canary-scans the result before publishing it
/// (decision 9), so a healthy scan is now milliseconds — 7–12 ms for the ~0.5–0.7 MB Newtonsoft.Json
/// assemblies, measured against a subset of 128 rule files.
/// <see cref="ScanFile"/> now bounds each native scan with its own wall-clock <see cref="scanTimeout"/>, as
/// defence in depth rather than as the mechanism (ADR 0028 decision 10) — reaching that bound now means a NEW
/// defect: on timeout it deliberately lets a <see cref="TimeoutException"/>
/// escape, which the default <c>ScanDirectory</c> turns into a <see cref="YaraScanIncompleteException"/> carrying the
/// hits so far, so the whole package scan is reported as <see cref="YaraScanStatus.Unavailable"/> rather than as a clean
/// <see cref="YaraScanStatus.Completed"/> (ADR 0027 decision 4) — silently swallowing a timed-out scan as
/// "no matches" would be indistinguishable from a healthy scan that found nothing. The abandoned native call
/// keeps running until it eventually returns (there is no safe way to cancel a blocked native
/// <c>yr_rules_scan_fd</c> call from managed code); its outcome is observed and discarded, and it is demoted to
/// <see cref="ThreadPriority.Lowest"/> at that point. That is why every bounded scan here runs on a DEDICATED
/// background thread — normal priority while it is still awaited — rather than on the thread pool
/// (<c>TryRunBounded</c>): a stuck scan is pure CPU, so abandoning a pool thread would permanently
/// remove one worker from the pool and peg a core for up to <c>libyaraNET.Scanner</c>'s 10000 s internal bound
/// — tolerable in a one-shot CLI, not in the long-lived WPF host.
/// </summary>
public sealed class LibYaraScanner : Runtime, IYaraScanner
{
    #region Properties
    /// <summary>
    /// <c>true</c> when the in-process engine actually initialized — the native <c>libyara.NET</c> dependency
    /// loaded, at least one embedded rule compiled, and the resulting ruleset passed its startup canary scan
    /// (<see cref="sharedEngine"/> / <see cref="BuildEngine"/>, ADR 0028 decision 9);
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
    /// <see cref="YaraMatch"/>. Returns empty when nothing matched, or when the ruleset is unavailable (no engine
    /// at all — exactly what <see cref="Available"/> reports). Exactly THREE things can leave this method.
    ///
    /// The first is <see cref="YaraScanIncompleteException"/> when <b>this file</b> was not scanned (ADR 0032
    /// decision 5): the path is empty or the file is missing, the native scan faulted (a non-zero yara error code,
    /// or <c>CreateFile</c> failing on a share-denied or ACL'd path even after <see cref="File.Exists"/> said
    /// otherwise), a hostile <see cref="ScanResult"/> failed to map, or the scan thread could not be started. Each is
    /// logged (path escaped) and thrown rather than flattened to empty, because an empty list here is read as
    /// "scanned, clean". It costs the other files nothing: the default <c>ScanDirectory</c> records this file as
    /// unscanned and keeps going, carrying every hit out (decision 6).
    ///
    /// The second is the native scan exceeding <see cref="scanTimeout"/>, which throws
    /// <see cref="TimeoutException"/> deliberately (see the class doc): the native <c>yr_rules_scan_fd</c> call
    /// cannot be safely cancelled, so the timed-out call is abandoned on its own thread and this method reports the
    /// failure honestly instead of swallowing it as "no matches".
    ///
    /// The third is a failure to LOAD the native <c>libyara.NET</c> assembly, which surfaces when this method
    /// forces <see cref="sharedEngine"/>'s <c>Lazy&lt;T&gt;.Value</c> on its first line — deliberately outside
    /// every <c>try</c>, because a load failure is raised as this method is JIT-resolved, so no guard written
    /// inside it (nor <see cref="BuildEngine"/>'s own catch, which never even runs) can intercept it, and
    /// <c>Lazy&lt;T&gt;</c> then caches and rethrows it for the process lifetime. It surfaces at THIS call site
    /// exactly as it can from <see cref="Available"/>, and is deliberately left unguarded for the same reason:
    /// <c>PackageScanner.ScanYara</c>'s outer catch turns it into <see cref="YaraScanStatus.Unavailable"/>, which
    /// is the honest answer when there is no engine to scan with at all.
    /// </summary>
    public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
    {
        var engine = sharedEngine.Value;
        if (engine is null)
            return Array.Empty<YaraMatch>();

        // The path is package-derived and therefore attacker-authored: it is escaped everywhere it is logged or
        // quoted in an exception message below.
        var shown = YaraPathSafety.Escape(fullPath);
        if (string.IsNullOrEmpty(fullPath) || !File.Exists(fullPath))
        {
            Warn("Skipping YARA scan for {0}: file not found on disk.", shown);
            throw new YaraScanIncompleteException(
                $"YARA did not scan '{shown}': file not found on disk. This file was NOT scanned and must not be reported as clean.");
        }

        var (_, rules, scanner) = engine.Value;   // engine is a non-null value tuple here
        try
        {
            // Scanner is documented threadsafe; Rules/Scanner are shared across files. The native scan runs on
            // its own bounded thread so a pathologically slow scan cannot block the caller forever (see class
            // doc) — libyaraNET.Scanner's own native timeout is a useless 10000 SECONDS. Everything except the
            // timeout is handled INSIDE this try, including a fault raised by the native call itself; the filter
            // lets the per-file exception thrown for that fault pass straight out rather than being re-wrapped.
            if (TryRunBounded(() => scanner.ScanFile(fullPath, rules), scanTimeout, out var results, out var error))
                return error is not null ? throw Failed(error)
                    : results is null ? Array.Empty<YaraMatch>()
                    : results.Select(MapMatch).ToArray();
        }
        catch (Exception ex) when (ex is not YaraScanIncompleteException)
        {
            throw Failed(ex);   // mapping a hostile ScanResult, or failing to even start the scan thread
        }

        // Timeout path ONLY, deliberately outside the try so it cannot be caught above and reported as an ordinary
        // per-file failure: a reached bound says the ENGINE's health can no longer be vouched for, which is why the
        // default ScanDirectory stops at it rather than moving on (ADR 0027 decision 4 / ADR 0028 decision 10).
        Warn("YARA scan TIMED OUT for {0} after {1}: the in-process engine's health can no longer be verified.", shown, scanTimeout);
        throw new TimeoutException($"YARA scan of '{shown}' exceeded the {scanTimeout} bound.");

        // This file was not scanned (ADR 0032 decision 5): logged, and thrown rather than returned as empty.
        YaraScanIncompleteException Failed(Exception ex)
        {
            Warn("YARA scan failed for {0}: {1}", shown, YaraPathSafety.Escape(ex.Message));
            return new YaraScanIncompleteException(
                $"YARA could not scan '{shown}': {YaraPathSafety.Escape(ex.Message)}. This file was NOT scanned and must not be reported as clean.",
                ex);
        }
    }

    // Runs a native scan on a DEDICATED background thread bounded by wall-clock <paramref name="bound"/>
    // (ADR 0028; W5 of the ADR-0028 review). Returns true when it finished within the bound, handing back
    // either its value or the exception it threw — this method itself never propagates the body's fault, which
    // is what lets ScanFile tell a fault (this file not scanned) from a timeout (engine health unknown). Returns false on timeout: a
    // blocked native yr_rules_scan_* call cannot be cancelled, so the thread is simply abandoned. It is a
    // dedicated thread, not a pool work item, because a stuck scan is pure CPU: abandoning a pool thread would
    // permanently cost the process a pool worker (and could starve later Lazy<T>-bound work such as the startup
    // canary, causing a SPURIOUS canary failure). IsBackground keeps an abandoned thread from holding the
    // process open. Priority is left NORMAL while the scan is still ours to wait on — a healthy scan is on the
    // caller's critical path, and running every scan at Lowest would make legitimate work the first thing the
    // scheduler starves on a loaded box, a real cost in the common case to contain one that should never happen
    // (W5a of the ADR-0028 review). It is demoted to Lowest only on the timeout path, at the instant we give up
    // on it: the Thread reference is still ours and valid, and from then on the runaway scan is pure waste that
    // must not compete with real work while it spins out its native call.
    private static bool TryRunBounded<T>(Func<T> body, TimeSpan bound, out T? value, out Exception? error)
        where T : class
    {
        T? outcome = null;
        Exception? fault = null;
        var thread = new Thread(() =>
        {
            // The fault is observed HERE, always: an exception escaping a raw thread's delegate terminates the
            // process. On the abandoned (timed-out) path nobody reads it back, which is the intent.
            try { outcome = body(); }
            catch (Exception ex) { fault = ex; }
        })
        {
            IsBackground = true,
            Name = "silvergun-yara-scan",
        };

        thread.Start();
        if (!thread.Join(bound))
        {
            // Abandoned: demote it so it stops competing with real work. Setting Priority races with the thread
            // finishing just after Join gave up (ThreadStateException), and this path exists only to let
            // ScanFile throw its deliberate TimeoutException — nothing here may escape, the log of the failed
            // demotion included: an exception out of Debug would land in ScanFile's catch and be reported as an
            // ordinary per-file failure, so the default ScanDirectory would keep scanning on an engine whose health is
            // no longer vouched for — the timeout's whole signal (ADR 0028 decision 10) lost. Losing a diagnostic line
            // is always the cheaper failure here.
            try { thread.Priority = ThreadPriority.Lowest; }
            catch (Exception ex)
            {
                try { Debug("Could not demote abandoned YARA scan thread: {0}", ex.Message); }
                catch { /* deliberately empty: see above */ }
            }

            (value, error) = (null, null);
            return false;
        }

        (value, error) = (outcome, fault);   // Join is the memory barrier that publishes both
        return true;
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

    // Initializes libyara once and compiles the embedded ruleset in TWO passes (ADR 0028 decision 8), then
    // self-checks it with a canary scan before publishing it (decision 9). Keeps the YaraContext rooted for
    // the process lifetime (yr_initialize/yr_finalize is per-process). Returns null whenever the engine cannot
    // be built AND verified, so the backend reports Available == false (=> YaraScanStatus.Unavailable) rather
    // than handing out a ruleset of unknown health.
    private static (YaraContext Context, Rules Rules, Scanner Scanner)? BuildEngine()
    {
        try
        {
            var context = new YaraContext();     // yr_initialize; rooted below, never finalized (process life)

            // Pass 1: validate every embedded rule source in ITS OWN throwaway compiler, which is disposed
            // either way. A compiler that has errored is poison (ADR 0028) and is never reused for anything.
            var outcomes = YaraRuleResources.ReadAll().ToLookup(s => CompilesCleanly(s.ResourceName, s.Text));
            var (valid, dropped) = (outcomes[true].ToArray(), outcomes[false].ToArray());

            if (dropped.Length > 0)
                Warn("Dropped {0} embedded YARA rule file(s) that failed validation (ADR 0028); they are NOT part of the compiled ruleset: {1}",
                    dropped.Length, string.Join(", ", dropped.Select(d => d.ResourceName)));

            if (valid.Length == 0)
            {
                Warn("No YARA rules compiled; in-process malware-signature scanning is disabled.");
                return null;
            }

            // Pass 2: ONE fresh compiler, only the validated sources, so GetRules() is only ever called on a
            // compiler that has not errored. Anything thrown here falls out to the catch below as null. The
            // compiler is disposed at scope exit and the Rules it produced stay valid — that is exactly what
            // libyara.NET's own Compiler::CompileRulesString does with its stack-allocated Compiler. Compiler
            // declares no finalizer, so skipping the dispose would leak its whole native YR_COMPILER arena for
            // the process lifetime.
            using var compiler = new Compiler();
            foreach (var (_, text) in valid)
                compiler.AddRuleString(text);

            var rules = compiler.GetRules();
            var scanner = new Scanner();
            if (!CanaryScanCompletes(rules, scanner))
                return null;

            Info("Compiled {0} embedded YARA rule file(s) for in-process malware-signature scanning.", valid.Length);
            return (context, rules, scanner);
        }
        catch (Exception ex)
        {
            Warn("Failed to initialize the in-process YARA engine: {0}", ex.Message);
            return null;
        }
    }

    // Pass-1 validation of a single embedded rule source, in a throwaway compiler that is discarded whatever
    // happens. The whole CompilationException.Message is logged, not its first line: it is multi-line and the
    // useful detail (e.g. unknown module "elf") is not on the first one.
    private static bool CompilesCleanly(string resource, string text)
    {
        try
        {
            using var throwaway = new Compiler();
            throwaway.AddRuleString(text);
            return true;
        }
        catch (Exception ex)
        {
            // A rule file that fails to compile (e.g. a module the native lib lacks) is skipped.
            Warn("Failed to compile embedded YARA rules {0}: {1}", resource, ex.Message);
            return false;
        }
    }

    // Startup canary (ADR 0028 decision 9): scan a tiny all-zero in-memory buffer under a short bound before
    // the engine is published. A corrupt ruleset does not terminate even on a 4-byte all-zero input, so this turns a
    // per-file, per-package mystery into one deterministic check. Same TryRunBounded shape as ScanFile — a
    // blocked native scan cannot be cancelled, so a stuck canary thread is simply abandoned. This runs under
    // Lazy<T>'s lock and blocks its caller, which is a second reason not to use the thread pool here: a
    // saturated pool could delay merely SCHEDULING the canary past its bound and discard a healthy engine for
    // the whole process.
    private static bool CanaryScanCompletes(Rules rules, Scanner scanner)
    {
        try
        {
            if (!TryRunBounded(() => scanner.ScanMemory(new byte[CanaryLength], rules), canaryTimeout, out _, out var error))
            {
                Warn("The in-process YARA engine FAILED its startup canary scan: {0} bytes did not complete within {1} (ADR 0028). The compiled ruleset is not usable; in-process malware-signature scanning is disabled.",
                    CanaryLength, canaryTimeout);
                return false;
            }

            if (error is not null)
                throw error;   // a faulted canary is a failed canary; reported by the shared handler below

            return true;
        }
        catch (Exception ex)
        {
            Warn("The in-process YARA engine FAILED its startup canary scan: {0} (ADR 0028). In-process malware-signature scanning is disabled.", ex.Message);
            return false;
        }
    }
    #endregion

    #region Fields
    // Size of the all-zero buffer scanned by the startup canary (ADR 0028 decision 9). A poisoned ruleset
    // fails to terminate on a 4-byte all-zero input, so this is ample; a healthy scan of a 1 MB buffer against
    // a subset of 128 rule files measured 15 ms all-zero / 18 ms random (yara-inprocess-timing-2026-08-21.tsv, E3).
    private const int CanaryLength = 64;

    // Compiled once, reused across files and packages (ADR 0016); null when nothing compiled. The rooted
    // YaraContext in the tuple keeps yr_finalize from running for the process lifetime.
    private static readonly Lazy<(YaraContext Context, Rules Rules, Scanner Scanner)?> sharedEngine = new(BuildEngine);

    // Per-file wall-clock bound for a single native ScanFile call (ADR 0016 decision 7). libyaraNET.Scanner's
    // OWN native timeout (10000 SECONDS, hardcoded, unconfigurable from its public API — see class doc) is
    // not a usable DoS bound, so this is Silvergun's own enforcement. 30s comfortably covers legitimate
    // assemblies/content while still bounding a pathologically slow scan to a small, predictable cost.
    private static readonly TimeSpan scanTimeout = TimeSpan.FromSeconds(30);

    // Wall-clock bound for the one-off startup canary scan (ADR 0028 decision 9). Deliberately much shorter
    // than scanTimeout: this is a 64-byte buffer, so anything but "instant" means the ruleset is not usable.
    private static readonly TimeSpan canaryTimeout = TimeSpan.FromSeconds(5);
    #endregion
}
#endif
