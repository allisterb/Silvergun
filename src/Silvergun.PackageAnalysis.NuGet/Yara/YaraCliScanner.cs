namespace Silvergun.PackageAnalysis.NuGet.Yara;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// The cross-platform <see cref="IYaraScanner"/> backend that drives the classic <c>yara</c>/<c>yarac</c> CLI
/// (ADR 0016). It is the non-Windows counterpart to the Windows backends (the out-of-process <c>YaraXWorkerScanner</c>
/// by default, the in-process <c>LibYaraScanner</c> as an explicit fallback); all compile the same embedded
/// ReversingLabs + custom ruleset, so verdicts match across platforms.
///
/// The <c>yara</c> binary is located from the <c>SILVERGUN_YARA_PATH</c> environment variable; the <c>yarac</c>
/// compiler is <c>SILVERGUN_YARAC_PATH</c> or, failing that, derived beside <c>yara</c>. When <c>yara</c> is
/// unset or missing the scanner degrades to a no-op (like <see cref="NullYaraScanner"/>) after a single note.
/// It prepares two rulesets, each lazily on first need, each in its own owner-only temp dir and compiled once with
/// <c>yarac</c> (or handed to yara as source when <c>yarac</c> is absent or fails): the batch ruleset, which adds the
/// coverage sentinel, for the one recursive <c>yara -r</c> run per <see cref="ScanDirectory"/> call; and the plain
/// ruleset for single-file runs, which happen only for <see cref="ScanFile"/> and for the files that recursive run
/// could not cover or attribute (re-scanned individually).
///
/// Lifetime: <see cref="Dispose"/> deletes those temp dirs, after the last scan in flight returns; a scan started
/// after it throws <see cref="YaraScanIncompleteException"/>. An instance that is never disposed — the process-wide
/// one <see cref="YaraScannerFactory"/> hands out — has its dirs deleted, best-effort, when the process exits.
///
/// Contract (the <see cref="IYaraScanner"/> one, ADR 0032): an empty result is a scan that happened and matched
/// nothing, or there is no <c>yara</c> binary at all (<see cref="Available"/>). All package content is hostile, so
/// the process is launched with an argument list (never a shell string), bounded by a timeout with
/// <c>Kill(entireProcessTree)</c>, and its output is parsed defensively.
///
/// Both <see cref="ScanFile"/> and <see cref="ScanDirectory"/> throw <see cref="YaraScanIncompleteException"/>
/// whenever what they did is <b>known</b> not to cover what they were asked to scan — the rules would not prepare,
/// the file was missing or its process failed, the tree would not enumerate, the recursive <c>yara -r</c> process
/// failed to start, exited nonzero or timed out, it exited 0 but printed an <c>error</c> line on stderr (an unopenable
/// file, or the one file mid-scan when its <c>--timeout</c> deadline passed — <c>yara -r</c> fails the run for
/// neither), a file it gave no positive coverage evidence for could not be re-scanned on its own, an unsafe-named file
/// could not be re-scanned through a safely named copy, or a hit could not be attributed (ADR 0029 decisions 13, 14
/// and 17; ADR 0032 decisions 5, 7 and 9). Returning a list for any of those would report content that was never
/// examined as a completed scan, and a hostile package can reach several of them on demand — files made expensive
/// enough to outlast yara's <c>--timeout</c> would otherwise buy a <see cref="YaraScanStatus.Completed"/> report with
/// the payload missing. In <c>-r</c> mode that timeout is ONE deadline for the whole run, and every file still queued
/// when it passes is dropped with exit 0 and <b>nothing</b> on stderr, so neither the exit code nor stderr is taken as
/// proof that a file was scanned: the recursive pass carries a coverage-sentinel rule that matches every file yara
/// actually examines, and a file with no sentinel line is re-scanned individually (ADR 0032 decision 9). Every such
/// exception thrown with hits in hand carries <b>all</b> of them in
/// <see cref="YaraScanIncompleteException.PartialFindings"/> (ADR 0032 decision 1): a package must not be able to
/// make its detected payload disappear by adding files that cannot be scanned. <c>PackageScanner.ScanYara</c>
/// reports those hits alongside <see cref="YaraScanStatus.Unavailable"/>.
/// </summary>
public sealed class YaraCliScanner : Runtime, IYaraScanner, IDisposable
{
    #region Constructors
    /// <param name="scanTimeoutMs">
    /// The wall-clock budget, and yara's <c>--timeout</c> under it, for one <c>yara</c> launch — a single-file scan, or
    /// the WHOLE recursive pass (yara applies <c>--timeout</c> to the run, not per file) — and the aggregate budget of
    /// the individual re-scan pass. A launch that outlives it plus a grace period is killed.
    /// </param>
    public YaraCliScanner(int scanTimeoutMs = DefaultScanTimeoutMs)
        : this(scanTimeoutMs, DefaultGraceMs)
    {
    }

    // The test seam for the grace period every kill and budget wait adds over scanTimeoutMs (production: the public
    // constructor's DefaultGraceMs). A negative grace would shorten the wall clock below yara's own --timeout, so it is
    // refused rather than normalized.
    internal YaraCliScanner(int scanTimeoutMs, int graceMs)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(graceMs);
        this.graceMs = graceMs;
        _scanTimeoutMs = scanTimeoutMs > 0 ? scanTimeoutMs : DefaultScanTimeoutMs;
        (_yaraPath, _yaracPath) = Locate();
        _ruleSet = new Lazy<RuleSet?>(() => CompileRules(sentinel: null));
        _batchRuleSet = new Lazy<RuleSet?>(() => CompileRules(sentinel: SentinelPrefix + RandomNumberGenerator.GetHexString(32, lowercase: true)));
    }
    #endregion

    #region Properties
    /// <summary><c>true</c> when a usable <c>yara</c> binary was located; otherwise the scanner is a no-op.</summary>
    public bool Available => _yaraPath is not null;
    #endregion

    #region Methods
    /// <summary>
    /// Scans <paramref name="fullPath"/> with <c>yara</c> against the compiled ruleset and maps the hits to
    /// <see cref="YaraMatch"/>. Returns empty when nothing matched, or when <c>yara</c> is unavailable (no engine at
    /// all — what <see cref="Available"/> reports). Throws <see cref="YaraScanIncompleteException"/> when this file
    /// was not scanned (ADR 0032 decision 5): the rules did not prepare, the file is missing or its path does not
    /// resolve, or the process failed to start, exited nonzero, timed out or faulted. The cause is logged (escaped)
    /// by <see cref="ScanOne"/>.
    /// </summary>
    public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
    {
        if (_yaraPath is null)
            return Array.Empty<YaraMatch>();   // no engine at all: Available already says so, honestly.

        return Admitted(
            () => ScanOne(
                    _ruleSet.Value ?? throw new YaraScanIncompleteException(
                        $"YARA could not prepare its embedded ruleset, so '{YaraPathSafety.Escape(fullPath)}' was NOT scanned and must not be reported as clean."),
                    fullPath)
                ?? throw new YaraScanIncompleteException(
                    $"YARA did not scan '{YaraPathSafety.Escape(fullPath)}' (the file is missing, its path does not resolve, or the yara process failed; see the preceding warning). This file was NOT scanned and must not be reported as clean."),
            () => new YaraScanIncompleteException(
                $"YARA's scanner has been disposed, so '{YaraPathSafety.Escape(fullPath)}' was NOT scanned and must not be reported as clean."));
    }

    /// <summary>
    /// Deletes the temp dirs holding this instance's prepared rulesets (best-effort: never throws; idempotent).
    /// Safe to call while scans are in flight — the dirs are deleted when the LAST of them returns, never under one —
    /// but the contract is to dispose only once no scan is in flight: every scan that starts after this call throws
    /// <see cref="YaraScanIncompleteException"/> rather than run without rules. The process-wide instance
    /// <see cref="YaraScannerFactory.Shared"/> is never disposed; its dirs are deleted when the process exits.
    /// </summary>
    public void Dispose()
    {
        bool release;
        lock (gate)
        {
            if (disposed)
                return;
            disposed = true;
            release = inFlight == 0;
        }

        if (release)
            DeleteRulesDirs();
    }

    // The single-file primitive behind ScanFile and the unsafe-name recovery pass below. Returns the (possibly
    // empty) hits, or NULL when the scan did not happen at all: missing file, unresolvable path, process start
    // failure, nonzero exit, timeout, exception. Null is never flattened to empty — ScanFile throws on it and the
    // recovery pass counts it as unrecovered — because "we could not scan this file" is what makes the whole
    // package Unavailable (ADR 0029 decision 13; ADR 0032 decision 5), and an empty list would silently read as clean.
    //
    // budgetMs caps this scan's wall clock at whatever is LEFT of the recovery pass's aggregate budget (see
    // ScanIndividually); null means the ordinary per-file budget.
    private IReadOnlyList<YaraMatch>? ScanOne(RuleSet ruleSet, string fullPath, int? budgetMs = null)
    {
        if (_yaraPath is null)
            return null;

        try
        {
            if (string.IsNullOrEmpty(fullPath) || !File.Exists(fullPath))
            {
                Warn("Skipping YARA scan for {0}: file not found on disk.", YaraPathSafety.Escape(fullPath));
                return null;
            }

            // Every hit this scan could yield has to be validated by comparing yara's echoed target against
            // fullPath, so a path that has no comparable form makes the scan UNVERIFIABLE — which is not the same
            // as clean. Falling through would run yara, reject every line it printed, and return an empty list that
            // reads as "recovered, scanned, nothing found": precisely the confusion decision 13 exists to prevent.
            if (TryNormalize(fullPath) is null)
            {
                Warn("Skipping YARA scan for {0}: its path does not resolve, so no hit on it could be verified.",
                    YaraPathSafety.Escape(fullPath));
                return null;
            }

            // The wall clock this launch may spend, and yara's own --timeout under it: the ordinary per-file budget,
            // or the remainder of the pass's aggregate budget when one was handed down, whichever is smaller.
            var waitMs = Math.Min(_scanTimeoutMs + graceMs, budgetMs ?? int.MaxValue);

            var options = new YaraOptions
            {
                Compiled = ruleSet.Compiled,
                PrintStrings = true,
                PrintTags = true,
                NoFollowSymlinks = true,
                Timeout = Math.Max(1, Math.Min(_scanTimeoutMs, waitMs) / 1000),
            };

            var args = options.ToArgs();
            args.Add(ruleSet.Path);
            args.Add(fullPath);

            var result = RunProcess(_yaraPath, args, waitMs);
            if (!result.Ok)
            {
                Warn("YARA scan of {0} failed: {1}", YaraPathSafety.Escape(fullPath), Explain(result));
                return null;
            }

            // The header regex is permissive enough to match arbitrary prose (a garbage/warning line on stdout
            // would otherwise fabricate a rule hit). yara only echoes the scanned path on a real match, and we
            // scan one known file — so keep only hits whose target resolves to fullPath and drop the rest. Of those, a
            // reserved-prefix record is foreign whatever its suffix: the plain ruleset carries no sentinel at all (see
            // WithoutForeignSentinels).
            var onTarget = YaraCliOutput.ParseAll(result.StdOut).Where(r => TargetMatches(r.Target, fullPath)).ToArray();
            return WithoutForeignSentinels(onTarget, ruleSet.Sentinel, fullPath)
                .Select(r => r.Match)
                .ToArray();
        }
        catch (Exception ex)
        {
            Warn("YARA scan failed for {0}: {1}", YaraPathSafety.Escape(fullPath), YaraPathSafety.Escape(ex.Message));
            return null;
        }
    }

    /// <summary>
    /// Scans every file under <paramref name="rootDir"/> in a <b>single</b> recursive <c>yara -r</c> process
    /// (far cheaper than one process per file), then attributes each hit to the real file its echoed target path
    /// resolves to. Output records whose target is not under the scanned root (prose, a warning line, a path outside
    /// the tree) are ignored as noise; one under the root that cannot be credited to a file fails the scan (below).
    /// A returned list, empty or not, means every enumerated file has <b>positive evidence</b> of having been scanned:
    /// the batch pass printed a coverage-sentinel line for it, or it was re-scanned on its own successfully — and the
    /// pass exited 0, printed no <c>error</c> line, and every hit it printed was attributed. Or the tree held no
    /// files, or there was nothing to scan at all (the backend is unavailable, or the directory does not exist). A
    /// file <c>yara</c> skipped without saying so — every file still queued when the recursive run's single
    /// <c>--timeout</c> deadline passes (ADR 0032 decision 9) — has no sentinel line and is therefore re-scanned
    /// individually, never assumed clean. A pass known to be missing files throws instead — see below.
    ///
    /// Files the batch output cannot faithfully name are excluded from it and scanned <b>individually</b>
    /// instead, so their coverage is recovered rather than dropped (ADR 0029; see
    /// <see cref="ScanIndividually"/>): names carrying a control character (the echoed path is line-split and the
    /// hit is lost), and names that share an echoed form with another entry (the package would otherwise choose
    /// which of its files a hit is credited to). The attributable files the batch pass printed no coverage-sentinel line
    /// for join them: the pass did not scan them, so they are scanned one at a time too.
    ///
    /// Throws <see cref="YaraScanIncompleteException"/> whenever the result is known to be missing files — the
    /// rules would not prepare, the tree would not enumerate, the batch process did not produce a usable run
    /// (start failure, nonzero exit, timeout), the batch process exited 0 but printed an <c>error</c> line on stderr
    /// (ADR 0032 decision 7: <c>yara -r</c> reports an unopenable file, and the one file mid-scan when its deadline
    /// passed, that way and still exits 0 — it says nothing at all about the files still queued, decision 9), an
    /// individual re-scan could not be performed, or the batch pass reported a hit under the root that could not be
    /// attributed to any file it enumerated (ADR 0029 decision 17: a dropped hit is missing coverage, not an absence
    /// of findings). Such a result must never be presented as a clean scan (ADR 0029 decisions 13, 14 and 17);
    /// <c>PackageScanner.ScanYara</c> maps it to <see cref="YaraScanStatus.Unavailable"/>. The exception carries
    /// every hit already in hand (ADR 0032): the batch pass's attributed hits, any unattributable one (decision 4,
    /// under its echoed target), and the individual pass's recovered hits — so a package cannot erase its detected
    /// payload by shipping 65 files whose names the batch output cannot round-trip, nor by shipping one file that
    /// yara cannot finish: a batch <c>error</c> line alone does not cancel the individual pass, it is thrown after it.
    /// </summary>
    public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
    {
        if (_yaraPath is null)
            return Array.Empty<(string, YaraMatch)>();   // no engine at all: Available already says so, honestly.

        return Admitted(
            () => ScanTree(rootDir),
            () => Incomplete($"scanner has been disposed, so nothing under '{YaraPathSafety.Escape(rootDir)}' was scanned"));
    }

    // ScanDirectory's body, run while admitted (see Admitted): the rulesets it prepares or uses cannot be deleted
    // under it. Every list of hits it returns or throws is de-duplicated per (file, namespace, rule) — see DistinctHits.
    private IReadOnlyList<(string FullPath, YaraMatch Match)> ScanTree(string rootDir)
    {
        // A ruleset that would not prepare means every file below is unscanned, which is exactly the state that
        // must not read as clean (decision 14) — the same reason ScanFile throws on it. This is the BATCH ruleset,
        // the one carrying the coverage sentinel; the individual pass prepares the plain one only if it is needed.
        var batchRuleSet = _batchRuleSet.Value
            ?? throw Incomplete($"could not prepare its embedded ruleset, so nothing under '{YaraPathSafety.Escape(rootDir)}' was scanned");

        string[] files;
        try
        {
            // Empty rather than Incomplete, deliberately: in production rootDir is NuGetPackage.ExtractionDir,
            // which the package CREATES and validates before any scan can be requested, so a missing root is not
            // reachable there — it is a degenerate direct call or a caller that deleted the tree under itself.
            // "There was nothing to scan" is therefore the honest reading, not "we failed to scan something"; a
            // package with content can never take this branch, so no coverage is being written off as clean here.
            if (string.IsNullOrEmpty(rootDir) || !Directory.Exists(rootDir))
            {
                Warn("Skipping YARA scan of {0}: directory not found on disk.", YaraPathSafety.Escape(rootDir));
                return Array.Empty<(string, YaraMatch)>();
            }

            files = Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            throw Incomplete($"could not enumerate '{YaraPathSafety.Escape(rootDir)}', so an unknown number of files went unscanned: {YaraPathSafety.Escape(ex.Message)}", ex);
        }

        // One pass over the names (ADR 0029 decisions 11-16), splitting them into the files the batch pass may be
        // trusted to name and the files that must be scanned one at a time.
        //
        // EchoKey is a conservative bound on how much of a path a `yara -r` header line can still carry: truncated
        // at the first control character, though the output path only ever cuts a line at a CR or an LF (the stdout
        // reader breaks lines at CR, LF and CRLF; ParseAll then splits the rejoined text on LF), and normalized
        // (which trims, as ParseAll's TrimEnd does). Two entries sharing an echo key are indistinguishable in that
        // output, and the package picks both names — so attributing such a hit means letting the package choose
        // which of its files gets blamed. Demonstrated shape: `content/a.bin\nZZZ` shipped alongside a real
        // `content/a.bin`, whose echoed target is identical; the same collision is reachable without any control
        // character at all, via a trailing space. Both members of every colliding group therefore leave the batch
        // pass, and neither loses coverage: they are re-scanned individually, where the target we hand yara is
        // unambiguous.
        //
        // ONE comparer decides all of it — OrdinalIgnoreCase here, in `forged`, in the attribution fallback and in
        // TargetMatches (decision 16). Mixing them reopened the evasion more CHEAPLY than the original: grouping
        // echo keys ordinally while vetoing and attributing case-insensitively left the payload `content/mal.dll`
        // ordinally distinct from the echo of an empty decoy named `content/MAL.dll\nx`, so the payload stayed in
        // the batch pass — and the case-folded veto then swallowed its genuine hit. Completed, zero findings.
        //
        // Why one comparer is sufficient: for any batch target T echoed for an enumerated file F, TryNormalize(T)
        // is either exactly EchoKey(F) or a string containing a C0 character (yara echoes the path verbatim; all the
        // output path can do to it is cut it at a CR or an LF and trim it). So once the partition and attribution
        // compare keys the same way, no non-attributable file's echo can reach an attributable file: every key such
        // a file can echo is shared with its group, and every member of a shared group is out of the attribution
        // table.
        //
        // The price of the conservative comparer over an OS-conditional one is that a Linux case-only duplicate
        // pair drops out of the cheap pass into individual re-scanning — bounded, rare, and far easier to prove
        // than a platform branch in the middle of a security decision (decision 16 records that trade).
        var keyed = files
            .Select(f => (File: f, Key: EchoKey(f), Unsafe: YaraPathSafety.IsUnsafeName(f)))
            .ToArray();

        var ambiguous = keyed
            .Where(x => x.Key is not null)
            .GroupBy(x => x.Key!, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Skip(1).Any())
            .Select(g => g.Key)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var split = keyed.ToLookup(x => !x.Unsafe && x.Key is not null && !ambiguous.Contains(x.Key!));
        var attributable = split[true].Select(x => x.File).ToArray();
        var individual = split[false].Select(x => (x.File, x.Unsafe)).ToArray();

        // Every truncation of an unsafe name: belt and braces over the partition above, so a forged target can
        // never be credited through the normalized fallback even to a file whose name differs from the truncation
        // only in case. It is applied AFTER the exact-ordinal check (see Attribute) — an exact ordinal echo of a
        // path we ourselves enumerated is the strongest evidence there is, and must not be vetoable by a name the
        // package chose.
        var forged = keyed
            .Where(x => x.Unsafe)
            .Select(x => x.Key)
            .OfType<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // The echoes the batch pass is EXPECTED not to place. `yara -r` walks the whole tree, so the files that
        // just left the batch pass still appear in its output; a record naming one of them is coverage taken
        // elsewhere (the recovery pass re-scans it), not coverage lost, and decision 17's dropped-hit counter must
        // not conflate the two.
        var deferred = split[false]
            .Select(x => x.Key)
            .OfType<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Nothing the recursive pass could attribute ⇒ do not spend a process on it (an empty tree, or one whose
        // every entry is being scanned individually anyway). This cannot lose a hit: attribution is closed over
        // `attributable`.
        var (batch, batchErrors, uncovered) = attributable.Length == 0
            ? (Array.Empty<(string FullPath, YaraMatch Match)>(), Array.Empty<string>(), Array.Empty<string>())
            : ScanBatch(batchRuleSet, rootDir, attributable, forged, deferred);

        // ADR 0032 decision 9: an attributable file the batch pass printed no coverage line for was NOT scanned by it
        // (yara -r drops every file still queued at its one --timeout deadline, exit 0, nothing on stderr), so it is
        // re-scanned on its own exactly like a deferred name — each in its own bounded single-file run that fails
        // closed on its exit code, the overflow past MaxIndividualScans or the pass budget counting as unrecovered.
        // Its batch hits, if the output somehow held any, are kept: a printed match is a detection either way.
        var rescan = individual.Concat(uncovered.Select(f => (File: f, Unsafe: false))).ToArray();

        // The batch hits are already in hand when the recovery pass gives up (an unrecoverable name, or more than
        // MaxIndividualScans of them — both package-selectable), so they travel with its exception rather than being
        // dropped by it (ADR 0032): the payload the batch pass found must survive 65 junk control-character names.
        //
        // A file with a batch hit but no coverage line keeps that hit AND is re-scanned, so the two passes can report the
        // same rule on the same file; DistinctHits folds that (and any repeated record) to one hit, on both exits.
        IReadOnlyList<(string FullPath, YaraMatch Match)> hits;
        try
        {
            hits = DistinctHits(rescan.Length == 0 ? batch : [.. batch, .. ScanIndividually(rootDir, rescan)]);
        }
        catch (YaraScanIncompleteException ex)
        {
            throw new YaraScanIncompleteException(
                batchErrors.Length == 0 ? ex.Message : $"{ex.Message.TrimEnd('.')}. {BatchErrors(rootDir, batchErrors)}",
                ex.InnerException,
                DistinctHits([.. batch, .. ex.PartialFindings]));
        }

        // ADR 0032 decision 7, thrown only now — AFTER the recovery pass — because the batch error lines are package-
        // selectable (files made to outlast yara's --timeout) and the batch pass may hold no hit at all: throwing
        // from ScanBatch would skip the recovery pass and let that one file erase a payload shipped under a
        // control-character name, turning a detection into Unavailable with zero findings. It stays, as defence in
        // depth, now that decision 9 re-scans every file without a coverage line: an error line is yara itself saying
        // that something went unscanned, and it is not parsed for WHICH file (decision 7), so it cannot be discharged.
        return batchErrors.Length == 0
            ? hits
            : throw new YaraScanIncompleteException(
                $"{BatchErrors(rootDir, batchErrors)} {hits.Count} hit(s) found in the files that were scanned are reported.",
                null,
                hits);
    }

    // The single recursive yara -r pass. Hits are attributed only to files in attributable (see ScanDirectory);
    // the echoed target must resolve to one of them, because the header regex is permissive enough to match
    // arbitrary prose and a garbage or attacker-authored line would otherwise fabricate a hit.
    //
    // Throws when the process did not produce a usable run (ADR 0029 decision 14). Returning an empty list there
    // was a false negative a package could buy on demand: one `yara -r` pushed past the timeout over the whole
    // tree — cheaper than any filename trick — and the report read Completed with zero findings.
    //
    // A usable run is still not proof that every file was scanned. `yara -r` reports a file it could not open, and the
    // one file mid-scan when its --timeout deadline passed, as an `error scanning <path>: …` line on stderr and exits 0
    // (ADR 0032 decision 7). Those lines come back as Errors, never parsed for a path (a CR or LF in a file name splits
    // a line, so path parsing is the fragile thing ADR 0029 is about): their existence alone fails the scan closed,
    // which ScanDirectory does after its recovery pass. Hits are returned alongside them, never dropped by them.
    //
    // And the absence of an error line is not proof either (ADR 0032 decision 9): in -r mode --timeout is ONE deadline
    // for the whole run, and every file still queued when it passes is dropped with exit 0 and NO line anywhere —
    // measured on yara 4.1.3, 1 of 20 slow files scanned, 0 error lines. So coverage is asked for, not inferred: the
    // batch ruleset carries a coverage-sentinel rule (`condition: true`, see CompileRules) that yara reports for every
    // file it actually examines. Sentinel lines are parsed and attributed exactly like hits; every attributable file
    // without one comes back as Uncovered, for ScanDirectory to re-scan individually. Sentinel records are coverage
    // evidence only, never hits: they never reach Hits, the decision 17 guard, a finding or a report.
    private (IReadOnlyList<(string FullPath, YaraMatch Match)> Hits, string[] Errors, string[] Uncovered) ScanBatch(
        RuleSet ruleSet, string rootDir, IReadOnlyList<string> attributable,
        IReadOnlySet<string> forged, IReadOnlySet<string> deferred)
    {
        // A batch ruleset is built with a sentinel by construction (CompileRules); this is the guard that keeps a path
        // that somehow lacks one from reporting a complete scan — without it, every file would read as covered by
        // nothing and nothing would distinguish that from yara having said nothing about any of them.
        var sentinel = ruleSet.Sentinel
            ?? throw Incomplete($"has no coverage sentinel in its batch ruleset, so it cannot tell which files under '{YaraPathSafety.Escape(rootDir)}' its recursive pass scanned");

        ProcessResult result;
        try
        {
            var options = new YaraOptions
            {
                Compiled = ruleSet.Compiled,
                Recurse = true,
                PrintStrings = true,
                PrintTags = true,
                NoFollowSymlinks = true,
                Timeout = Math.Max(1, _scanTimeoutMs / 1000),
            };

            var args = options.ToArgs();
            args.Add(ruleSet.Path);
            args.Add(rootDir);

            result = RunProcess(_yaraPath!, args, _scanTimeoutMs + graceMs);
        }
        catch (Exception ex)
        {
            throw Incomplete($"could not run its recursive pass over '{YaraPathSafety.Escape(rootDir)}', so no file under it was scanned: {YaraPathSafety.Escape(ex.Message)}", ex);
        }

        if (!result.Ok)
            throw Incomplete(
                $"did not complete its recursive pass over '{YaraPathSafety.Escape(rootDir)}' ({Explain(result)}), so no file under it was scanned",
                result.Outcome == ProcessOutcome.TimedOut ? new TimeoutException(Explain(result)) : null);

        // Attribution table, built once per pass. An exact ordinal echo of a path we enumerated is the only
        // unambiguous evidence of which file matched, so it is tried first; the normalized comparison that follows
        // is a tolerance for path spellings (separators, casing, trailing text on the line) and must therefore
        // refuse to guess when more than one enumerated file shares a normalized form — under the SAME
        // OrdinalIgnoreCase the partition used, so the two can never disagree about what "shared" means.
        var exact = attributable.ToHashSet(StringComparer.Ordinal);
        var normalized = attributable
            .Select(f => (Key: TryNormalize(f), File: f))
            .Where(x => x.Key is not null)
            .GroupBy(x => x.Key!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Skip(1).Any() ? null : g.First().File, StringComparer.OrdinalIgnoreCase);

        var root = TryNormalize(rootDir);
        // Sentinel lines go through the SAME header parsing and the SAME Attribute as real hits (ADR 0032 decision 9):
        // coverage is credited to exactly the file a hit on that line would have been credited to, no more leniently.
        // The rule name is compared ordinally against this ruleset's own sentinel, which carries a per-ruleset random
        // suffix, so a line the package authored (an LF in a file name lets it start a physical line of its own) cannot
        // claim coverage for a file yara dropped: it would have to guess 128 random bits. A record that guesses wrong —
        // the reserved prefix with any other suffix — is removed before anything else sees it (WithoutForeignSentinels):
        // no shipped rule carries the prefix, so it is forged output, and it must become neither a hit, nor coverage,
        // nor a decision 17 dropped hit that would turn the package Unavailable.
        var records = WithoutForeignSentinels(YaraCliOutput.ParseAll(result.StdOut), sentinel, rootDir)
            .Select(r => (r.Target, Key: TryNormalize(r.Target), r.Match, Sentinel: string.Equals(r.Match.Rule, sentinel, StringComparison.Ordinal)))
            .Select(x => (x.Target, x.Key, x.Match, x.Sentinel, File: Attribute(x.Target, x.Key)))
            .ToArray();

        // The files yara is known to have scanned: those an attributed sentinel line names. Every other attributable
        // file is Uncovered and goes to the individual pass. An UNATTRIBUTABLE sentinel line is deliberately ignored —
        // neither coverage nor a detection, and not a decision 17 dropped hit. Ignoring it is the fail-closed choice
        // that cannot flip a benign package: it credits coverage to nothing, so the worst it can do is leave a file
        // Uncovered and re-scanned. Treating one as "coverage unknown" and failing the package would buy nothing — the
        // attributable files' coverage is already decided above, by their own lines — and would flip benign packages:
        // any tree with a deferred name produces such lines by design (yara -r walks the deferred files too, and their
        // sentinel echoes are unattributable by the partition above), so every such package would read Unavailable
        // with no finding to show for it, even after the individual pass had covered those files properly.
        var covered = records
            .Where(x => x.Sentinel && x.File is not null)
            .Select(x => x.File!)
            .ToHashSet(StringComparer.Ordinal);
        var uncovered = attributable.Where(f => !covered.Contains(f)).ToArray();

        // ADR 0029 decision 17. A record this pass cannot place is either noise — prose, a warning, a directory, a
        // path outside the tree, an attacker-authored second line naming /etc/passwd — or a hit we SAW and could
        // not credit to anything, which is missing coverage. Silently discarding both was the channel the comparer
        // evasion above travelled through: it produced a clean report with no counter and no log line. So a target
        // that resolves under the scanned root and does not belong to a file the recovery pass is re-scanning is
        // counted, logged escaped, and fails the package closed instead of returning the survivors as the story.
        //
        // The exclusion compares the target's ECHO KEY, not its normalized form (decision 17a). The two differ for
        // exactly the deferred files this is meant to exclude: `yara -r` echoes the name verbatim, and the only
        // characters that cut the echo are CR and LF — RunProcess reads stdout through OutputDataReceived, whose
        // AsyncStreamReader breaks lines at CR, LF and CRLF and rejoins them with '\n' before ParseAll splits on
        // '\n'. So a deferred file whose first control character is a TAB or any of 0x01-0x08 / 0x0B / 0x0C /
        // 0x0E-0x1F still arrives with that character intact (0x0D is absent from that list precisely BECAUSE it
        // cuts the line: a CR never survives to reach ParseAll — do not "restore" it here). Such a target's
        // normalized form is nothing in `deferred`, and comparing it would fire this guard on a recovery that is
        // about to succeed, turning a finding the individual pass would have attributed correctly into Unavailable
        // with zero findings. That is the outcome decisions 11-13 exist to prevent, reached from the other side.
        //
        // Widening the exclusion from key to echo key cannot suppress a genuine hit from any file this pass
        // enumerated: this filter only sees records that Attribute could NOT place, and no attributable file's echo
        // has an echo key in `deferred` — an attributable file is C0-free, so its echo key is its key, and any
        // enumerated file sharing an echo key with a deferred entry is ambiguous under the same comparer and hence
        // deferred itself. The attributable keys and `deferred` are disjoint by the partition. The claim is scoped
        // to enumerated files on purpose: it says nothing about a target belonging to no enumerated file that
        // happens to truncate onto a deferred key (an attacker-authored extra output line, or a file created
        // between Directory.GetFiles and the scan). Both are unreachable in our threat model — we execute no
        // package code and pass NoFollowSymlinks — and the pre-17a predicate had the same hole.
        //
        // Firing the guard must not cost the hits it fired on, nor the ones already attributed (ADR 0032 decision 4):
        // an unattributable hit is a DETECTION whose attribution is uncertain, not an absence. Both travel with the
        // exception — the unattributable ones under the target yara echoed (raw here, escaped at the report boundary
        // like every other path). A forged extra line can only make the package's own report look worse.
        var dropped = records
            .Where(x => !x.Sentinel && x.File is null && x.Key is { } key && IsUnderRoot(key) && !IsDeferredEcho(x.Target))
            .Select(x => (Target: x.Target!, x.Match))
            .ToArray();

        var attributed = records
            .Where(x => !x.Sentinel && x.File is not null)
            .Select(x => (x.File!, x.Match))
            .ToArray();

        // ADR 0032 decision 7: any trimmed stderr line starting with "error" means at least one file went unscanned.
        // `warning:` lines (e.g. the uncompiled-rules fallback) do not count. Logged here, once, escaped and bounded;
        // the throw is ScanDirectory's (see above). Computed BEFORE the decision 17 guard so that, when both fire, the
        // one exception names both causes and carries both sets of hits.
        var errors = result.StdErr
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.StartsWith("error", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (errors.Length > 0)
            Warn("YARA: the recursive pass over {0} exited 0 but reported {1} error line(s), so at least one file under it was not scanned. Line(s), control characters escaped: {2}",
                YaraPathSafety.Escape(rootDir), errors.Length, YaraPathSafety.Bounded(errors));

        if (dropped.Length > 0)
        {
            var targets = dropped.Select(x => x.Target).ToArray();
            Warn("YARA: {0} hit(s) from the recursive pass over {1} could not be attributed to any file it enumerated. Target(s), control characters escaped: {2}",
                dropped.Length, YaraPathSafety.Escape(rootDir), Describe(rootDir, targets));

            // Thrown here, before the recovery pass, as decision 17 always was; it always carries at least one hit.
            throw new YaraScanIncompleteException(
                $"YARA matched {dropped.Length} target(s) under '{YaraPathSafety.Escape(rootDir)}' that could not be attributed to any file it enumerated; they are reported under the path yara echoed, and this package must not be reported as clean. Target(s), control characters escaped: {Describe(rootDir, targets)}"
                + (errors.Length == 0 ? string.Empty : $". {BatchErrors(rootDir, errors)}"),
                null,
                DistinctHits([.. attributed, .. dropped]));
        }

        if (uncovered.Length > 0)
            Warn("YARA: the recursive pass over {0} exited 0 but printed no coverage line for {1} of {2} file(s), so it did not scan them (its --timeout is one deadline for the whole run, and files still queued when it passes are skipped silently); they are re-scanned individually. Path(s), control characters escaped: {3}",
                YaraPathSafety.Escape(rootDir), uncovered.Length, attributable.Count, Describe(rootDir, uncovered));

        return (attributed, errors, uncovered);

        // Strictly below the scanned root, in the same comparable form attribution uses. Anything else is not this
        // package's coverage and is not counted as lost. Only '/' separates: TryNormalize has already folded
        // backslashes on Windows, and on Linux a backslash is an ordinary filename character, so accepting one here
        // would read a sibling literally named "<root>\evil" as living under the root.
        bool IsUnderRoot(string key) =>
            root is not null
            && key.Length > root.Length
            && key.StartsWith(root, StringComparison.OrdinalIgnoreCase)
            && key[root.Length] is '/';

        // Whether this echoed target is the batch pass's (necessarily unattributable) echo of a file the recovery
        // pass is re-scanning — see the dropped-hit filter above. A target that normalizes to nothing at all is
        // not one of ours and is left to the guard.
        bool IsDeferredEcho(string target) => EchoKey(target) is { } echo && deferred.Contains(echo);

        string? Attribute(string? target, string? key)
        {
            if (target is null || key is null)
                return null;   // prose, or text that is not a usable path at all

            // Evidence beats veto (decision 16): this is an ordinal echo of a path WE enumerated and handed to no
            // one, so no name the package chose may suppress it. The tolerant fallback below is the vetoable one.
            if (exact.Contains(target))
                return target;

            return !forged.Contains(key) && normalized.TryGetValue(key, out var file) ? file : null;
        }
    }

    // ADR 0029 decisions 11-13 and 15. classic yara echoes the scanned path on every header line and its output is
    // line-oriented, so a control character in a file name — legal in a zip entry, written to disk verbatim by the
    // extractor, therefore ATTACKER-CONTROLLED — splits that file's hit across two physical lines and the batch
    // pass silently drops it; a name that collides with another entry's echoed form is just as unattributable, and
    // worse, because the collision decides who gets blamed. Coverage is RECOVERED, not merely reported: each such
    // file is scanned on its own, an unsafe-named one through a temp copy with a name WE generate (so the echoed
    // target is a path we chose and validates through TargetMatches unchanged), and its hits attributed back to
    // the real path. If even one of them cannot be recovered, this throws rather than returning a partial list,
    // because a result known to be missing hits must not read as a completed clean scan — the caller maps that to
    // YaraScanStatus.Unavailable. The hits it did recover travel with the exception (ADR 0032), never dropped by it.
    //
    // ADR 0032 decision 9 sends the batch pass's UNCOVERED files here too — attributable names the pass printed no
    // coverage-sentinel line for — under the same bounds and the same fail-closed accounting. They are scanned with
    // the plain ruleset (no sentinel: a single-file run's exit code already says whether it scanned its one file),
    // prepared on first need; if it will not prepare, every target is unrecovered.
    private IReadOnlyList<(string FullPath, YaraMatch Match)> ScanIndividually(
        string rootDir, IReadOnlyList<(string File, bool Unsafe)> targets)
    {
        Warn("YARA: {0} file(s) under {1} were not covered by the recursive pass (a name its output cannot attribute — control characters, or an echoed path shared with another entry — or no coverage line for it); re-scanning each in isolation. Path(s), control characters escaped: {2}",
            targets.Count, YaraPathSafety.Escape(rootDir), Describe(rootDir, targets.Select(t => t.File).ToArray()));

        var ruleSet = _ruleSet.Value;
        var staging = targets.Any(t => t.Unsafe) ? CreateStagingDir() : null;
        var hits = new List<(string, YaraMatch)>();
        var unrecovered = new List<string>();
        var elapsed = Stopwatch.StartNew();
        var budgetMs = _scanTimeoutMs + graceMs;
        var attempted = 0;

        foreach (var (file, isUnsafe) in targets)
        {
            // The work this pass may do is bounded in BOTH directions the package controls: a tree with thousands
            // of unattributable names must not turn one process into thousands, and the pass as a whole must not
            // outlive the wall clock a single batch was allowed. The aggregate bound is enforced by handing each
            // scan only what is LEFT of it rather than a fresh copy — checking it merely before each launch would
            // let the pass overrun by nearly one whole scan budget. Whatever the budget does not cover counts as
            // UNRECOVERED, never as quietly clean (decision 13): a scan killed by the remainder returns null just
            // like one that was never attempted, and either way the overflow makes the package Unavailable.
            //
            // Neither a link nor a file reached THROUGH a linked directory is handed to a single-file scan or copied:
            // -N only stops yara -r from following links while it walks a tree (which is why the batch pass printed no
            // coverage line for a file under a linked directory — Directory.GetFiles followed the link on Linux, yara
            // did not), whereas a single-file yara opens the path it is given and WOULD follow every link in it out of
            // the package: other content blamed on an in-package path, or a link into /dev blocking until the budget
            // runs out. Such a file counts as unrecovered, before any launch (IsLink checks the leaf AND every
            // directory between rootDir and it; ScanViaSafeCopy repeats the check at its File.Copy).
            var remainingMs = budgetMs - (int)Math.Min(budgetMs, elapsed.ElapsedMilliseconds);
            var matches = ruleSet is null || attempted >= MaxIndividualScans || remainingMs <= 0 ? null
                : IsLink(rootDir, file) ? RefuseLink(file)
                : isUnsafe ? (staging is null ? null : ScanViaSafeCopy(ruleSet, rootDir, staging, file, attempted, remainingMs))
                : ScanOne(ruleSet, file, remainingMs);
            attempted++;

            if (matches is null)
                unrecovered.Add(file);
            else
                hits.AddRange(matches.Select(match => (file, match)));
        }

        if (staging is not null)
            try { Directory.Delete(staging, recursive: true); } catch { /* best effort: a leaked temp dir must not fail a scan */ }

        return unrecovered.Count == 0
            ? hits
            : throw new YaraScanIncompleteException(
                $"YARA could not scan {unrecovered.Count} of {targets.Count} file(s) that its recursive pass did not cover (names its batch output cannot round-trip, or files it printed no coverage line for), so this package was NOT fully scanned and must not be reported as clean. Path(s), control characters escaped: {Describe(rootDir, unrecovered)}",
                null,
                hits);

        IReadOnlyList<YaraMatch>? RefuseLink(string file)
        {
            Warn("YARA will not re-scan {0} on its own: it is a link or lies under a linked directory, and following it would scan content outside the package.",
                YaraPathSafety.Escape(file));
            return null;
        }
    }

    // Copies one unsafe-named file to a generated safe name and scans the copy, returning its (possibly empty)
    // hits, or null when the copy or the scan did not happen. The copy is deleted afterwards, best-effort.
    // budgetMs is the remainder of the recovery pass's aggregate wall clock, passed straight through to the scan.
    private IReadOnlyList<YaraMatch>? ScanViaSafeCopy(
        RuleSet ruleSet, string rootDir, string stagingDir, string fullPath, int ordinal, int? budgetMs = null)
    {
        // Both yara invocations are launched with -N precisely so a link in package content cannot be followed out
        // of the extraction tree; File.Copy has no such option and WOULD follow it — the leaf or any linked directory
        // on the way to it — so such a file is never copied. It counts as unrecovered rather than as scanned-and-clean.
        if (IsLink(rootDir, fullPath))
        {
            Warn("YARA will not copy {0} to a safely named temp file: it is a link or lies under a linked directory, and following it would scan content outside the package.",
                YaraPathSafety.Escape(fullPath));
            return null;
        }

        var copy = Path.Combine(stagingDir, $"unsafe-{ordinal:D5}.bin");
        try
        {
            File.Copy(fullPath, copy, overwrite: true);
        }
        catch (Exception ex)
        {
            // ex.Message quotes the source path on Unix ("Access to the path '…' is denied."), and this path holds
            // a control character BY CONSTRUCTION — escaping only the other argument would leave the log forgeable.
            Warn("YARA could not copy {0} to a safely named temp file: {1}",
                YaraPathSafety.Escape(fullPath), YaraPathSafety.Escape(ex.Message));
            return null;
        }

        try
        {
            return ScanOne(ruleSet, copy, budgetMs);
        }
        finally
        {
            try { File.Delete(copy); } catch { /* best effort */ }
        }
    }

    // Whether opening fullPath could follow a link: the file itself is one, OR any directory between rootDir
    // (exclusive — the extraction root is ours) and the file is one. The walk is over fullPath's OWN text, a lexical
    // strip of rootDir (YaraPathSafety.Relative, the way every enumerated path begins), so no normalizer can re-spell a
    // component and check a different directory than the one a single-file yara would traverse. A path that is not
    // lexically under rootDir, or any exception, reads as a link: we cannot vouch for it, so it is not followed.
    private static bool IsLink(string rootDir, string fullPath)
    {
        try
        {
            var start = fullPath.Length - YaraPathSafety.Relative(rootDir, fullPath).Length;
            return start == 0
                || new FileInfo(fullPath).LinkTarget is not null
                || Enumerable.Range(start, fullPath.Length - start)
                    .Where(i => fullPath[i] == Path.DirectorySeparatorChar || fullPath[i] == Path.AltDirectorySeparatorChar)
                    .Any(i => new DirectoryInfo(fullPath[..i]).LinkTarget is not null);
        }
        catch
        {
            return true;   // cannot tell ⇒ do not follow it
        }
    }

    // The temp directory holding the safely named copies, or null (logged) when it cannot be created — in which
    // case no unsafe-named file can be recovered and the scan fails closed. On Unix it is created owner-only: it
    // briefly holds a copy of hostile package content in a world-writable /tmp.
    private string? CreateStagingDir()
    {
        try
        {
            return CreatePrivateTempDir("silvergun-yara-safe-");
        }
        catch (Exception ex)
        {
            Warn("YARA could not create a temp directory in which to re-scan control-character file names: {0}",
                YaraPathSafety.Escape(ex.Message));
            return null;
        }
    }

    // The ADR 0029 decision 14 seam. Every "the scan did not really happen" condition in ScanDirectory raises the
    // SAME exception the partial-recovery failure raises, rather than the TimeoutException carve-out of ADR 0028
    // decision 10: one seam is enough, PackageScanner.ScanYara already turns it into YaraScanStatus.Unavailable,
    // and the message can name the actual cause. A timeout additionally carries a TimeoutException as its
    // InnerException, so that cause stays machine-readable for a caller that wants to distinguish it. Every site using
    // this helper throws before any hit is trusted, so there are no partial findings to carry (ADR 0032): on a nonzero
    // exit yara's stdout IS captured, but deliberately not parsed, because a run that failed vouches for nothing it printed.
    private static YaraScanIncompleteException Incomplete(string what, Exception? inner = null) =>
        new($"YARA {what}. This package was NOT scanned and must not be reported as clean.", inner);

    // Why a process produced no usable run, as a log/message fragment. yara's own stderr is included when it said
    // anything, one item per non-blank line, escaped and bounded (YaraPathSafety.Bounded): it echoes paths, those
    // paths are package content, and a package can make yara print one line per file it ships.
    private static string Explain(ProcessResult result)
    {
        var reason = result.Outcome switch
        {
            ProcessOutcome.StartFailed => "the yara process could not be started",
            ProcessOutcome.TimedOut => "the yara process exceeded its time budget and was killed",
            ProcessOutcome.Faulted => "the yara process could not be run",
            _ => $"yara exited with code {result.ExitCode}",
        };

        var lines = result.StdErr.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return lines.Length == 0 ? reason : $"{reason}: {YaraPathSafety.Bounded(lines)}";
    }

    // Renders offending paths for a log line: package-relative where possible, always control-escaped so this
    // attacker-authored text cannot forge a line in our own log, and capped so a package full of them cannot
    // flood it (YaraPathSafety.Bounded, the one rendering every YARA message shares).
    // The relative form is the lexical strip YaraPathSafety.Relative, not Path.GetRelativePath, which would render
    // a device-named entry (COM1.dll) as "\\.\COM1" on Windows (ADR 0030, sixth instance).
    private static string Describe(string rootDir, IReadOnlyList<string> paths) =>
        YaraPathSafety.Bounded(paths.Select(p => YaraPathSafety.Relative(rootDir, p)).ToArray());

    // The message fragment for ADR 0032 decision 7: the batch pass exited 0 but printed error line(s) on stderr.
    // yara echoes package paths in those lines, so they are escaped and bounded like any other package text.
    private static string BatchErrors(string rootDir, IReadOnlyList<string> errors) =>
        $"YARA's recursive pass over '{YaraPathSafety.Escape(rootDir)}' exited 0 but reported {errors.Count} error line(s), so at least one file under it was NOT scanned and this package must not be reported as clean. Line(s), control characters escaped: {YaraPathSafety.Bounded(errors)}.";

    // True when a parsed header target refers to the file we actually scanned. ScanFile always hands yara the
    // ABSOLUTE fullPath and classic yara echoes that path verbatim, so the robust, platform-independent primitive is
    // normalized exact equality (case-insensitive, '/' and '\' treated alike). A bidirectional raw-string EndsWith
    // would over-match across a filename-character boundary (e.g. "ab.dll" vs "b.dll") on POSIX, where GetFullPath
    // does not drive-root the input — so we deliberately do NOT do that. Any parse/normalize failure ⇒ "no match".
    //
    // The case-insensitive comparison is not a Windows convenience: it is the ONE comparer this backend uses
    // wherever two paths are compared (ADR 0029 decision 16) — the partition's echo-key grouping, the forged set,
    // the attribution fallback and this predicate. They must agree about when two paths are "the same", or a file
    // is attributable under one rule and conflated under another, which is exactly the gap that reopened the
    // false negative.
    internal static bool TargetMatches(string? target, string fullPath) =>
        TryNormalize(target) is { } t
        && TryNormalize(fullPath) is { } f
        && t.Equals(f, StringComparison.OrdinalIgnoreCase);

    // The comparable form of a path: absolute, trailing-separator-free and — on Windows only — '/'-folded, because
    // backslash is a path separator there and a legal filename character everywhere else, where folding it would
    // mis-normalize a real path and drop a genuine hit. Leading/trailing whitespace is trimmed, since one side of
    // every comparison is text read off a yara output line. Null when the text is not a usable path.
    internal static string? TryNormalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        try
        {
            var p = Path.GetFullPath(path.Trim());
            if (OperatingSystem.IsWindows())
                p = p.Replace('\\', '/');
            return p.TrimEnd('/');
        }
        catch
        {
            return null;
        }
    }

    // A conservative bound on how much of a path a batch header line can carry, in comparable form: truncated at
    // the first control character — conservative because the echo is only ever cut at a CR or an LF (the stdout
    // reader breaks lines at CR, LF and CRLF; YaraCliOutput.ParseAll then splits the rejoined text on LF) — and
    // normalized (which trims, as ParseAll's per-line TrimEnd does). Two entries with the same echo key are
    // indistinguishable in `yara -r` output, so neither may be attributed from it — see ScanDirectory.
    private static string? EchoKey(string path) => TryNormalize(YaraPathSafety.TruncateAtFirstControl(path));

    // Resolves (yara, yarac) from the environment. Missing/blank/nonexistent yara ⇒ (null, null) plus a
    // one-time note. yarac comes from SILVERGUN_YARAC_PATH or is derived beside yara; if it cannot be found the
    // scanner still works by handing yara the uncompiled source (yara compiles rules at scan time).
    private static (string? Yara, string? Yarac) Locate()
    {
        var yara = Environment.GetEnvironmentVariable(YaraPathVar);
        if (string.IsNullOrWhiteSpace(yara) || !File.Exists(yara))
        {
            if (Interlocked.Exchange(ref unavailableNoted, 1) == 0)
                Debug("YARA malware-signature scanning unavailable (set {0} to the yara binary). Continuing without it.", YaraPathVar);
            return (null, null);
        }

        var yarac = Environment.GetEnvironmentVariable(YaracPathVar);
        if (string.IsNullOrWhiteSpace(yarac) || !File.Exists(yarac))
            yarac = DeriveYarac(yara);

        return (yara, yarac is not null && File.Exists(yarac) ? yarac : null);
    }

    // Derives the yarac path beside the yara binary: "yara[.ext]" ⇒ "yarac[.ext]".
    private static string? DeriveYarac(string yaraPath)
    {
        try
        {
            var dir = Path.GetDirectoryName(yaraPath) ?? string.Empty;
            var name = Path.GetFileNameWithoutExtension(yaraPath);
            var ext = Path.GetExtension(yaraPath);
            var yaracName = (name.EndsWith("yara", StringComparison.OrdinalIgnoreCase) ? name + "c" : "yarac") + ext;
            return Path.Combine(dir, yaracName);
        }
        catch
        {
            return null;
        }
    }

    // Writes the embedded ruleset to a temp file and compiles it once with yarac. Returns the compiled rules
    // (preferred) or, if yarac is absent or fails, the uncompiled source (yara compiles at scan time). Returns
    // null when there are no rules, writing failed, or the sentinel guard below fired — and a null ruleset is never
    // read as "no matches": ScanFile and ScanDirectory both throw YaraScanIncompleteException on it (ADR 0032
    // decision 5), and the individual pass counts every file it was handed as unrecovered.
    //
    // With a sentinel name (the batch ruleset, ADR 0032 decision 9) the coverage-sentinel rule is appended to the
    // SOURCE, before either path forks, so the compiled and the uncompiled ruleset both carry it — there is no way to
    // obtain a batch RuleSet without one. It lives in the default namespace with the embedded rules, so an exact name
    // collision is also a compile error in yarac and in yara (a duplicated identifier); that only ever fails closed
    // (no compiled set ⇒ uncompiled ⇒ yara exits nonzero ⇒ the pass is Incomplete). The guard here refuses earlier
    // and more broadly: the embedded text may not contain the reserved prefix AT ALL, case-insensitively, so no
    // embedded rule can share, shadow or be mistaken for the sentinel. The random suffix makes the name unguessable
    // by a package, which is what keeps an attacker-authored output line from claiming coverage (see ScanBatch).
    private RuleSet? CompileRules(string? sentinel)
    {
        if (_yaraPath is null)
            return null;

        try
        {
            // Owner-only on Unix, like the staging dir: it holds the batch ruleset, whose sentinel name is the secret
            // that keeps package-authored output from claiming coverage. Registered for deletion the moment it exists,
            // so even a preparation that fails below leaves nothing behind (Dispose, or the process-exit fallback).
            var dir = CreatePrivateTempDir("silvergun-yara-");
            TrackRulesDir(dir);

            var sourcePath = Path.Combine(dir, "silvergun-rules.yara");
            var sb = new StringBuilder();
            var count = 0;
            foreach (var (name, text) in YaraRuleResources.ReadAll(GetType().Assembly))
            {
                sb.Append("// ").Append(name).Append('\n').Append(text).Append('\n');
                count++;
            }

            if (count == 0)
            {
                Warn("No embedded YARA rules found; malware-signature scanning is disabled.");
                return null;
            }

            if (sentinel is not null)
            {
                if (sb.ToString().Contains(SentinelPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    Warn("The embedded YARA rules use the reserved coverage-sentinel name prefix '{0}', so the recursive pass could not tell which files it scanned; refusing to prepare it.", SentinelPrefix);
                    return null;
                }

                sb.Append("// Silvergun coverage sentinel (ADR 0032 decision 9): matches every file yara examines; never a finding.\n")
                  .Append("rule ").Append(sentinel).Append(" { condition: true }\n");
            }

            File.WriteAllText(sourcePath, sb.ToString());

            if (_yaracPath is null)
            {
                Info("Compiled {0} embedded YARA rule file(s); yarac not found, scanning with uncompiled rules.", count);
                return new RuleSet(sourcePath, Compiled: false, sentinel);
            }

            var compiledPath = Path.Combine(dir, "silvergun-rules.yarac");
            var result = RunProcess(_yaracPath, new List<string> { sourcePath, compiledPath }, _scanTimeoutMs + graceMs);
            if (!result.Ok || !File.Exists(compiledPath))
            {
                // Not an incomplete scan: yara compiles the source at scan time, so the pass still covers every file.
                Warn("yarac failed to compile embedded YARA rules ({0}); scanning with uncompiled rules.", Explain(result));
                return new RuleSet(sourcePath, Compiled: false, sentinel);
            }

            Info("Compiled {0} embedded YARA rule file(s) with yarac for malware-signature scanning.", count);
            return new RuleSet(compiledPath, Compiled: true, sentinel);
        }
        catch (Exception ex)
        {
            Warn("Failed to prepare embedded YARA rules: {0}", YaraPathSafety.Escape(ex.Message));
            return null;
        }
    }

    // A fresh, uniquely named directory under the temp path: owner-only (0700) on Unix, where the temp path is shared
    // with every other local user. Throws on failure; the callers decide what that means.
    private static string CreatePrivateTempDir(string prefix)
    {
        var dir = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        return (OperatingSystem.IsWindows()
            ? Directory.CreateDirectory(dir)
            : Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute)).FullName;
    }

    // Runs one public scan while ADMITTED: counted in flight, so Dispose cannot delete the rules dirs under it (the
    // last admitted scan to return deletes them instead). Once Dispose has been called nothing is admitted, and the
    // scan throws `refused` — fail-closed, inside the IYaraScanner contract — rather than run without its rules.
    // Everything that prepares a ruleset (the Lazy values, hence CompileRules) runs only in here, so no rules dir can
    // be created after the deletion.
    private T Admitted<T>(Func<T> scan, Func<YaraScanIncompleteException> refused)
    {
        lock (gate)
        {
            if (disposed)
                throw refused();
            inFlight++;
        }

        try
        {
            return scan();
        }
        finally
        {
            bool release;
            lock (gate)
                release = --inFlight == 0 && disposed;
            if (release)
                DeleteRulesDirs();
        }
    }

    // Records a rules dir this instance created: per instance, for Dispose, and process-wide, for the exit fallback.
    private void TrackRulesDir(string dir)
    {
        undeletedRulesDirs.TryAdd(dir, 0);
        lock (gate)
            rulesDirs.Add(dir);
    }

    // Deletes this instance's rules dirs. Reached exactly once, with nothing in flight (Dispose or Admitted).
    private void DeleteRulesDirs()
    {
        string[] dirs;
        lock (gate)
        {
            dirs = [.. rulesDirs];
            rulesDirs.Clear();
        }

        foreach (var dir in dirs)
            DeleteRulesDir(dir);
    }

    // Best-effort, never throws. A dir that would not delete (e.g. a still-running yara holding its file open on
    // Windows) stays in the process-wide registry for the exit fallback; one that is gone leaves it.
    private static void DeleteRulesDir(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
            undeletedRulesDirs.TryRemove(dir, out _);
        }
        catch
        {
            /* best effort: a leaked temp dir must not fail a scan or a dispose */
        }
    }

    // The process-wide registry of rules dirs not yet deleted, with the ProcessExit fallback that deletes them,
    // registered once. It holds directory PATHS only, never scanner instances, so it keeps no scanner alive. It deletes
    // nothing but the dirs this process created: other processes' silvergun-yara-* dirs may be in use and are left
    // alone.
    private static ConcurrentDictionary<string, byte> CreateExitRegistry()
    {
        var dirs = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            foreach (var dir in dirs.Keys)
                DeleteRulesDir(dir);
        };
        return dirs;
    }

    // One hit per (file, namespace, rule). yara reports a rule at most once per file per pass, so a repeat only ever
    // comes from two passes over one file (a batch hit on a file the batch pass printed no coverage line for, which is
    // then re-scanned) or from a forged output line — never from two distinct detections. Paths compare ordinally:
    // both sides are our own enumeration or yara's exact echo of it.
    private static IReadOnlyList<(string FullPath, YaraMatch Match)> DistinctHits(
        IEnumerable<(string FullPath, YaraMatch Match)> hits) =>
        hits.DistinctBy(h => (h.FullPath, h.Match.Namespace, h.Match.Rule)).ToArray();

    // Removes every record whose rule name uses the reserved sentinel prefix (case-insensitively) but is not the
    // exact sentinel of the ruleset in use (`sentinel`; null for the plain ruleset, which has none). No shipped rule
    // carries the prefix (CompileRules refuses it for the batch ruleset; the embedded rules are pinned never to), so
    // such a record is output the scanned content forged — an LF in a file name lets it start a line of its own — and
    // removing it cannot suppress a genuine detection. It is neither a hit, nor coverage, nor a decision 17 dropped hit
    // nor any other Incomplete signal; one warning says it happened, its echoed targets escaped and bounded (the rule
    // names are not repeated: they are package-authored and say nothing the prefix does not).
    private static IReadOnlyList<(YaraMatch Match, string Target)> WithoutForeignSentinels(
        IReadOnlyList<(YaraMatch Match, string Target)> records, string? sentinel, string scanned)
    {
        var foreign = records.Where(r => IsForeignSentinel(r.Match.Rule, sentinel)).ToArray();
        if (foreign.Length == 0)
            return records;

        Warn("YARA: ignored {0} output record(s) from the scan of {1} whose rule name uses the reserved coverage-sentinel prefix but is not this scan's own sentinel; no shipped rule has that prefix, so they are forged output, neither findings nor coverage. Target(s), control characters escaped: {2}",
            foreign.Length, YaraPathSafety.Escape(scanned), YaraPathSafety.Bounded(foreign.Select(r => r.Target).ToArray()));
        return records.Where(r => !IsForeignSentinel(r.Match.Rule, sentinel)).ToArray();

        static bool IsForeignSentinel(string? rule, string? sentinel) =>
            rule is not null
            && rule.StartsWith(SentinelPrefix, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(rule, sentinel, StringComparison.Ordinal);
    }

    // Runs a process with an argument LIST (no shell, no UseShellExecute — hostile filenames cannot inject),
    // capturing stdout/stderr, bounded by timeoutMs with Kill(entireProcessTree). Never throws: a start failure,
    // a timeout and a launch exception each come back as a ProcessResult whose Outcome says which, because
    // "did not run" and "ran and found nothing" are the distinction the whole backend turns on (ADR 0029
    // decision 14) and a bare null loses it.
    private static ProcessResult RunProcess(string exe, IReadOnlyList<string> args, int timeoutMs)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (var a in args)
                psi.ArgumentList.Add(a);

            using var process = new Process { StartInfo = psi };
            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            process.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.Append(e.Data).Append('\n'); };
            process.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.Append(e.Data).Append('\n'); };

            if (!process.Start())
                return ProcessResult.NotRun(ProcessOutcome.StartFailed);

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            if (!process.WaitForExit(timeoutMs))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
                Warn("YARA process '{0}' timed out after {1} ms and was terminated.", YaraPathSafety.Escape(exe), timeoutMs);
                return ProcessResult.NotRun(ProcessOutcome.TimedOut);
            }

            process.WaitForExit();   // let the async output/error readers drain
            return new ProcessResult(ProcessOutcome.Ran, process.ExitCode, stdout.ToString(), stderr.ToString());
        }
        catch (Exception ex)
        {
            Warn("Failed to run YARA process '{0}': {1}", YaraPathSafety.Escape(exe), YaraPathSafety.Escape(ex.Message));
            return ProcessResult.NotRun(ProcessOutcome.Faulted);
        }
    }
    #endregion

    #region Fields
    /// <summary>Environment variable naming the <c>yara</c> scanner binary.</summary>
    public const string YaraPathVar = "SILVERGUN_YARA_PATH";

    /// <summary>Environment variable optionally naming the <c>yarac</c> compiler binary (else derived beside <c>yara</c>).</summary>
    public const string YaracPathVar = "SILVERGUN_YARAC_PATH";

    private const int DefaultScanTimeoutMs = 60_000;
    private const int DefaultGraceMs = 5_000;   // extra wall-clock over the yara --timeout before the hard kill

    // The reserved name prefix of the batch ruleset's coverage-sentinel rule (ADR 0032 decision 9). The full name is
    // this plus 32 random hex digits drawn per ruleset, so it is unguessable by a package; no embedded rule may
    // contain the prefix (CompileRules refuses to prepare the batch ruleset if one does).
    internal const string SentinelPrefix = "SilvergunCoverageSentinel_";

    // The per-package ceiling on the one-process-per-file recovery pass. A package with thousands of entries whose
    // names the batch output cannot round-trip must not turn one process into thousands; the overflow is treated
    // as unrecovered, so exceeding it fails the package closed (Unavailable) rather than open.
    private const int MaxIndividualScans = 64;

    private readonly int _scanTimeoutMs;
    private readonly string? _yaraPath;
    private readonly string? _yaracPath;
    private readonly Lazy<RuleSet?> _ruleSet;        // plain: single-file scans (ScanFile, the individual pass)
    private readonly Lazy<RuleSet?> _batchRuleSet;   // with the coverage sentinel: the recursive pass only
    private readonly int graceMs;                    // DefaultGraceMs, except through the internal test constructor

    // Lifetime (see Dispose and Admitted), all guarded by `gate`: the rules dirs this instance created and has not yet
    // deleted, the public scans currently running, and whether Dispose has been called.
    private readonly Lock gate = new();
    private readonly List<string> rulesDirs = [];
    private int inFlight;
    private bool disposed;

    // Emit the "unavailable" note at most once per process.
    private static int unavailableNoted;

    // Every rules dir any instance created and has not deleted, for the ProcessExit fallback (CreateExitRegistry).
    private static readonly ConcurrentDictionary<string, byte> undeletedRulesDirs = CreateExitRegistry();
    #endregion

    #region Nested types
    // The prepared ruleset handed to yara: a file path, whether it is a yarac-compiled blob (-C) or source, and the
    // name of the coverage-sentinel rule it carries (the batch ruleset only; null for the plain one).
    private sealed record RuleSet(string Path, bool Compiled, string? Sentinel);

    // Why a launch produced no usable run — the distinction ADR 0029 decision 14 turns on.
    private enum ProcessOutcome { Ran, StartFailed, TimedOut, Faulted }

    private sealed record ProcessResult(ProcessOutcome Outcome, int ExitCode, string StdOut, string StdErr)
    {
        // "yara ran to completion and its stdout is trustworthy". Anything else means the files it was pointed at
        // were not scanned, which is NOT the same as their having matched nothing. Necessary, not sufficient, for a
        // recursive pass: `yara -r` exits 0 even when it could not scan a file — with an `error` line on stderr for
        // some (ADR 0032 decision 7) and with no line at all for the files queued past its --timeout deadline — so
        // ScanBatch also checks stderr AND requires a coverage-sentinel line per file (decision 9).
        internal bool Ok => Outcome == ProcessOutcome.Ran && ExitCode == 0;

        internal static ProcessResult NotRun(ProcessOutcome outcome) =>
            new(outcome, ExitCode: -1, StdOut: string.Empty, StdErr: string.Empty);
    }
    #endregion
}
