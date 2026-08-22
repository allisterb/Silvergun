namespace Silvergun.PackageAnalysis.NuGet.Yara;

using System.Diagnostics;
using System.Text;

/// <summary>
/// The cross-platform <see cref="IYaraScanner"/> backend that drives the classic <c>yara</c>/<c>yarac</c> CLI
/// (ADR 0016). It is the non-Windows counterpart to the in-process <c>LibYaraScanner</c>; both compile the same
/// embedded ReversingLabs + custom ruleset, so verdicts match across platforms.
///
/// The <c>yara</c> binary is located from the <c>SILVERGUN_YARA_PATH</c> environment variable; the <c>yarac</c>
/// compiler is <c>SILVERGUN_YARAC_PATH</c> or, failing that, derived beside <c>yara</c>. When <c>yara</c> is
/// unset or missing the scanner degrades to a no-op (like <see cref="NullYaraScanner"/>) after a single note.
/// On first use it writes the embedded rules to a temp dir, compiles them once with <c>yarac</c>, and then runs
/// <c>yara -C &lt;compiled&gt;</c> per file.
///
/// Contract: <see cref="ScanFile"/> <b>never throws</b> — a per-file failure logs a note and yields an empty
/// result so the rest of the scan continues. All package content is hostile, so the process is launched with an
/// argument list (never a shell string), bounded by a timeout with <c>Kill(entireProcessTree)</c>, and its output
/// is parsed defensively.
///
/// <see cref="ScanDirectory"/> is different, and deliberately so: it throws
/// <see cref="YaraScanIncompleteException"/> whenever the pass it performed is <b>known</b> not to cover every
/// file under the root — the rules would not prepare, the tree would not enumerate, the recursive <c>yara -r</c>
/// process failed to start, exited nonzero or timed out, or an unsafe-named file could not be re-scanned through
/// a safely named copy (ADR 0029 decisions 13 and 14). Returning an empty list for any of those would report a
/// package that was never examined as a completed, clean scan, and a hostile package can reach several of them on
/// demand — one <c>yara -r</c> made to exceed the timeout would otherwise buy a clean report outright.
/// <c>PackageScanner.ScanYara</c> maps the exception to <see cref="YaraScanStatus.Unavailable"/>.
/// </summary>
public sealed class YaraCliScanner : Runtime, IYaraScanner
{
    #region Constructors
    /// <param name="scanTimeoutMs">Hard per-file wall-clock budget after which the <c>yara</c> process is killed.</param>
    public YaraCliScanner(int scanTimeoutMs = DefaultScanTimeoutMs)
    {
        _scanTimeoutMs = scanTimeoutMs > 0 ? scanTimeoutMs : DefaultScanTimeoutMs;
        (_yaraPath, _yaracPath) = Locate();
        _ruleSet = new Lazy<RuleSet?>(CompileRules);
    }
    #endregion

    #region Properties
    /// <summary><c>true</c> when a usable <c>yara</c> binary was located; otherwise the scanner is a no-op.</summary>
    public bool Available => _yaraPath is not null;
    #endregion

    #region Methods
    /// <summary>
    /// Scans <paramref name="fullPath"/> with <c>yara</c> against the compiled ruleset and maps the hits to
    /// <see cref="YaraMatch"/>. Returns empty when <c>yara</c> is unavailable, the rules did not compile, the
    /// file is missing, the process errors or times out, or nothing matched. Never throws.
    /// </summary>
    public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
    {
        var ruleSet = _yaraPath is null ? null : _ruleSet.Value;
        return ruleSet is null
            ? Array.Empty<YaraMatch>()
            : ScanOne(ruleSet, fullPath) ?? Array.Empty<YaraMatch>();
    }

    // The single-file primitive behind ScanFile and the unsafe-name recovery pass below. Returns the (possibly
    // empty) hits, or NULL when the scan did not happen at all: missing file, unresolvable path, process start
    // failure, nonzero exit, timeout, exception. ScanFile flattens null to empty because of the never-throws
    // contract, but the recovery pass needs the distinction — "we could not scan this file" is what makes the whole
    // package Unavailable (ADR 0029 decision 13), and an empty list there would silently read as clean.
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
            var waitMs = Math.Min(_scanTimeoutMs + GraceMs, budgetMs ?? int.MaxValue);

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
            // scan one known file — so keep only hits whose target resolves to fullPath and drop the rest.
            return YaraCliOutput.ParseAll(result.StdOut)
                .Where(r => TargetMatches(r.Target, fullPath))
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
    /// resolves to. Hits whose target is not a real file under the scanned root (a warning line, prose, a
    /// directory, or a path the package deliberately made ambiguous) are dropped. An empty result always means
    /// "nothing matched", never "something went wrong": the pass ran and no rule fired, the tree held no files, or
    /// there was nothing to scan at all (the backend is unavailable, or the directory does not exist). A pass known
    /// to be missing files throws instead — see below.
    ///
    /// Files the batch output cannot faithfully name are excluded from it and scanned <b>individually</b>
    /// instead, so their coverage is recovered rather than dropped (ADR 0029; see
    /// <see cref="ScanIndividually"/>): names carrying a control character (the echoed path is line-split and the
    /// hit is lost), and names that share an echoed form with another entry (the package would otherwise choose
    /// which of its files a hit is credited to).
    ///
    /// Throws <see cref="YaraScanIncompleteException"/> whenever the result is known to be missing files — the
    /// rules would not prepare, the tree would not enumerate, the batch process did not produce a usable run
    /// (start failure, nonzero exit, timeout), an individual re-scan could not be performed, or the batch pass
    /// reported a hit under the root that could not be attributed to any file it enumerated (ADR 0029 decision 17:
    /// a dropped hit is missing coverage, not an absence of findings). Such a result must never be presented as a
    /// clean scan (ADR 0029 decisions 13, 14 and 17); <c>PackageScanner.ScanYara</c> maps it to
    /// <see cref="YaraScanStatus.Unavailable"/>.
    /// </summary>
    public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
    {
        if (_yaraPath is null)
            return Array.Empty<(string, YaraMatch)>();   // no engine at all: Available already says so, honestly.

        // A ruleset that would not prepare means every file below is unscanned, which is exactly the state that
        // must not read as clean (decision 14) — unlike ScanFile, which has to swallow it to keep its contract.
        var ruleSet = _ruleSet.Value
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
        var batch = attributable.Length == 0
            ? Array.Empty<(string FullPath, YaraMatch Match)>()
            : ScanBatch(ruleSet, rootDir, attributable, forged, deferred);

        return individual.Length == 0
            ? batch
            : [.. batch, .. ScanIndividually(ruleSet, rootDir, individual)];
    }

    // The single recursive yara -r pass. Hits are attributed only to files in attributable (see ScanDirectory);
    // the echoed target must resolve to one of them, because the header regex is permissive enough to match
    // arbitrary prose and a garbage or attacker-authored line would otherwise fabricate a hit.
    //
    // Throws when the process did not produce a usable run (ADR 0029 decision 14). Returning an empty list there
    // was a false negative a package could buy on demand: one `yara -r` pushed past the timeout over the whole
    // tree — cheaper than any filename trick — and the report read Completed with zero findings.
    private IReadOnlyList<(string FullPath, YaraMatch Match)> ScanBatch(
        RuleSet ruleSet, string rootDir, IReadOnlyList<string> attributable,
        IReadOnlySet<string> forged, IReadOnlySet<string> deferred)
    {
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

            result = RunProcess(_yaraPath!, args, _scanTimeoutMs + GraceMs);
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
        var records = YaraCliOutput.ParseAll(result.StdOut)
            .Select(r => (r.Target, Key: TryNormalize(r.Target), r.Match))
            .Select(x => (x.Target, x.Key, x.Match, File: Attribute(x.Target, x.Key)))
            .ToArray();

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
        var dropped = records
            .Where(x => x.File is null && x.Key is { } key && IsUnderRoot(key) && !IsDeferredEcho(x.Target))
            .Select(x => x.Target)
            .ToArray();

        if (dropped.Length > 0)
        {
            Warn("YARA: {0} hit(s) from the recursive pass over {1} could not be attributed to any file it enumerated. Target(s), control characters escaped: {2}",
                dropped.Length, YaraPathSafety.Escape(rootDir), Describe(rootDir, dropped));

            throw new YaraScanIncompleteException(
                $"YARA matched {dropped.Length} target(s) under '{YaraPathSafety.Escape(rootDir)}' that could not be attributed to any file it enumerated, so those hits would be silently dropped and this package must not be reported as clean. Target(s), control characters escaped: {Describe(rootDir, dropped)}");
        }

        return records
            .Where(x => x.File is not null)
            .Select(x => (x.File!, x.Match))
            .ToArray();

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
    // YaraScanStatus.Unavailable.
    private IReadOnlyList<(string FullPath, YaraMatch Match)> ScanIndividually(
        RuleSet ruleSet, string rootDir, IReadOnlyList<(string File, bool Unsafe)> targets)
    {
        Warn("YARA: {0} extracted file name(s) under {1} cannot be attributed from the recursive pass (control characters, or an echoed path shared with another entry); re-scanning each in isolation. Path(s), control characters escaped: {2}",
            targets.Count, YaraPathSafety.Escape(rootDir), Describe(rootDir, targets.Select(t => t.File).ToArray()));

        var staging = targets.Any(t => t.Unsafe) ? CreateStagingDir() : null;
        var hits = new List<(string, YaraMatch)>();
        var unrecovered = new List<string>();
        var elapsed = Stopwatch.StartNew();
        var budgetMs = _scanTimeoutMs + GraceMs;
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
            var remainingMs = budgetMs - (int)Math.Min(budgetMs, elapsed.ElapsedMilliseconds);
            var matches = attempted >= MaxIndividualScans || remainingMs <= 0 ? null
                : isUnsafe ? (staging is null ? null : ScanViaSafeCopy(ruleSet, staging, file, attempted, remainingMs))
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
                $"YARA could not scan {unrecovered.Count} of {targets.Count} file(s) whose names its batch output cannot round-trip, so this package was NOT fully scanned and must not be reported as clean. Path(s), control characters escaped: {Describe(rootDir, unrecovered)}");
    }

    // Copies one unsafe-named file to a generated safe name and scans the copy, returning its (possibly empty)
    // hits, or null when the copy or the scan did not happen. The copy is deleted afterwards, best-effort.
    // budgetMs is the remainder of the recovery pass's aggregate wall clock, passed straight through to the scan.
    private IReadOnlyList<YaraMatch>? ScanViaSafeCopy(
        RuleSet ruleSet, string stagingDir, string fullPath, int ordinal, int? budgetMs = null)
    {
        // Both yara invocations are launched with -N precisely so a link in package content cannot be followed out
        // of the extraction tree; File.Copy has no such option and WOULD follow it, so a link is never copied. It
        // counts as unrecovered rather than as scanned-and-clean.
        if (IsLink(fullPath))
        {
            Warn("YARA will not copy {0} to a safely named temp file: it is a link, and following it would scan content outside the package.",
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

    private static bool IsLink(string fullPath)
    {
        try { return new FileInfo(fullPath).LinkTarget is not null; }
        catch { return true; }   // cannot tell ⇒ do not copy it
    }

    // The temp directory holding the safely named copies, or null (logged) when it cannot be created — in which
    // case no unsafe-named file can be recovered and the scan fails closed. On Unix it is created owner-only: it
    // briefly holds a copy of hostile package content in a world-writable /tmp.
    private string? CreateStagingDir()
    {
        try
        {
            var dir = Path.Combine(Path.GetTempPath(), "silvergun-yara-safe-" + Guid.NewGuid().ToString("N"));
            return (OperatingSystem.IsWindows()
                ? Directory.CreateDirectory(dir)
                : Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute)).FullName;
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
    // InnerException, so that cause stays machine-readable for a caller that wants to distinguish it.
    private static YaraScanIncompleteException Incomplete(string what, Exception? inner = null) =>
        new($"YARA {what}. This package was NOT scanned and must not be reported as clean.", inner);

    // Why a process produced no usable run, as a log/message fragment. yara's own stderr is included when it said
    // anything, escaped: it echoes paths, and those paths are package content.
    private static string Explain(ProcessResult result)
    {
        var reason = result.Outcome switch
        {
            ProcessOutcome.StartFailed => "the yara process could not be started",
            ProcessOutcome.TimedOut => "the yara process exceeded its time budget and was killed",
            ProcessOutcome.Faulted => "the yara process could not be run",
            _ => $"yara exited with code {result.ExitCode}",
        };

        var stderr = result.StdErr.Trim();
        return stderr.Length == 0 ? reason : $"{reason}: {YaraPathSafety.Escape(stderr)}";
    }

    // Renders offending paths for a log line: package-relative where possible, always control-escaped so this
    // attacker-authored text cannot forge a line in our own log, and capped so a package full of them cannot
    // flood it.
    private static string Describe(string rootDir, IReadOnlyList<string> paths) =>
        string.Join(", ", paths.Take(MaxLoggedPaths).Select(p => "'" + YaraPathSafety.Escape(Relative(rootDir, p)) + "'"))
        + (paths.Count > MaxLoggedPaths ? $" (+{paths.Count - MaxLoggedPaths} more)" : string.Empty);

    private static string Relative(string rootDir, string fullPath)
    {
        try { return Path.GetRelativePath(rootDir, fullPath); }
        catch { return fullPath; }
    }

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
    // null only when there are no rules or writing failed, in which case the scanner degrades to "no matches".
    private RuleSet? CompileRules()
    {
        if (_yaraPath is null)
            return null;

        try
        {
            var dir = Path.Combine(Path.GetTempPath(), "silvergun-yara-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);

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

            File.WriteAllText(sourcePath, sb.ToString());

            if (_yaracPath is null)
            {
                Info("Compiled {0} embedded YARA rule file(s); yarac not found, scanning with uncompiled rules.", count);
                return new RuleSet(sourcePath, Compiled: false);
            }

            var compiledPath = Path.Combine(dir, "silvergun-rules.yarac");
            var result = RunProcess(_yaracPath, new List<string> { sourcePath, compiledPath }, _scanTimeoutMs + GraceMs);
            if (!result.Ok || !File.Exists(compiledPath))
            {
                // Not an incomplete scan: yara compiles the source at scan time, so the pass still covers every file.
                Warn("yarac failed to compile embedded YARA rules ({0}); scanning with uncompiled rules.", Explain(result));
                return new RuleSet(sourcePath, Compiled: false);
            }

            Info("Compiled {0} embedded YARA rule file(s) with yarac for malware-signature scanning.", count);
            return new RuleSet(compiledPath, Compiled: true);
        }
        catch (Exception ex)
        {
            Warn("Failed to prepare embedded YARA rules: {0}", YaraPathSafety.Escape(ex.Message));
            return null;
        }
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
    private const int GraceMs = 5_000;   // extra wall-clock over the yara --timeout before the hard kill
    private const int MaxLoggedPaths = 10;   // a hostile package must not be able to flood the log with names

    // The per-package ceiling on the one-process-per-file recovery pass. A package with thousands of entries whose
    // names the batch output cannot round-trip must not turn one process into thousands; the overflow is treated
    // as unrecovered, so exceeding it fails the package closed (Unavailable) rather than open.
    private const int MaxIndividualScans = 64;

    private readonly int _scanTimeoutMs;
    private readonly string? _yaraPath;
    private readonly string? _yaracPath;
    private readonly Lazy<RuleSet?> _ruleSet;

    // Emit the "unavailable" note at most once per process.
    private static int unavailableNoted;
    #endregion

    #region Nested types
    // The prepared ruleset handed to yara: a file path and whether it is a yarac-compiled blob (-C) or source.
    private sealed record RuleSet(string Path, bool Compiled);

    // Why a launch produced no usable run — the distinction ADR 0029 decision 14 turns on.
    private enum ProcessOutcome { Ran, StartFailed, TimedOut, Faulted }

    private sealed record ProcessResult(ProcessOutcome Outcome, int ExitCode, string StdOut, string StdErr)
    {
        // "yara ran to completion and its output is trustworthy". Anything else means the files it was pointed at
        // were not scanned, which is NOT the same as their having matched nothing.
        internal bool Ok => Outcome == ProcessOutcome.Ran && ExitCode == 0;

        internal static ProcessResult NotRun(ProcessOutcome outcome) =>
            new(outcome, ExitCode: -1, StdOut: string.Empty, StdErr: string.Empty);
    }
    #endregion
}
