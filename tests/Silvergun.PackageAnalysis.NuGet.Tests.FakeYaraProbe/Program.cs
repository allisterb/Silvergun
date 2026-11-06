namespace Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe;

using System.Globalization;

using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// A multi-role child-process fixture for the ADR 0029 and ADR 0033 tests. Neither role can be played from inside the xunit
/// process, which is why this is its own executable.
///
/// <para><b>Role 1 — a fake <c>yara</c> binary (default).</b> <see cref="YaraCliScanner"/> launches whatever
/// <c>SILVERGUN_YARA_PATH</c> names, by path, with an argument list it controls. To pin "the batch process exited
/// non-zero" and "the batch process outlived its timeout" as <i>fail closed</i>, a test needs a real executable
/// that misbehaves on demand and on <b>both</b> platforms — <c>/bin/false</c> exists only on Unix, and nothing in
/// <c>System32</c> reliably hangs or fails for an arbitrary argument list without reading stdin. Behaviour is
/// taken from the environment (the argument list belongs to the scanner) and every argv is logged, which is also
/// how a test counts how many processes a scan actually spawned — the difference between the cheap single batch
/// pass and the per-file recovery pass. Invoked with exactly <c>&lt;source.yara&gt; &lt;output&gt;</c> it plays
/// <c>yarac</c> instead (see <see cref="FakeYarac"/>). Like real yara it prints a coverage-sentinel line for every file
/// it "scans" whenever its ruleset declares one (ADR 0032 decision 9; see <see cref="Emit"/>).</para>
///
/// <para><b>Role 2 — a scanner harness (<c>--scan-directory</c>, or <c>--scan-file</c> for the per-file
/// primitive).</b> The one ADR 0029 failure site that cannot be
/// reached in-process is "the embedded ruleset could not be prepared": it is reached by making
/// <see cref="Path.GetTempPath"/> unusable, and <c>TMPDIR</c>/<c>TEMP</c> are process-global — poisoning them
/// inside the test host would break whatever unrelated test happens to be running in parallel. Here the poisoning
/// is scoped to this process, set after the runtime has started, and the outcome is reported on stdout.</para>
///
/// <para><b>Role 3 — a worker-mode logging host (<c>--stderr-logging</c>).</b> A fresh process for
/// <c>Runtime.WithStderrLogging</c> (ADR 0033), whose logger is process-wide and set once; see <see cref="StderrLogging"/>.</para>
///
/// <para><b>Role 4 — a scripted fake YARA worker (<c>--fake-worker &lt;script&gt;</c>).</b> Stands in for
/// <c>silvergun __worker yara</c> so the parent backend's handling of every worker behaviour can be driven exactly; see
/// <see cref="FakeWorker"/>.</para>
///
/// <para><b>Role 5 — a scripted fake graph worker (<c>--fake-graph-worker &lt;script&gt;</c>).</b> Stands in for
/// <c>silvergun __worker graph</c> (<c>docs/agent/tasks/graph-worker.md</c>); see <see cref="FakeGraphWorker"/>. Its only
/// analysis is the real graph worker loop it delegates a genuine answer to.</para>
///
/// <para>This fixture never scans anything for real and contains no rule logic; it is deliberately inert.</para>
/// </summary>
internal static class Program
{
    #region Methods
    private static int Main(string[] args) => args switch
    {
        ["--scan-directory", var root, ..] => Harness(root, args),
        ["--scan-file", var file, ..] => FileHarness(file, args),
        ["--stderr-logging", var logName, var mode] => StderrLogging(logName, mode),
        ["--fake-worker", var script] => FakeWorker.Run(script),
        ["--fake-graph-worker", var script] => FakeGraphWorker.Run(script),
        [var source, var compiled] when IsYaracCall(source, compiled) => FakeYarac(source, compiled),
        _ => FakeYara(args),
    };

    // --- Role 1: the fake yara binary ------------------------------------------------------------------------

    // Ignores its arguments (they are the scanner's) and does exactly what the environment says: record the
    // invocation, optionally outlive the caller's timeout, then exit with the requested code.
    //
    // SILVERGUN_FAKEYARA_SINGLE_EXIT_CODE, when set, overrides the exit code of a SINGLE-FILE scan only (last argument a
    // file), so a test can let the recursive pass succeed while every individual re-scan fails (ADR 0032 decision 9).
    // SILVERGUN_FAKEYARA_SINGLE_FAIL ('|'-separated file names) fails (exit 1) only the single-file scans of those names,
    // so one re-scan can fail while another succeeds. SILVERGUN_FAKEYARA_SINGLE_SLEEP_MS, when set, replaces
    // SILVERGUN_FAKEYARA_SLEEP_MS for single-file scans only: a cheap recursive pass with slow individual re-scans, which is
    // the shape the recovery pass's aggregate budget is about.
    private static int FakeYara(string[] args)
    {
        Log(args);
        Emit(args);

        var isSingle = args.Length > 0 && !Directory.Exists(args[^1]);
        var singleSleep = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_SINGLE_SLEEP_MS");
        var sleepMs = isSingle && !string.IsNullOrEmpty(singleSleep)
            ? Int("SILVERGUN_FAKEYARA_SINGLE_SLEEP_MS")
            : Int("SILVERGUN_FAKEYARA_SLEEP_MS");
        if (sleepMs > 0)
            Thread.Sleep(sleepMs);

        var fail = (Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_SINGLE_FAIL") ?? string.Empty)
            .Split('|', StringSplitOptions.RemoveEmptyEntries);
        if (isSingle && fail.Contains(Path.GetFileName(args[^1]), StringComparer.Ordinal))
            return 1;

        var single = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_SINGLE_EXIT_CODE");
        return !string.IsNullOrEmpty(single) && isSingle
            ? Int("SILVERGUN_FAKEYARA_SINGLE_EXIT_CODE")
            : Int("SILVERGUN_FAKEYARA_EXIT_CODE");
    }

    // --- Role 1b: a fake yarac -------------------------------------------------------------------------------

    // YaraCliScanner launches yarac with exactly two arguments, `<source .yara> <compiled output>`; no yara launch is
    // ever that short (it always carries options). A test that points SILVERGUN_YARAC_PATH at this apphost gets the
    // scanner's COMPILED path (`yara -C <compiled>`) without a real compiler: the "compiled" file is a byte copy of the
    // source, which is all the fake yara above ever reads from it (the coverage-sentinel rule's name). Exit code from
    // SILVERGUN_FAKEYARA_YARAC_EXIT_CODE: nonzero writes nothing, which is how the scanner's "yarac failed, fall back
    // to uncompiled rules" path is staged. Not logged — the invocation log counts yara launches only.
    private static bool IsYaracCall(string source, string compiled) =>
        source.EndsWith(".yara", StringComparison.OrdinalIgnoreCase) && File.Exists(source) && !Directory.Exists(compiled);

    //
    // SILVERGUN_FAKEYARA_YARAC_DELETE (ADR 0034) plays Storage Sense for a whole scan-package run, whose extraction
    // directory the test never sees: every file of that exact name ('*': every file) under each
    // <temp>/silvergun/pkg-* directory is deleted. The scanner compiles its batch ruleset at the top of a scan, AFTER the
    // package's YARA inventory was taken and BEFORE any enumeration of its own, so the deletion lands exactly in the gap
    // the inventory exists to cover. The test gives the CLI a private temp directory, so only its own package is there.
    private static int FakeYarac(string source, string compiled)
    {
        DeleteExtractedFiles(Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_YARAC_DELETE"));
        var exit = Int("SILVERGUN_FAKEYARA_YARAC_EXIT_CODE");
        if (exit == 0)
            File.Copy(source, compiled, overwrite: true);
        return exit;
    }

    private static void DeleteExtractedFiles(string? name)
    {
        var extractions = Path.Combine(Path.GetTempPath(), "silvergun");
        if (string.IsNullOrEmpty(name) || !Directory.Exists(extractions))
            return;

        foreach (var dir in Directory.EnumerateDirectories(extractions, "pkg-*"))
            foreach (var file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                if (name == "*" || string.Equals(Path.GetFileName(file), name, StringComparison.Ordinal))
                    File.Delete(file);
    }

    // Stands in for yara's own stdout, which is the ONLY thing the scanner attributes hits from. Two knobs, split
    // by what the last argument is, because the scanner drives the binary in two very different modes:
    //
    //   SILVERGUN_FAKEYARA_STDOUT    — printed verbatim on the RECURSIVE pass (last argument is a directory), with
    //                                  the two-character sequence \n decoded to a real newline. That decoding is
    //                                  the point: it lets a test stage the exact bytes `yara -r` prints for a file
    //                                  whose name carries a control character — one hit split across two physical
    //                                  lines — which is the shape ADR 0029 decisions 15 and 17 turn on and which
    //                                  cannot be produced by a fake that only echoes its arguments.
    //   SILVERGUN_FAKEYARA_ECHO_RULE — on a SINGLE-FILE scan (last argument is a file), prints
    //                                  "<rule> <path>", which is what yara prints when that file matches. The
    //                                  recovery pass hands out a path IT chose (a temp copy with a generated
    //                                  name), so a test cannot know that path in advance and must have the fake
    //                                  echo whatever it was given.
    //
    //   SILVERGUN_FAKEYARA_BATCH_ECHO_RULE / _NAME / _GHOST
    //                               — on the RECURSIVE pass, print "<rule> <file>" for every file under the root
    //                                  whose file name is exactly _NAME, and (when _GHOST is set) also
    //                                  "<rule> <that file's directory>/<_GHOST>" — a hit on a file that does NOT
    //                                  exist, i.e. an unattributable hit under the root (ADR 0029 decision 17). This
    //                                  is the batch twin of _ECHO_RULE, for a test that cannot know the scanned
    //                                  root in advance: a whole scan-package run extracts into a directory the
    //                                  test never sees, so SILVERGUN_FAKEYARA_STDOUT cannot name the file.
    //
    //   SILVERGUN_FAKEYARA_BATCH_STDERR
    //                               — printed verbatim on STDERR on the RECURSIVE pass, with the same \n decoding as
    //                                  _STDOUT, while the exit code stays whatever _EXIT_CODE says (0 by default).
    //                                  This is real `yara -r`'s behaviour for a file it could not open or that
    //                                  outlasted its own --timeout: an `error scanning <path>: …` line on stderr, and
    //                                  exit 0 (ADR 0032 decision 7). The single-file scans never print it.
    //
    // The coverage sentinel (ADR 0032 decision 9). The scanner adds a `condition: true` rule named
    // SilvergunCoverageSentinel_<32 random hex> to the ruleset it hands the RECURSIVE pass, and treats a file with no
    // line for that rule as unscanned. Real yara prints `<sentinel> [] <file>` for every file it examines, so this fake
    // does too — the name is read from the rules file it was handed (the argument before the target; source text, or
    // the fake yarac's byte copy of it), so the uncompiled and the compiled path are emulated alike. Like real yara, it
    // also prints the line on a single-file scan IF that ruleset carries a sentinel (the scanner's plain ruleset must
    // not). Knobs, all on the recursive pass:
    //
    //   SILVERGUN_FAKEYARA_SENTINEL_SKIP  — '|'-separated file names whose sentinel line is NOT printed: the files a
    //                                       real `yara -r` silently dropped at its one global --timeout deadline. An
    //                                       entry ending in '*' is a name prefix; "*" alone skips every file.
    //   SILVERGUN_FAKEYARA_SENTINEL_FORGE — for each skipped file, print "<this rule name> [] <file>" instead: a forged
    //                                       coverage line under a name that is NOT this ruleset's sentinel. Two values
    //                                       are special: "@upper" forges the ruleset's REAL sentinel name upper-cased
    //                                       whole, "@upper-suffix" only its random suffix — the real name, in another case.
    //   SILVERGUN_FAKEYARA_SENTINEL_GHOST — also print "<sentinel> [] <root>/<this relative path>", a real sentinel line
    //                                       for a file that does not exist (unattributable coverage evidence).
    //
    // Nothing here decides what "matches": the caller stages the output it wants parsed. This fixture stays inert.
    private static void Emit(string[] args)
    {
        var target = args.Length == 0 ? string.Empty : args[^1];
        if (target.Length == 0)
            return;

        var sentinel = args.Length >= 2 ? ReadSentinel(args[^2]) : null;

        if (Directory.Exists(target))
        {
            var batch = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_STDOUT");
            if (!string.IsNullOrEmpty(batch))
                Console.Out.Write(batch.Replace("\\n", "\n") + "\n");
            EmitBatchEcho(target);
            EmitSentinels(target, sentinel);

            var errors = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_BATCH_STDERR");
            if (!string.IsNullOrEmpty(errors))
                Console.Error.Write(errors.Replace("\\n", "\n") + "\n");
            return;
        }

        var rule = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_ECHO_RULE");
        if (!string.IsNullOrEmpty(rule) && File.Exists(target))
            Console.Out.Write(rule + " " + target + "\n");
        if (sentinel is not null && File.Exists(target))
            Console.Out.Write(sentinel + " [] " + target + "\n");
    }

    // See Emit: one `<sentinel> [] <file>` line per file under the root (ordinal order, names verbatim — so a name with
    // a newline splits its line exactly as real yara's echo does), minus the skipped ones, plus the optional ghost.
    private static void EmitSentinels(string root, string? sentinel)
    {
        if (sentinel is null)
            return;   // a ruleset without a sentinel (the pre-decision-9 scanner): print what real yara would — nothing

        var skip = (Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_SENTINEL_SKIP") ?? string.Empty)
            .Split('|', StringSplitOptions.RemoveEmptyEntries);
        const string prefix = "SilvergunCoverageSentinel_";
        var forge = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_SENTINEL_FORGE") switch
        {
            "@upper" => sentinel.ToUpperInvariant(),
            "@upper-suffix" => prefix + sentinel[prefix.Length..].ToUpperInvariant(),
            var other => other,
        };

        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            var name = Path.GetFileName(file);
            var skipped = skip.Any(s => s.EndsWith('*')
                ? name.StartsWith(s[..^1], StringComparison.Ordinal)
                : string.Equals(name, s, StringComparison.Ordinal));
            if (!skipped)
                Console.Out.Write(sentinel + " [] " + file + "\n");
            else if (!string.IsNullOrEmpty(forge))
                Console.Out.Write(forge + " [] " + file + "\n");
        }

        var ghost = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_SENTINEL_GHOST");
        if (!string.IsNullOrEmpty(ghost))
            Console.Out.Write(sentinel + " [] " + Path.Combine(root, ghost) + "\n");
    }

    // The coverage-sentinel rule name declared in a rules file, or null when it declares none (or cannot be read).
    // An ordinal scan for the fixed declaration prefix rather than a regex over megabytes of rule source, then the same
    // shape the scanner generates: exactly 32 lower-case hex digits.
    private static string? ReadSentinel(string rulesPath)
    {
        const string declaration = "rule SilvergunCoverageSentinel_";
        try
        {
            if (!File.Exists(rulesPath))
                return null;

            var text = File.ReadAllText(rulesPath);
            var at = text.IndexOf(declaration, StringComparison.Ordinal);
            if (at < 0 || at + declaration.Length + 32 > text.Length)
                return null;

            var suffix = text.Substring(at + declaration.Length, 32);
            return suffix.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')
                ? declaration["rule ".Length..] + suffix
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    // See Emit: the recursive pass's "<rule> <file>" lines for the files named _NAME, plus an optional ghost sibling.
    // SILVERGUN_FAKEYARA_BATCH_ECHO_REPEAT (default 1) prints that whole block that many times: byte-identical repeated
    // records, which real yara does not produce but forged output can (the scanner de-duplicates per file and rule).
    private static void EmitBatchEcho(string root)
    {
        var rule = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_BATCH_ECHO_RULE");
        var name = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_BATCH_ECHO_NAME");
        var ghost = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_BATCH_GHOST");
        if (string.IsNullOrEmpty(rule) || string.IsNullOrEmpty(name))
            return;

        var files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(f => string.Equals(Path.GetFileName(f), name, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        for (var repeat = Math.Max(1, Int("SILVERGUN_FAKEYARA_BATCH_ECHO_REPEAT")); repeat > 0; repeat--)
        {
            foreach (var file in files)
            {
                Console.Out.Write(rule + " " + file + "\n");
                if (!string.IsNullOrEmpty(ghost))
                    Console.Out.Write(rule + " " + Path.Combine(Path.GetDirectoryName(file)!, ghost) + "\n");
            }
        }
    }

    // One line per invocation, to the file named by SILVERGUN_FAKEYARA_LOG (absent ⇒ no log). Records the last
    // argument — for a `yara -r` pass the scanned root, for a recovery scan the safely named temp copy — and the
    // Unix mode of the directory holding it, which is how the "the staging directory is 0700" test observes a
    // directory that YaraCliScanner creates and deletes inside a single call. Appended after those (so existing
    // `target=…|` matches are unaffected): whether the rules were handed over compiled (`-C`), and the coverage-sentinel
    // rule the rules file declares ("-" for none) — how the ADR 0032 decision 9 tests observe which ruleset each launch
    // got: the sentinel-carrying one for the recursive pass, the plain one for every single-file scan. Last, the rules
    // file itself (`rules=…`, the argument before the target): the only place a test can learn where the scanner put the
    // temp directory it prepared that ruleset in, which is what the lifetime tests watch being deleted.
    private static void Log(string[] args)
    {
        var log = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_LOG");
        if (string.IsNullOrEmpty(log))
            return;

        var target = args.Length == 0 ? string.Empty : args[^1];
        var sentinel = args.Length >= 2 ? ReadSentinel(args[^2]) : null;
        var line = $"argc={args.Length}|target={Sanitize(target)}|dirmode={DirMode(target)}"
                   + $"|compiled={args.Contains("-C")}|sentinel={sentinel ?? "-"}"
                   + $"|rules={(args.Length >= 2 ? Sanitize(args[^2]) : "-")}\n";

        // The recovery pass is sequential, but retry anyway: a lost line would silently weaken an assertion.
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                File.AppendAllText(log, line);
                return;
            }
            catch (IOException) when (attempt < 20)
            {
                Thread.Sleep(10);
            }
        }
    }

    // The permission bits of the directory containing `path`, as three octal digits ("-" on Windows or when they
    // cannot be read). UnixFileMode's low nine bits are the standard rwxrwxrwx layout, so a plain mask prints as
    // the familiar mode.
    private static string DirMode(string path)
    {
        if (OperatingSystem.IsWindows() || path.Length == 0)
            return "-";

        try
        {
            var dir = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
            return string.IsNullOrEmpty(dir)
                ? "-"
                : Convert.ToString((int)File.GetUnixFileMode(dir) & 0x1FF, 8).PadLeft(3, '0');
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return "-";
        }
    }

    // The logged paths come from package content, so they can carry control characters; keep the log one line per
    // invocation (and unforgeable) by replacing every C0 character with a printable stand-in.
    private static string Sanitize(string text) =>
        new(text.Select(c => c <= (char)0x1F ? '·' : c).ToArray());

    private static int Int(string variable) =>
        int.TryParse(Environment.GetEnvironmentVariable(variable), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : 0;

    // --- Role 2: the out-of-process scanner harness ----------------------------------------------------------

    // Runs YaraCliScanner.ScanDirectory over `root` in this process and reports the outcome on stdout as
    // key=value lines. Exit code: 0 completed, 1 YaraScanIncompleteException, 2 any other exception, 3 bad usage.
    //
    // --warmup <dir> scans <dir> first with the SAME scanner instance (its outcome is printed as warmup=…), and
    // --poison-temp-after-warmup <path> poisons the temp directory only after that. The scanner prepares its two
    // rulesets lazily and separately (ADR 0032 decision 9: the sentinel-carrying batch ruleset on the first recursive
    // pass, the plain one on the first single-file scan), so a warm-up whose files are all covered prepares the batch
    // ruleset ALONE, and the poisoning then makes the plain one fail when the scan of <root> first needs it.
    //
    // The scanner is disposed before the process returns, so it deletes its temp rules dirs itself — unless --no-dispose
    // is given, which leaves them to the scanner's process-exit fallback (the lifetime test of a never-disposed instance,
    // the shape YaraScannerFactory.Shared has). --report-rules-dirs prints, after the scan and before any dispose, how
    // many rules dirs exist in this process's temp directory (`rulesdirs=N`): the evidence that there was something for
    // the exit fallback to delete.
    private static int Harness(string root, string[] args)
    {
        // Poison this process's temp directory (and only this process's) before the scanner is constructed, so
        // that its one-time ruleset preparation — Directory.CreateDirectory under Path.GetTempPath() — fails.
        var poison = Value(args, "--poison-temp");
        if (poison is not null)
            PoisonTemp(poison);

        var timeout = Value(args, "--timeout-ms");
        var scanner = timeout is null ? new YaraCliScanner() : new YaraCliScanner(int.Parse(timeout, CultureInfo.InvariantCulture));
        try
        {
            // Printed BEFORE the scan and unconditionally: the point of several of these tests is that Available is
            // true (it is a one-time File.Exists on the binary) while the scan itself could not be performed.
            Console.WriteLine($"available={scanner.Available}");
            Console.WriteLine($"temp={Sanitize(SafeTempPath())}");

            var warmup = Value(args, "--warmup");
            if (warmup is not null)
            {
                try
                {
                    Console.WriteLine($"warmup=completed:{scanner.ScanDirectory(warmup).Count}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"warmup=error:{ex.GetType().Name}:{Sanitize(ex.Message)}");
                }

                var late = Value(args, "--poison-temp-after-warmup");
                if (late is not null)
                    PoisonTemp(late);
            }

            try
            {
                var hits = Value(args, "--list-then-delete") is { } delete ? ListThenDelete(scanner, root, delete) : scanner.ScanDirectory(root);
                Console.WriteLine("outcome=completed");
                Console.WriteLine($"hits={hits.Count}");
                return 0;
            }
            catch (YaraScanIncompleteException ex)
            {
                Console.WriteLine("outcome=incomplete");
                Console.WriteLine($"inner={ex.InnerException?.GetType().Name ?? "none"}");
                Console.WriteLine($"message={Sanitize(ex.Message)}");
                // Every carried hit as "<file name>:<rule>", ordinal order — enough for a test to say WHICH hits travelled.
                Console.WriteLine($"partial={ex.PartialFindings.Count}");
                Console.WriteLine("partialhits=" + string.Join(",", ex.PartialFindings
                    .Select(h => Sanitize(Path.GetFileName(h.FullPath)) + ":" + Sanitize(h.Match.Rule))
                    .Order(StringComparer.Ordinal)));
                return 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"outcome=error:{ex.GetType().Name}");
                Console.WriteLine($"message={Sanitize(ex.Message)}");
                return 2;
            }
        }
        finally
        {
            Release(scanner, args);
        }
    }

    // --list-then-delete <name> (ADR 0034, I5): instead of ScanDirectory, list `root` exactly as NuGetPackage.Open takes a
    // package's YARA inventory, delete every listed file of that name ('|'-separated names), then ScanFiles over the list —
    // so a listed file is gone by scan time. Combined with --warmup and --poison-temp-after-warmup it reaches the individual
    // pass with a plain ruleset that cannot be prepared. Prints `listed=N` and `deleted=N`.
    private static IReadOnlyList<(string FullPath, YaraMatch Match)> ListThenDelete(YaraCliScanner scanner, string root, string delete)
    {
        var names = delete.Split('|', StringSplitOptions.RemoveEmptyEntries);
        var listed = Directory.GetFiles(root, "*", SearchOption.AllDirectories);
        var deleted = 0;
        foreach (var file in listed.Where(f => names.Contains(Path.GetFileName(f), StringComparer.Ordinal)))
        {
            File.Delete(file);
            deleted++;
        }

        Console.WriteLine($"listed={listed.Length}");
        Console.WriteLine($"deleted={deleted}");
        return scanner.ScanFiles(root, listed);
    }

    // The ScanFile twin of Harness (ADR 0032 decision 5): the per-file primitive must THROW when the ruleset would not
    // prepare, and that failure is reached the same process-global way, so it is observed here too. Same exit-code
    // contract; a completed scan reports its hit count. Same --no-dispose / --report-rules-dirs.
    private static int FileHarness(string file, string[] args)
    {
        var poison = Value(args, "--poison-temp");
        if (poison is not null)
            PoisonTemp(poison);

        var scanner = new YaraCliScanner();
        try
        {
            Console.WriteLine($"available={scanner.Available}");
            Console.WriteLine($"temp={Sanitize(SafeTempPath())}");

            try
            {
                var hits = scanner.ScanFile(file);
                Console.WriteLine("outcome=completed");
                Console.WriteLine($"hits={hits.Count}");
                return 0;
            }
            catch (YaraScanIncompleteException ex)
            {
                Console.WriteLine("outcome=incomplete");
                Console.WriteLine($"inner={ex.InnerException?.GetType().Name ?? "none"}");
                Console.WriteLine($"message={Sanitize(ex.Message)}");
                return 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"outcome=error:{ex.GetType().Name}");
                Console.WriteLine($"message={Sanitize(ex.Message)}");
                return 2;
            }
        }
        finally
        {
            Release(scanner, args);
        }
    }

    // The end of a harness run: report the rules dirs if asked, then dispose the scanner unless told not to.
    private static void Release(YaraCliScanner scanner, string[] args)
    {
        if (args.Contains("--report-rules-dirs"))
            Console.WriteLine($"rulesdirs={RulesDirCount()}");
        if (!args.Contains("--no-dispose"))
            scanner.Dispose();
    }

    // The scanner's rules dirs in this process's temp directory: `silvergun-yara-` plus 32 hex digits (a Guid "N"), which
    // excludes the staging dirs (`silvergun-yara-safe-…`). -1 when the temp directory cannot be listed.
    private static int RulesDirCount()
    {
        try
        {
            return Directory.EnumerateDirectories(Path.GetTempPath(), "silvergun-yara-*")
                .Select(Path.GetFileName)
                .Count(n => n is not null && n.Length == "silvergun-yara-".Length + 32
                            && n["silvergun-yara-".Length..].All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return -1;
        }
    }

    private static void PoisonTemp(string value)
    {
        foreach (var variable in new[] { "TMPDIR", "TEMP", "TMP" })
            Environment.SetEnvironmentVariable(variable, value);
    }

    private static string SafeTempPath()
    {
        try { return Path.GetTempPath(); }
        catch (Exception ex) { return "<unavailable: " + ex.GetType().Name + ">"; }
    }

    private static string? Value(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    // --- Role 3: a worker-mode logging host (--stderr-logging <logName> <levels|flood>) -------------------------------
    //
    // Runtime.WithStderrLogging (ADR 0033 worker-mode logging) installs the process-wide logger, and Runtime.Initialize
    // is once per process, so it cannot be observed inside the xunit host (already initialised, shared by parallel
    // tests). This role is a fresh process that configures worker-mode logging (debug on, so every level is enabled) and
    // then logs: "levels" once at every level, "flood" far past the 64 KiB cap, followed by a direct Console.Error write
    // that must also be capped. stdout gets only `stdout-only` and the writer's own counters, so a test can tell the two
    // streams apart.
    private static int StderrLogging(string logName, string mode)
    {
        var stderr = Silvergun.Runtime.WithStderrLogging("Silvergun", logName, debug: true);
        if (mode == "levels")
        {
            Silvergun.Runtime.Debug("probe-debug {0}", 1);
            Silvergun.Runtime.Info("probe-info {0}", 2);
            Silvergun.Runtime.Warn("probe-warn {0}", 3);
            Silvergun.Runtime.Error("probe-error {0}", 4);
            Silvergun.Runtime.Fatal("probe-fatal {0}", 5);
        }
        else
        {
            for (var i = 0; i < 5_000; i++)
                Silvergun.Runtime.Warn("probe-flood {0} {1}", i, new string('w', 100));
            Console.Error.WriteLine("probe-direct-after-flood");
        }

        Console.Out.Write($"stdout-only\ncapped-bytes={stderr.BytesWritten}\ntruncated={stderr.Truncated}\n");
        Console.Out.Flush();
        return 0;
    }
    #endregion
}
