namespace Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe;

using System.Globalization;

using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// A two-role child-process fixture for the ADR 0029 tests. Neither role can be played from inside the xunit
/// process, which is why this is its own executable.
///
/// <para><b>Role 1 — a fake <c>yara</c> binary (default).</b> <see cref="YaraCliScanner"/> launches whatever
/// <c>SILVERGUN_YARA_PATH</c> names, by path, with an argument list it controls. To pin "the batch process exited
/// non-zero" and "the batch process outlived its timeout" as <i>fail closed</i>, a test needs a real executable
/// that misbehaves on demand and on <b>both</b> platforms — <c>/bin/false</c> exists only on Unix, and nothing in
/// <c>System32</c> reliably hangs or fails for an arbitrary argument list without reading stdin. Behaviour is
/// taken from the environment (the argument list belongs to the scanner) and every argv is logged, which is also
/// how a test counts how many processes a scan actually spawned — the difference between the cheap single batch
/// pass and the per-file recovery pass.</para>
///
/// <para><b>Role 2 — a scanner harness (<c>--scan-directory</c>).</b> The one ADR 0029 failure site that cannot be
/// reached in-process is "the embedded ruleset could not be prepared": it is reached by making
/// <see cref="Path.GetTempPath"/> unusable, and <c>TMPDIR</c>/<c>TEMP</c> are process-global — poisoning them
/// inside the test host would break whatever unrelated test happens to be running in parallel. Here the poisoning
/// is scoped to this process, set after the runtime has started, and the outcome is reported on stdout.</para>
///
/// <para>This fixture never scans anything for real and contains no rule logic; it is deliberately inert.</para>
/// </summary>
internal static class Program
{
    #region Methods
    private static int Main(string[] args) =>
        args is ["--scan-directory", var root, ..] ? Harness(root, args) : FakeYara(args);

    // --- Role 1: the fake yara binary ------------------------------------------------------------------------

    // Ignores its arguments (they are the scanner's) and does exactly what the environment says: record the
    // invocation, optionally outlive the caller's timeout, then exit with the requested code.
    private static int FakeYara(string[] args)
    {
        Log(args);
        Emit(args);

        var sleepMs = Int("SILVERGUN_FAKEYARA_SLEEP_MS");
        if (sleepMs > 0)
            Thread.Sleep(sleepMs);

        return Int("SILVERGUN_FAKEYARA_EXIT_CODE");
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
    // Nothing here decides what "matches": the caller stages the output it wants parsed. This fixture stays inert.
    private static void Emit(string[] args)
    {
        var target = args.Length == 0 ? string.Empty : args[^1];
        if (target.Length == 0)
            return;

        if (Directory.Exists(target))
        {
            var batch = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_STDOUT");
            if (!string.IsNullOrEmpty(batch))
                Console.Out.Write(batch.Replace("\\n", "\n") + "\n");
            return;
        }

        var rule = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_ECHO_RULE");
        if (!string.IsNullOrEmpty(rule) && File.Exists(target))
            Console.Out.Write(rule + " " + target + "\n");
    }

    // One line per invocation, to the file named by SILVERGUN_FAKEYARA_LOG (absent ⇒ no log). Records the last
    // argument — for a `yara -r` pass the scanned root, for a recovery scan the safely named temp copy — and the
    // Unix mode of the directory holding it, which is how the "the staging directory is 0700" test observes a
    // directory that YaraCliScanner creates and deletes inside a single call.
    private static void Log(string[] args)
    {
        var log = Environment.GetEnvironmentVariable("SILVERGUN_FAKEYARA_LOG");
        if (string.IsNullOrEmpty(log))
            return;

        var target = args.Length == 0 ? string.Empty : args[^1];
        var line = $"argc={args.Length}|target={Sanitize(target)}|dirmode={DirMode(target)}\n";

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
    private static int Harness(string root, string[] args)
    {
        // Poison this process's temp directory (and only this process's) before the scanner is constructed, so
        // that its one-time ruleset preparation — Directory.CreateDirectory under Path.GetTempPath() — fails.
        var poison = Value(args, "--poison-temp");
        if (poison is not null)
            foreach (var variable in new[] { "TMPDIR", "TEMP", "TMP" })
                Environment.SetEnvironmentVariable(variable, poison);

        var timeout = Value(args, "--timeout-ms");
        var scanner = timeout is null ? new YaraCliScanner() : new YaraCliScanner(int.Parse(timeout, CultureInfo.InvariantCulture));

        // Printed BEFORE the scan and unconditionally: the point of several of these tests is that Available is
        // true (it is a one-time File.Exists on the binary) while the scan itself could not be performed.
        Console.WriteLine($"available={scanner.Available}");
        Console.WriteLine($"temp={Sanitize(SafeTempPath())}");

        try
        {
            var hits = scanner.ScanDirectory(root);
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
    #endregion
}
