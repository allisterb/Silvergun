namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The one xunit collection every YARA test class belongs to, and the helpers those classes share.
///
/// <para><b>Why a collection.</b> <c>SILVERGUN_YARA_PATH</c>, <c>SILVERGUN_YARAC_PATH</c> and the
/// <c>SILVERGUN_FAKEYARA_*</c> knobs are <b>process-global</b>, and xunit runs test <i>collections</i> in
/// parallel: with every YARA class in its own implicit collection, one class pointing the scanner at a
/// placeholder binary raced another class asserting that the scanner is unavailable, and either could win.
/// That race was live (it is review item W3) and is not hypothetical — it silently decides which binary a
/// <see cref="YaraCliScanner"/> constructed in the other class latches onto. Serializing these classes against
/// each other is the fix; they still run in parallel with the rest of the assembly, which never touches these
/// variables.</para>
/// </summary>
[CollectionDefinition(Name)]
public sealed class YaraEnvCollection
{
    /// <summary>The collection name. Every class that reads or writes a YARA environment variable carries
    /// <c>[Collection(YaraEnvCollection.Name)]</c>.</summary>
    public const string Name = "yara-env";
}

/// <summary>
/// Saves and restores the YARA path environment variables around a test, so a developer's real
/// <c>SILVERGUN_YARA_PATH</c> cannot leak into — or be clobbered by — the suite. Shared by every YARA test class
/// (there used to be a private copy per class).
/// </summary>
internal sealed class YaraEnvScope : IDisposable
{
    #region Constructors
    public YaraEnvScope(string? yara, string? yarac)
    {
        // Pin the process-wide memoized backend BEFORE poisoning the environment. YaraScannerFactory.Shared is a
        // Lazy that reads SILVERGUN_YARA_PATH exactly once, on first touch, for the lifetime of the process — so
        // whichever test happens to touch it first decides what EVERY later PackageScanner.Scan that does not
        // inject a backend will use. Without this, a test pointing the variable at a fake binary could leave the
        // whole assembly driving that fake: measured as a 5x slowdown of the suite (every default-runYara scan
        // spawning a stand-in process), and in principle as a wrong result. Touching it here fixes the selection
        // to the ambient environment, deterministically, no matter which test runs first. It cannot throw here in
        // any configuration we ship, but a backend constructor is native code on Windows, so it is guarded.
        try { _ = YaraScannerFactory.Shared; }
        catch { /* an unhealthy ambient backend is not this scope's problem */ }

        _previousYara = Environment.GetEnvironmentVariable(YaraCliScanner.YaraPathVar);
        _previousYarac = Environment.GetEnvironmentVariable(YaraCliScanner.YaracPathVar);
        Environment.SetEnvironmentVariable(YaraCliScanner.YaraPathVar, yara);
        Environment.SetEnvironmentVariable(YaraCliScanner.YaracPathVar, yarac);
    }
    #endregion

    #region Methods
    public void Dispose()
    {
        Environment.SetEnvironmentVariable(YaraCliScanner.YaraPathVar, _previousYara);
        Environment.SetEnvironmentVariable(YaraCliScanner.YaracPathVar, _previousYarac);
    }
    #endregion

    #region Fields
    private readonly string? _previousYara;
    private readonly string? _previousYarac;
    #endregion
}

/// <summary>
/// A file called <c>yara</c> that exists but is not an executable, in a directory of its own. It makes
/// <see cref="YaraCliScanner"/> report <c>Available</c> (that signal is a one-time <c>File.Exists</c>, never a
/// process launch) while every launch of it fails — the cross-platform way to reach the "the engine did not
/// produce a usable run" branch without a real engine. Its own directory matters: the scanner derives
/// <c>yarac</c> beside <c>yara</c>, and an empty directory guarantees that derivation finds nothing, so preparing
/// the ruleset launches no process either.
/// </summary>
internal sealed class PlaceholderYaraBinary : IDisposable
{
    #region Constructors
    public PlaceholderYaraBinary()
    {
        Directory = Path.Combine(Path.GetTempPath(), "silvergun-fake-yara-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Directory);
        BinaryPath = Path.Combine(Directory, "yara");
        File.WriteAllText(BinaryPath, "not a real yara binary");
        _env = new YaraEnvScope(BinaryPath, yarac: null);
    }
    #endregion

    #region Properties
    public string Directory { get; }

    public string BinaryPath { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        _env.Dispose();
        try
        {
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private readonly YaraEnvScope _env;
    #endregion
}

/// <summary>
/// Points <c>SILVERGUN_YARA_PATH</c> at a private copy of a trivial POSIX binary — <c>/bin/true</c>, which
/// ignores its arguments and exits 0. For the tests that care only about <b>how many files the scanner tried to
/// scan</b>, this is the cheapest possible engine: the recovery-pass cap needs 64 successful single-file scans,
/// and 64 managed apphost launches on a WSL share would dominate the suite's run time.
///
/// <para>The copy is what makes it private, and the name is chosen so that <c>YaraCliScanner</c>'s "derive
/// <c>yarac</c> beside <c>yara</c>" step finds nothing: pointing straight at <c>/bin/true</c> would make it
/// derive <c>/bin/yarac</c>, which exists on a box with yara installed, and every test would then pay for a real
/// ruleset compilation it does not need.</para>
/// </summary>
internal sealed class TrivialYaraStandIn : IDisposable
{
    #region Constructors
    public TrivialYaraStandIn()
    {
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("This stand-in copies a POSIX binary; [LinuxFact] must have gated its caller.");

        var source = YaraCliProbe.AlwaysSucceedingBinary
            ?? throw new InvalidOperationException("No /bin/true was found; this stand-in is for POSIX hosts only.");

        Directory = Path.Combine(Path.GetTempPath(), "silvergun-standin-yara-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Directory);
        BinaryPath = Path.Combine(Directory, "exit-zero-stand-in");
        File.Copy(source, BinaryPath);
        File.SetUnixFileMode(
            BinaryPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        _env = new YaraEnvScope(BinaryPath, yarac: null);
    }
    #endregion

    #region Properties
    public string Directory { get; }

    public string BinaryPath { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        _env.Dispose();
        try
        {
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private readonly YaraEnvScope _env;
    #endregion
}

/// <summary>
/// A POSIX <c>/bin/sh</c> stand-in for <c>yara</c> that does exactly two things, both cheaply: on the recursive pass
/// (last argument a directory) it prints <c>"&lt;rule&gt; &lt;file&gt;"</c> for <c>&lt;root&gt;/&lt;payload&gt;</c>
/// and <c>&lt;root&gt;/*/&lt;payload&gt;</c> when they exist (the second shape is a package's extraction directory,
/// which nests the content under a folder named after the <c>.nupkg</c>), and on a single-file scan it prints
/// nothing and exits with <paramref name="singleFileExitCode"/>.
///
/// <para>Why not the <c>FakeYaraProbe</c>: the ADR 0032 headline shape is a payload plus <b>65</b> unsafe names, which
/// spends <c>MaxIndividualScans</c> = 64 single-file launches before the 65th overflows — 64 managed apphost starts
/// would dominate the suite (the same reason <see cref="TrivialYaraStandIn"/> exists), while 64 <c>sh</c> starts cost
/// milliseconds. The script is generated text holding only test-chosen constants (a rule name, a relative path with
/// no quote characters, a number), and it is launched by the scanner's own argument-list <c>Process.Start</c>, never
/// through a shell string.</para>
/// </summary>
internal sealed class ScriptedYaraStandIn : IDisposable
{
    #region Constructors
    public ScriptedYaraStandIn(string rule, string payloadRelative, int singleFileExitCode = 0)
    {
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("This stand-in is a /bin/sh script; [LinuxFact] must have gated its caller.");
        if ((rule + payloadRelative).Any(c => c is '\'' or '\\' or '$' or '`' || c < ' '))
            throw new ArgumentException("The stand-in embeds its parameters in single quotes; keep them plain.");

        Directory = Path.Combine(Path.GetTempPath(), "silvergun-scripted-yara-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Directory);
        // Named so that YaraCliScanner's "derive yarac beside yara" step finds nothing (see TrivialYaraStandIn).
        BinaryPath = Path.Combine(Directory, "scripted-stand-in");
        // On the recursive pass it also prints, like real yara, one coverage-sentinel line (ADR 0032 decision 9) per
        // regular file under the root — the sentinel's name read from the rules file (the argument before the
        // target), `-type f` so a symlink is skipped exactly as `yara -r -N` skips it — and nothing when the rules
        // declare no sentinel. Without it every attributable file would read as unscanned and be re-scanned.
        File.WriteAllText(BinaryPath,
            "#!/bin/sh\n"
            + "prev=; last=\n"
            + "for a in \"$@\"; do prev=$last; last=$a; done\n"
            + "if [ -d \"$last\" ]; then\n"
            + $"  for f in \"$last\"/'{payloadRelative}' \"$last\"/*/'{payloadRelative}'; do\n"
            + $"    if [ -f \"$f\" ]; then printf '%s %s\\n' '{rule}' \"$f\"; fi\n"
            + "  done\n"
            + "  s=$(grep -o 'rule SilvergunCoverageSentinel_[0-9a-f]\\{32\\}' \"$prev\" 2>/dev/null | head -n 1)\n"
            + "  s=${s#rule }\n"
            + "  if [ -n \"$s\" ]; then find \"$last\" -type f -exec printf '%s [] %s\\n' \"$s\" {} \\; ; fi\n"
            + "  exit 0\n"
            + "fi\n"
            + $"exit {singleFileExitCode}\n");
        File.SetUnixFileMode(
            BinaryPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        _env = new YaraEnvScope(BinaryPath, yarac: null);
    }
    #endregion

    #region Properties
    public string Directory { get; }

    public string BinaryPath { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        _env.Dispose();
        try
        {
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private readonly YaraEnvScope _env;
    #endregion
}

/// <summary>
/// Points <c>SILVERGUN_YARA_PATH</c> at the <c>FakeYaraProbe</c> apphost (see that project) and configures its
/// behaviour for the duration of a test: the exit code it returns, how long it sleeps before returning, and
/// whether it records each invocation.
///
/// <para>This is what makes "the batch process exited non-zero" and "the batch process outlived its timeout"
/// testable on Windows as well as Linux, and what lets a test <b>count</b> the processes a scan spawned — the
/// observable difference between the single cheap <c>yara -r</c> pass and the one-process-per-file recovery
/// pass.</para>
///
/// <para><paramref name="batchStdOut"/> and <paramref name="echoRule"/> stage the engine's <b>output</b>, which is
/// the only thing attribution has to work with. <paramref name="batchStdOut"/> is printed verbatim by the
/// recursive pass (the two-character sequence <c>\n</c> becomes a real newline), so a test can reproduce the exact
/// bytes <c>yara -r</c> prints for a hostile name — including a hit split across two physical lines, which is the
/// shape ADR 0029 decision 17 is about. <paramref name="echoRule"/> makes a single-file scan print
/// <c>"&lt;rule&gt; &lt;the file it was handed&gt;"</c>, which is the only way to stage a hit on the recovery
/// pass's temp copy: the scanner generates that name, so a test cannot know it in advance.</para>
///
/// <para><paramref name="batchEchoRule"/>/<paramref name="batchEchoName"/>/<paramref name="batchGhost"/> are the
/// recursive-pass equivalent for a root the test cannot name in advance (a package's extraction directory): the
/// probe prints a hit for every file named <paramref name="batchEchoName"/>, plus, optionally, one for a sibling
/// called <paramref name="batchGhost"/> that does not exist — an unattributable hit (ADR 0029 decision 17).</para>
///
/// <para><paramref name="batchStdErr"/> is printed on the recursive pass's <b>stderr</b> (same <c>\n</c> decoding as
/// <paramref name="batchStdOut"/>) while the process still exits <paramref name="exitCode"/> — by default 0. That is
/// how real <c>yara -r</c> reports a file it could not open or that outlasted its <c>--timeout</c> (ADR 0032
/// decision 7), so it is what stages "the batch pass ran, exited 0, and did NOT scan everything".</para>
///
/// <para><b>Coverage sentinel (ADR 0032 decision 9).</b> Like real yara, the probe prints a
/// <c>&lt;sentinel&gt; [] &lt;file&gt;</c> line for every file its recursive pass "scans", reading the sentinel rule's
/// name from the rules file the scanner hands it — so by default every enumerated file is covered and a test that
/// does not care about coverage sees the same scanner behaviour as before decision 9. <paramref name="sentinelSkip"/>
/// (<c>'|'</c>-separated file names, a trailing <c>*</c> for a prefix, <c>"*"</c> for all) withholds the line for the
/// files a real <c>yara -r</c> would have dropped at its one global <c>--timeout</c> deadline;
/// <paramref name="sentinelForge"/> prints a coverage line under a <i>wrong</i> rule name in its place;
/// <paramref name="sentinelGhost"/> adds a real sentinel line for a file that does not exist.
/// <paramref name="singleFileExitCode"/> overrides the exit code of single-file scans only, and
/// <paramref name="fakeYarac"/> also points <c>SILVERGUN_YARAC_PATH</c> at the probe (which then plays a <c>yarac</c>
/// that byte-copies the source, or fails with <paramref name="yaracExitCode"/>), to reach the compiled-rules path.</para>
///
/// <para>Round E knobs. <paramref name="singleFileSleepMs"/> replaces <paramref name="sleepMs"/> for single-file scans
/// only (a cheap recursive pass, slow re-scans: the recovery budget's shape); <paramref name="singleFileFail"/>
/// (<c>'|'</c>-separated file names) fails only those files' single-file scans; <paramref name="batchEchoRepeat"/> prints
/// the <paramref name="batchEchoRule"/> block that many times, byte-identical. <paramref name="sentinelForge"/> also
/// takes <c>"@upper"</c> / <c>"@upper-suffix"</c>: the ruleset's real sentinel name in another case.</para>
/// </summary>
internal sealed class FakeYaraBinary : IDisposable
{
    #region Constructors
    public FakeYaraBinary(
        int exitCode = 0, int sleepMs = 0, bool recordInvocations = false,
        string? batchStdOut = null, string? echoRule = null,
        string? batchEchoRule = null, string? batchEchoName = null, string? batchGhost = null,
        string? batchStdErr = null,
        string? sentinelSkip = null, string? sentinelForge = null, string? sentinelGhost = null,
        int? singleFileExitCode = null, bool fakeYarac = false, int yaracExitCode = 0,
        int? singleFileSleepMs = null, string? singleFileFail = null, int batchEchoRepeat = 1)
    {
        Assert.True(
            File.Exists(ProbePath),
            $"The FakeYaraProbe apphost was not found at '{ProbePath}'. It is a ProjectReference of this test "
            + "project, so a normal build produces it; a missing apphost means the fixture project did not build.");

        LogPath = recordInvocations
            ? Path.Combine(Path.GetTempPath(), "silvergun-fakeyara-log-" + Guid.NewGuid().ToString("N") + ".txt")
            : null;

        _previous = Knobs.ToDictionary(k => k, Environment.GetEnvironmentVariable);
        Environment.SetEnvironmentVariable(ExitCodeVar, exitCode.ToString());
        Environment.SetEnvironmentVariable(SleepVar, sleepMs.ToString());
        Environment.SetEnvironmentVariable(LogVar, LogPath);
        Environment.SetEnvironmentVariable(StdOutVar, batchStdOut);
        Environment.SetEnvironmentVariable(EchoRuleVar, echoRule);
        Environment.SetEnvironmentVariable(BatchEchoRuleVar, batchEchoRule);
        Environment.SetEnvironmentVariable(BatchEchoNameVar, batchEchoName);
        Environment.SetEnvironmentVariable(BatchGhostVar, batchGhost);
        Environment.SetEnvironmentVariable(BatchStdErrVar, batchStdErr);
        Environment.SetEnvironmentVariable(SentinelSkipVar, sentinelSkip);
        Environment.SetEnvironmentVariable(SentinelForgeVar, sentinelForge);
        Environment.SetEnvironmentVariable(SentinelGhostVar, sentinelGhost);
        Environment.SetEnvironmentVariable(SingleExitCodeVar, singleFileExitCode?.ToString());
        Environment.SetEnvironmentVariable(YaracExitCodeVar, yaracExitCode.ToString());
        Environment.SetEnvironmentVariable(SingleSleepVar, singleFileSleepMs?.ToString());
        Environment.SetEnvironmentVariable(SingleFailVar, singleFileFail);
        Environment.SetEnvironmentVariable(BatchEchoRepeatVar, batchEchoRepeat.ToString());
        _env = new YaraEnvScope(ProbePath, yarac: fakeYarac ? ProbePath : null);
    }
    #endregion

    #region Properties
    /// <summary>The apphost the scanner will launch as its <c>yara</c> binary.</summary>
    public static string ProbePath { get; } =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe");

    /// <summary>Where the probe records its invocations, or <c>null</c> when recording was not requested.</summary>
    public string? LogPath { get; }

    /// <summary>One entry per launch of the fake binary, in order: <c>argc=…|target=…|dirmode=…|compiled=…|sentinel=…|rules=…</c>.</summary>
    public IReadOnlyList<string> Invocations =>
        LogPath is not null && File.Exists(LogPath)
            ? File.ReadAllLines(LogPath).Where(l => l.Length > 0).ToArray()
            : Array.Empty<string>();

    /// <summary>
    /// The temp directories holding the rulesets the logged launches were handed (the directory of each <c>rules=</c>
    /// field), distinct, in launch order: where <see cref="YaraCliScanner"/> prepared them, which is what its lifetime
    /// tests watch being deleted.
    /// </summary>
    public IReadOnlyList<string> RulesDirs =>
        Invocations
            .Select(i => i.Split('|').Select(p => p.Split('=', 2)).First(p => p[0] == "rules")[1])
            .Select(p => Path.GetDirectoryName(p)!)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    #endregion

    #region Methods
    public void Dispose()
    {
        _env.Dispose();
        foreach (var (key, value) in _previous)
            Environment.SetEnvironmentVariable(key, value);

        try
        {
            if (LogPath is not null && File.Exists(LogPath))
                File.Delete(LogPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private const string ExitCodeVar = "SILVERGUN_FAKEYARA_EXIT_CODE";
    private const string SleepVar = "SILVERGUN_FAKEYARA_SLEEP_MS";
    private const string LogVar = "SILVERGUN_FAKEYARA_LOG";
    private const string StdOutVar = "SILVERGUN_FAKEYARA_STDOUT";
    private const string EchoRuleVar = "SILVERGUN_FAKEYARA_ECHO_RULE";
    private const string BatchEchoRuleVar = "SILVERGUN_FAKEYARA_BATCH_ECHO_RULE";
    private const string BatchEchoNameVar = "SILVERGUN_FAKEYARA_BATCH_ECHO_NAME";
    private const string BatchGhostVar = "SILVERGUN_FAKEYARA_BATCH_GHOST";
    private const string BatchStdErrVar = "SILVERGUN_FAKEYARA_BATCH_STDERR";
    private const string SentinelSkipVar = "SILVERGUN_FAKEYARA_SENTINEL_SKIP";
    private const string SentinelForgeVar = "SILVERGUN_FAKEYARA_SENTINEL_FORGE";
    private const string SentinelGhostVar = "SILVERGUN_FAKEYARA_SENTINEL_GHOST";
    private const string SingleExitCodeVar = "SILVERGUN_FAKEYARA_SINGLE_EXIT_CODE";
    private const string YaracExitCodeVar = "SILVERGUN_FAKEYARA_YARAC_EXIT_CODE";
    private const string SingleSleepVar = "SILVERGUN_FAKEYARA_SINGLE_SLEEP_MS";
    private const string SingleFailVar = "SILVERGUN_FAKEYARA_SINGLE_FAIL";
    private const string BatchEchoRepeatVar = "SILVERGUN_FAKEYARA_BATCH_ECHO_REPEAT";

    // Every knob is saved and restored by Dispose, so a test that leaves one unset cannot inherit a previous test's.
    private static readonly string[] Knobs =
    [
        ExitCodeVar, SleepVar, LogVar, StdOutVar, EchoRuleVar, BatchEchoRuleVar, BatchEchoNameVar, BatchGhostVar, BatchStdErrVar,
        SentinelSkipVar, SentinelForgeVar, SentinelGhostVar, SingleExitCodeVar, YaracExitCodeVar,
        SingleSleepVar, SingleFailVar, BatchEchoRepeatVar,
    ];

    private readonly Dictionary<string, string?> _previous;
    private readonly YaraEnvScope _env;
    #endregion
}

/// <summary>
/// Runs <see cref="YaraCliScanner.ScanDirectory"/> inside the <c>FakeYaraProbe</c> child process and parses its
/// <c>key=value</c> report. Needed for exactly one thing: the ruleset-preparation failure, which is reached by
/// making <see cref="Path.GetTempPath"/> unusable — a process-global change that would corrupt whatever unrelated
/// test happens to run in parallel if it were made inside the test host.
/// </summary>
internal static class YaraHarness
{
    #region Methods
    public static HarnessResult ScanDirectory(string root, string yaraPath, string? poisonTempWith = null, int? timeoutMs = null) =>
        Run("--scan-directory", root, yaraPath, poisonTempWith, timeoutMs);

    /// <summary>
    /// One scanner instance scans <paramref name="warmup"/> first, then the temp directory is poisoned with
    /// <paramref name="poisonTempAfterWarmupWith"/>, then it scans <paramref name="root"/> — so whichever ruleset the
    /// warm-up did NOT prepare can no longer be prepared (ADR 0032 decision 9 keeps two, prepared lazily).
    /// </summary>
    public static HarnessResult ScanDirectoryAfterWarmup(string root, string warmup, string yaraPath, string poisonTempAfterWarmupWith) =>
        Run("--scan-directory", root, yaraPath, poisonTempWith: null, timeoutMs: null,
            ["--warmup", warmup, "--poison-temp-after-warmup", poisonTempAfterWarmupWith]);

    /// <summary>The same harness over <see cref="YaraCliScanner.ScanFile"/> (ADR 0032 decision 5).</summary>
    public static HarnessResult ScanFile(string file, string yaraPath, string? poisonTempWith = null) =>
        Run("--scan-file", file, yaraPath, poisonTempWith, timeoutMs: null);

    /// <summary>
    /// The scanner-lifetime run: the child's temp directory is <paramref name="privateTemp"/> (TMP, TEMP and TMPDIR, so
    /// <see cref="Path.GetTempPath"/> resolves there on Windows and Linux alike), it reports how many rules dirs exist
    /// there once the scan is done (<c>rulesdirs=N</c>), and with <paramref name="dispose"/> false it never disposes the
    /// scanner — leaving those dirs to the scanner's process-exit fallback, as the never-disposed shared instance does.
    /// </summary>
    public static HarnessResult ScanDirectoryInPrivateTemp(string root, string yaraPath, string privateTemp, bool dispose) =>
        Run("--scan-directory", root, yaraPath, poisonTempWith: null, timeoutMs: null,
            dispose ? ["--report-rules-dirs"] : ["--report-rules-dirs", "--no-dispose"], privateTemp);

    private static HarnessResult Run(
        string mode, string target, string yaraPath, string? poisonTempWith, int? timeoutMs, string[]? extra = null,
        string? privateTemp = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = FakeYaraBinary.ProbePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(mode);
        psi.ArgumentList.Add(target);
        if (poisonTempWith is not null)
        {
            psi.ArgumentList.Add("--poison-temp");
            psi.ArgumentList.Add(poisonTempWith);
        }
        if (timeoutMs is not null)
        {
            psi.ArgumentList.Add("--timeout-ms");
            psi.ArgumentList.Add(timeoutMs.Value.ToString());
        }
        foreach (var arg in extra ?? [])
            psi.ArgumentList.Add(arg);

        // The child's own environment, not the test host's: the harness never relies on inherited YARA state.
        psi.Environment[YaraCliScanner.YaraPathVar] = yaraPath;
        psi.Environment.Remove(YaraCliScanner.YaracPathVar);
        if (privateTemp is not null)
            foreach (var variable in new[] { "TMPDIR", "TEMP", "TMP" })
                psi.Environment[variable] = privateTemp;

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Could not start the harness at '{FakeYaraBinary.ProbePath}'.");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(120_000), "The YARA harness child process did not exit within 120 s.");

        return new HarnessResult(process.ExitCode, stdout, stderr);
    }
    #endregion

    #region Nested types
    internal sealed record HarnessResult(int ExitCode, string StdOut, string StdErr)
    {
        /// <summary>The value of a <c>key=value</c> line the harness printed, or <c>null</c>.</summary>
        public string? this[string key] =>
            StdOut.Split('\n')
                .Select(l => l.TrimEnd('\r'))
                .FirstOrDefault(l => l.StartsWith(key + "=", StringComparison.Ordinal))
                ?[(key.Length + 1)..];

        /// <summary>Everything the child said, for an assertion message that explains itself.</summary>
        public string Report => $"exit={ExitCode}\nstdout:\n{StdOut}\nstderr:\n{StdErr}";
    }
    #endregion
}

/// <summary>
/// Resolves the platform-appropriate file name of a <c>dotnet build</c>-produced apphost: a <c>.exe</c> suffix
/// only on Windows. Duplicated (not shared) from the same helper in <c>Silvergun.CLI.Tests</c> /
/// <c>Silvergun.CodeAnalysis.IL.Tests</c>, which have no project reference to this assembly.
/// </summary>
internal static class ApphostPath
{
    #region Methods
    public static string Resolve(string baseDirectory, string assemblyName) =>
        Path.Combine(baseDirectory, OperatingSystem.IsWindows() ? $"{assemblyName}.exe" : assemblyName);
    #endregion
}

/// <summary>
/// A self-cleaning temp tree whose <see cref="Write"/> takes a forward-slash relative path and returns the
/// absolute path written. It writes <b>bytes</b> and does not translate separators, because the names these tests
/// stage intentionally contain characters (newline, carriage return, a trailing space) that must reach the
/// filesystem verbatim.
/// </summary>
internal sealed class TempTree : IDisposable
{
    #region Constructors
    public TempTree()
    {
        Root = Path.Combine(Path.GetTempPath(), "silvergun-yara-unsafe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
    }
    #endregion

    #region Properties
    public string Root { get; }
    #endregion

    #region Methods
    public string Write(string relative, byte[] bytes)
    {
        var full = Path.Combine(Root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, bytes);
        return full;
    }

    public string Write(string relative, string text) => Write(relative, System.Text.Encoding.UTF8.GetBytes(text));

    public void Dispose()
    {
        try
        {
            if (!Directory.Exists(Root))
                return;

            // A mode-000 entry staged by an unrecoverable-file test would otherwise be fine to delete, but restore
            // permissions first so cleanup cannot depend on the platform's unlink semantics.
            if (OperatingSystem.IsLinux())
                Restore(Root);

            Directory.Delete(Root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    private static void Restore(string dir)
    {
        if (!OperatingSystem.IsLinux())
            return;

        foreach (var sub in Directory.GetDirectories(dir))
        {
            try { File.SetUnixFileMode(sub, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            Restore(sub);
        }

        foreach (var file in Directory.GetFiles(dir))
        {
            try { File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
    #endregion
}
