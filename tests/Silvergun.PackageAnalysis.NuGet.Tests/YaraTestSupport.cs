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
/// </summary>
internal sealed class FakeYaraBinary : IDisposable
{
    #region Constructors
    public FakeYaraBinary(
        int exitCode = 0, int sleepMs = 0, bool recordInvocations = false,
        string? batchStdOut = null, string? echoRule = null)
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
        _env = new YaraEnvScope(ProbePath, yarac: null);
    }
    #endregion

    #region Properties
    /// <summary>The apphost the scanner will launch as its <c>yara</c> binary.</summary>
    public static string ProbePath { get; } =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe");

    /// <summary>Where the probe records its invocations, or <c>null</c> when recording was not requested.</summary>
    public string? LogPath { get; }

    /// <summary>One entry per launch of the fake binary, in order: <c>argc=…|target=…|dirmode=…</c>.</summary>
    public IReadOnlyList<string> Invocations =>
        LogPath is not null && File.Exists(LogPath)
            ? File.ReadAllLines(LogPath).Where(l => l.Length > 0).ToArray()
            : Array.Empty<string>();
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

    private static readonly string[] Knobs = [ExitCodeVar, SleepVar, LogVar, StdOutVar, EchoRuleVar];

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
    public static HarnessResult ScanDirectory(string root, string yaraPath, string? poisonTempWith = null, int? timeoutMs = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = FakeYaraBinary.ProbePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("--scan-directory");
        psi.ArgumentList.Add(root);
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

        // The child's own environment, not the test host's: the harness never relies on inherited YARA state.
        psi.Environment[YaraCliScanner.YaraPathVar] = yaraPath;
        psi.Environment.Remove(YaraCliScanner.YaracPathVar);

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
