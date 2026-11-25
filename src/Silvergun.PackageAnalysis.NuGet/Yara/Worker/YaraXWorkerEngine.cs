namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using Microsoft.Win32.SafeHandles;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

/// <summary>
/// The production engines of the <c>__worker yara</c> verb (ADR 0033 FINAL FORM). On Windows (the <c>net10.0-windows</c>
/// build) that is the YARA-X engine with the DPAPI-bound rules cache; on Linux the YARA-X engine with the secure-path rules
/// cache (<c>YaraXLinuxRulesCache</c>, docs/agent/tasks/yarax-worker-linux.md, Phase 2); anywhere else the verb answers
/// <c>fatal</c> "engine unavailable on this platform". Never the T1 stub.
/// </summary>
public static class YaraWorkerEngines
{
    #region Methods
    /// <summary>
    /// The engine for this build, every scan bounded by <paramref name="timeoutSeconds"/> (≥ 1). Creating it loads
    /// nothing: the YARA-X library and the rules load in <see cref="IYaraWorkerEngine.Start"/>.
    /// </summary>
    public static IYaraWorkerEngine ForPlatform(int timeoutSeconds) =>
#if WINDOWS
        new YaraXWorkerEngine(timeoutSeconds, new YaraXRulesCache());
#else
        OperatingSystem.IsLinux() ? new YaraXWorkerEngine(timeoutSeconds, new YaraXLinuxRulesCache()) : new UnavailableYaraWorkerEngine();
#endif
    #endregion
}

/// <summary>The engine of a build with no YARA-X binding: <see cref="Start"/> is always <c>fatal</c>.</summary>
internal sealed class UnavailableYaraWorkerEngine : IYaraWorkerEngine
{
    #region Methods
    public WorkerMessage Start() => new WorkerFatal(Reason);

    public WorkerResult Scan(WorkerRequest request) => new(request.Index, WorkerScanStatus.Error, Reason);
    #endregion

    #region Fields
    internal const string Reason = "engine unavailable on this platform: the YARA-X worker engine runs on Windows and Linux only";
    #endregion
}

/// <summary>
/// The request path form of worker protocol v1 (amendment G2), checked and turned into the form the file is opened
/// through, purely lexically. The ONE definition of the form (amendment (j')): the worker uses it to open a request's
/// file, and the parent (<c>YaraXWorkerScanner</c>) uses it both to refuse a path before sending it and as the form its
/// link check walks, so the two sides agree by construction.
/// <para><b>Windows</b>: a Win32 verbatim path. Never <see cref="Path.GetFullPath(string)"/>, which maps a real file named
/// <c>nul.txt</c> to the device <c>\\.\NUL</c>, and never any other normalization: the verbatim prefix opens exactly the
/// file named.</para>
/// <para><b>Unix</b> (docs/agent/tasks/yarax-worker-linux.md, L3): the path itself, which the kernel opens as named.
/// <c>/</c> is the only separator; a backslash is an ordinary file-name character there.</para>
/// </summary>
internal static class WorkerPathForm
{
    #region Methods
    /// <summary>The form of <paramref name="path"/> to open on this OS, or <c>null</c> when it is not in the protocol's form.</summary>
    internal static string? Verbatim(string? path) => Verbatim(path, OperatingSystem.IsWindows());

    /// <summary>
    /// On Windows (<paramref name="windows"/>), the verbatim form of <paramref name="path"/> — <c>\\?\C:\…</c> for a drive
    /// path, <c>\\?\UNC\server\share\…</c> for a UNC path — or <c>null</c> when it is not in the protocol's form:
    /// well-formed UTF-16 (review W1), absolute (<c>X:\</c> or <c>\\server\share\</c>), backslash-separated (no <c>/</c>),
    /// no empty, <c>.</c> or <c>..</c> segment, no NUL, and no <c>:</c> outside the drive designator (an NTFS file name
    /// cannot hold one, so it could only name an alternate data stream). Device and already-verbatim paths (<c>\\?\</c>,
    /// <c>\\.\</c>, <c>\??\</c>) are not in the form.
    /// <para>Elsewhere, <paramref name="path"/> itself, or <c>null</c> unless it is well-formed UTF-16, has no NUL, is
    /// absolute (<c>/</c> first) and has no empty, <c>.</c> or <c>..</c> segment.</para>
    /// </summary>
    internal static string? Verbatim(string? path, bool windows)
    {
        if (string.IsNullOrEmpty(path) || path.Contains('\0') || !WorkerProtocol.IsWellFormedUtf16(path))
            return null;
        if (!windows)
            return path[0] == '/' && path[1..].Split('/').All(s => s.Length > 0 && s is not ("." or "..")) ? path : null;
        if (path.Contains('/'))
            return null;

        if (path.Length > 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\')
            return Segments(path[3..], minimum: 1) ? VerbatimPrefix + path : null;

        // \\server\share\file: at least server, share and one name after the two leading backslashes. A server named '?'
        // or '.' is the verbatim or device namespace, not a server.
        return path.StartsWith(@"\\", StringComparison.Ordinal) && Segments(path[2..], minimum: 3) && path[2..].Split('\\')[0] is not "?"
            ? VerbatimUncPrefix + path[2..]
            : null;
    }

    private static bool Segments(string rest, int minimum)
    {
        var segments = rest.Split('\\');
        return segments.Length >= minimum && segments.All(s => s.Length > 0 && s is not ("." or "..") && !s.Contains(':'));
    }
    #endregion

    #region Fields
    private const string VerbatimPrefix = @"\\?\";
    private const string VerbatimUncPrefix = @"\\?\UNC\";
    #endregion
}

/// <summary>
/// The YARA-X engine of <c>__worker yara</c> (ADR 0033; task T3; Linux: docs/agent/tasks/yarax-worker-linux.md). <see cref="Start"/> loads the engine and the embedded
/// rules — from the user-private rules cache when an entry verifies, otherwise compiled — whose canary must pass, and
/// creates the ONE scanner every request uses. It is used from one thread only: the thread that called
/// <see cref="Start"/> (<see cref="YaraXScanner"/> refuses any other, because one scanner on two threads aborts the
/// process).
///
/// <para><b>Per request</b>: the path must be in the protocol's form (<see cref="WorkerPathForm"/>; otherwise
/// <c>error</c> "invalid path form"); the file is opened through that form with read sharing only, so nobody can write or
/// truncate it while it is read or mapped (amendment G7; on Linux the sharing is advisory, and the length re-check is the
/// guard), and scanned by bytes with the length re-checked after.
/// Only a completed engine scan is <c>scanned</c>; a timeout is <c>timeout</c>, and every other failure — open, read,
/// engine — is <c>error</c> with an escaped, bounded reason (ADR 0030: a file that was not scanned is never clean).</para>
/// </summary>
internal sealed class YaraXWorkerEngine : IYaraWorkerEngine, IDisposable
{
    #region Constructors
    internal YaraXWorkerEngine(int timeoutSeconds, IYaraXRulesCache? cache)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(timeoutSeconds, 1);
        (this.timeoutSeconds, this.cache) = (timeoutSeconds, cache);
    }
    #endregion

    #region Methods
    public WorkerMessage Start()
    {
        if (scanner is not null)
            return new WorkerFatal("the engine was already started");

        var loaded = YaraXEngine.Load(cache);
        if (loaded.Rules is not { } loadedRules)
            return new WorkerFatal(WorkerProtocol.Safe(loaded.Failure ?? "the YARA-X engine failed to start"));

        YaraXScanner? created = null;
        try
        {
            created = loadedRules.CreateScanner(timeoutSeconds);
            // The canary already passed on a scanner of its own; this proves the very scanner every request will use.
            if (created.CheckCanary() is { } canaryFailure)
                throw new InvalidOperationException("the request scanner failed the canary: " + canaryFailure);
        }
        catch (Exception ex)
        {
            created?.Dispose();
            loadedRules.Dispose();
            return new WorkerFatal(WorkerProtocol.Safe($"could not create the scanner: {ex.GetType().Name}: {ex.Message}"));
        }

        (rules, scanner) = (loadedRules, created);
        Runtime.Info("yara worker: YARA-X {0} ready with {1} rules ({2}); {3} rule source(s) with errors; canary passed; per-file timeout {4} s.",
            YaraXNative.EngineVersion, loadedRules.RuleCount, loaded.FromCache ? "from the rules cache" : "compiled", loadedRules.SourceErrors, timeoutSeconds);
        // G1: the worker reports a partial ruleset honestly; it is the parent that refuses to trust one (it requires 0).
        return new WorkerReady(WorkerProtocol.Version, EngineName, YaraXNative.EngineVersion, loadedRules.RuleCount, loadedRules.SourcesSha256, WorkerProtocol.CanaryPassed)
        {
            RuleSourceErrors = loadedRules.SourceErrors,
        };
    }

    public WorkerResult Scan(WorkerRequest request)
    {
        if (scanner is null)
            return Error(request.Index, "the engine is not started");
        if (WorkerPathForm.Verbatim(request.Path) is not { } verbatim)
            return Error(request.Index, InvalidPathForm);

        SafeFileHandle file;
        try
        {
            file = File.OpenHandle(verbatim, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Error(request.Index, $"could not open the file: {ex.GetType().Name}: {ex.Message}");
        }

        using (file)
            return scanner.Scan(file) switch
            {
                YaraXScanResult.Scanned scanned => new(request.Index, WorkerScanStatus.Scanned,
                    Hits: scanned.Hits.Select(h => new WorkerHit(h.Rule, h.Namespace, h.Tags)).ToArray()),
                YaraXScanResult.Timeout => new(request.Index, WorkerScanStatus.Timeout, $"the scan did not finish within the engine timeout of {timeoutSeconds} s"),
                YaraXScanResult.Error error => Error(request.Index, error.Message),
                var other => Error(request.Index, $"the engine returned an unknown result '{other.GetType().Name}'"),
            };
    }

    public void Dispose()
    {
        scanner?.Dispose();
        rules?.Dispose();
    }

    private static WorkerResult Error(int index, string reason) => new(index, WorkerScanStatus.Error, WorkerProtocol.Safe(reason));
    #endregion

    #region Fields
    /// <summary>The <see cref="WorkerReady.Engine"/> of this engine.</summary>
    internal const string EngineName = "yara-x";

    /// <summary>The reason for a request whose path is not in the protocol's form (amendment G2).</summary>
    internal const string InvalidPathForm = "invalid path form";

    private readonly int timeoutSeconds;
    private readonly IYaraXRulesCache? cache;
    private YaraXRules? rules;
    private YaraXScanner? scanner;
    #endregion
}
