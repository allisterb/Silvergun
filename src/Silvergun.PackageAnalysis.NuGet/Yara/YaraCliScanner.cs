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
/// Contract: <b>never throws</b>. All package content is hostile, so the process is launched with an argument
/// list (never a shell string), bounded by a timeout with <c>Kill(entireProcessTree)</c>, and its output is
/// parsed defensively. Any failure — missing binary, nonzero exit, timeout, malformed output — logs a note and
/// yields an empty result; the scan always continues.
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
        if (_yaraPath is null)
            return Array.Empty<YaraMatch>();

        var ruleSet = _ruleSet.Value;
        if (ruleSet is null)
            return Array.Empty<YaraMatch>();

        try
        {
            if (string.IsNullOrEmpty(fullPath) || !File.Exists(fullPath))
            {
                Warn("Skipping YARA scan for {0}: file not found on disk.", fullPath);
                return Array.Empty<YaraMatch>();
            }

            var options = new YaraOptions
            {
                Compiled = ruleSet.Compiled,
                PrintStrings = true,
                PrintTags = true,
                NoFollowSymlinks = true,
                Timeout = Math.Max(1, _scanTimeoutMs / 1000),
            };

            var args = options.ToArgs();
            args.Add(ruleSet.Path);
            args.Add(fullPath);

            var result = RunProcess(_yaraPath, args, _scanTimeoutMs + GraceMs);
            if (result is not { ExitCode: 0 })
            {
                var stderr = result?.StdErr?.Trim();
                if (!string.IsNullOrEmpty(stderr))
                    Warn("YARA scan of {0} failed: {1}", fullPath, stderr);
                return Array.Empty<YaraMatch>();
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
            Warn("YARA scan failed for {0}: {1}", fullPath, ex.Message);
            return Array.Empty<YaraMatch>();
        }
    }

    /// <summary>
    /// Scans every file under <paramref name="rootDir"/> in a <b>single</b> recursive <c>yara -r</c> process
    /// (far cheaper than one process per file), then attributes each hit to the real file its echoed target path
    /// resolves to via <see cref="TargetMatches"/> normalized-exact-equality. Hits whose target is not a real
    /// file under the scanned root (a warning line, prose, or a directory) are dropped. Returns empty when
    /// <c>yara</c> is unavailable, the rules did not compile, the directory is missing, or the process errors or
    /// times out. Never throws.
    /// </summary>
    public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
    {
        if (_yaraPath is null)
            return Array.Empty<(string, YaraMatch)>();

        var ruleSet = _ruleSet.Value;
        if (ruleSet is null)
            return Array.Empty<(string, YaraMatch)>();

        try
        {
            if (string.IsNullOrEmpty(rootDir) || !Directory.Exists(rootDir))
            {
                Warn("Skipping YARA scan of {0}: directory not found on disk.", rootDir);
                return Array.Empty<(string, YaraMatch)>();
            }

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

            var result = RunProcess(_yaraPath, args, _scanTimeoutMs + GraceMs);
            if (result is not { ExitCode: 0 })
            {
                var stderr = result?.StdErr?.Trim();
                if (!string.IsNullOrEmpty(stderr))
                    Warn("YARA scan of {0} failed: {1}", rootDir, stderr);
                return Array.Empty<(string, YaraMatch)>();
            }

            // The echoed target must resolve to an actual extracted file (the header regex is permissive enough
            // to match arbitrary prose). Enumerate the tree once and attribute each hit to its matching file.
            string[] files;
            try { files = Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories); }
            catch { return Array.Empty<(string, YaraMatch)>(); }

            return YaraCliOutput.ParseAll(result.StdOut)
                .Select(r => (File: files.FirstOrDefault(f => TargetMatches(r.Target, f)), r.Match))
                .Where(x => x.File is not null)
                .Select(x => (x.File!, x.Match))
                .ToArray();
        }
        catch (Exception ex)
        {
            Warn("YARA scan failed for {0}: {1}", rootDir, ex.Message);
            return Array.Empty<(string, YaraMatch)>();
        }
    }

    // True when a parsed header target refers to the file we actually scanned. ScanFile always hands yara the
    // ABSOLUTE fullPath and classic yara echoes that path verbatim, so the robust, platform-independent primitive is
    // normalized exact equality (case-insensitive, '/' and '\' treated alike). A bidirectional raw-string EndsWith
    // would over-match across a filename-character boundary (e.g. "ab.dll" vs "b.dll") on POSIX, where GetFullPath
    // does not drive-root the input — so we deliberately do NOT do that. Any parse/normalize failure ⇒ "no match".
    internal static bool TargetMatches(string? target, string fullPath)
    {
        if (string.IsNullOrWhiteSpace(target))
            return false;

        try
        {
            return Normalize(target).Equals(Normalize(fullPath), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }

        static string Normalize(string path) =>
            Path.GetFullPath(path.Trim()).Replace('\\', '/').TrimEnd('/');
    }

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
            if (result is not { ExitCode: 0 } || !File.Exists(compiledPath))
            {
                var stderr = result?.StdErr?.Trim();
                Warn("yarac failed to compile embedded YARA rules ({0}); scanning with uncompiled rules.",
                    string.IsNullOrEmpty(stderr) ? "no detail" : stderr);
                return new RuleSet(sourcePath, Compiled: false);
            }

            Info("Compiled {0} embedded YARA rule file(s) with yarac for malware-signature scanning.", count);
            return new RuleSet(compiledPath, Compiled: true);
        }
        catch (Exception ex)
        {
            Warn("Failed to prepare embedded YARA rules: {0}", ex.Message);
            return null;
        }
    }

    // Runs a process with an argument LIST (no shell, no UseShellExecute — hostile filenames cannot inject),
    // capturing stdout/stderr, bounded by timeoutMs with Kill(entireProcessTree). Returns null on start failure
    // or timeout. Never throws.
    private static ProcessResult? RunProcess(string exe, IReadOnlyList<string> args, int timeoutMs)
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
                return null;

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            if (!process.WaitForExit(timeoutMs))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
                Warn("YARA process '{0}' timed out after {1} ms and was terminated.", exe, timeoutMs);
                return null;
            }

            process.WaitForExit();   // let the async output/error readers drain
            return new ProcessResult(process.ExitCode, stdout.ToString(), stderr.ToString());
        }
        catch (Exception ex)
        {
            Warn("Failed to run YARA process '{0}': {1}", exe, ex.Message);
            return null;
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

    private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);
    #endregion
}
