namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using System.Buffers;
using System.Globalization;
using System.Text.Unicode;

/// <summary>
/// The constants of worker protocol v1 (ADR 0033 FINAL FORM; the binding contract is the "worker protocol v1" section
/// of <c>docs/agent/tasks/yarax-worker.md</c>) and the one helper every sender uses to make text safe to put on the
/// wire or in a log line.
/// </summary>
public static class WorkerProtocol
{
    #region Properties
    /// <summary>
    /// The worker's fixed launch arguments after the executable, which is whatever
    /// <c>YaraXWorkerScanner.ResolveWorkerExecutable</c> finds (amendment (o): this process's own executable only when it is
    /// the Silvergun CLI apphost, otherwise the apphost in the application directory). A launch also carries
    /// <c>--timeout &lt;seconds&gt;</c> (amendment G3): use <see cref="YaraWorkerLaunchArguments"/>.
    /// </summary>
    public static IReadOnlyList<string> YaraWorkerArguments { get; } = ["__worker", "yara", "--protocol", "1"];
    #endregion

    #region Methods
    /// <summary>
    /// The complete launch arguments (amendment G3): <see cref="YaraWorkerArguments"/>, then
    /// <c>--timeout &lt;<paramref name="engineTimeoutSeconds"/>&gt;</c>. The engine timeout is never 0 ("no timeout"):
    /// a value outside [<see cref="MinTimeoutSeconds"/>, <see cref="MaxTimeoutSeconds"/>] is refused, because the worker
    /// would answer it with <c>fatal</c> (amendment W-D).
    /// </summary>
    public static IReadOnlyList<string> YaraWorkerLaunchArguments(int engineTimeoutSeconds)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(engineTimeoutSeconds, MinTimeoutSeconds);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(engineTimeoutSeconds, MaxTimeoutSeconds);
        return [.. YaraWorkerArguments, TimeoutOption, engineTimeoutSeconds.ToString(CultureInfo.InvariantCulture)];
    }

    /// <summary>
    /// <paramref name="text"/> made safe to log or send: escaped through <see cref="YaraPathSafety.Escape"/>, then cut
    /// to at most <paramref name="maxChars"/> chars (marked with a trailing <c>...</c>), never splitting a surrogate pair.
    /// </summary>
    internal static string Safe(string? text, int maxChars = MaxReasonChars)
    {
        var escaped = YaraPathSafety.Escape(text);
        if (escaped.Length <= maxChars)
            return escaped;

        var cut = Math.Max(0, maxChars - Ellipsis.Length);
        if (cut > 0 && char.IsHighSurrogate(escaped[cut - 1]))
            cut--;
        return escaped[..cut] + Ellipsis;
    }

    /// <summary>
    /// <c>true</c> when <paramref name="text"/> is well-formed UTF-16: every surrogate is half of a correctly ordered
    /// pair. Checked by transcoding with <see cref="Utf8.FromUtf16"/> and <c>replaceInvalidSequences: false</c>, so a lone
    /// surrogate is reported, never replaced with U+FFFD (review W1). Ill-formed text cannot go on the wire as itself.
    /// </summary>
    internal static bool IsWellFormedUtf16(ReadOnlySpan<char> text)
    {
        Span<byte> scratch = stackalloc byte[ScratchBytes];
        while (!text.IsEmpty)
        {
            var status = Utf8.FromUtf16(text, scratch, out var read, out _, replaceInvalidSequences: false, isFinalBlock: true);
            if (status == OperationStatus.Done)
                return true;
            if (status != OperationStatus.DestinationTooSmall || read == 0)
                return false;
            text = text[read..];
        }
        return true;
    }
    #endregion

    #region Fields
    /// <summary>The protocol version this build speaks.</summary>
    public const int Version = 1;

    /// <summary>The launch option carrying the per-file engine timeout in whole seconds (amendment G3).</summary>
    public const string TimeoutOption = "--timeout";

    /// <summary>
    /// The engine timeout when none is configured (amendment G3: never "no timeout"). The ONE default (amendment (i)): the
    /// worker's absent <c>--timeout</c> and the parent's null <see cref="YaraOptions.Timeout"/> both mean this.
    /// </summary>
    public const int DefaultTimeoutSeconds = 30;

    /// <summary>
    /// The smallest engine timeout in whole seconds (amendment W-D). YARA-X ticks at 1 Hz, so a budget of T seconds can
    /// end anywhere in (T−1, T]: at T = 1 that is as little as ~0.1 s (measured), which is no budget at all.
    /// </summary>
    public const int MinTimeoutSeconds = 2;

    /// <summary>The largest engine timeout in whole seconds (amendments (k) and W-D).</summary>
    public const int MaxTimeoutSeconds = 3600;

    /// <summary>Exit code after <c>done</c>.</summary>
    public const int ExitDone = 0;

    /// <summary>Exit code after <c>fatal</c> (and for any request-stream violation).</summary>
    public const int ExitFatal = 3;

    /// <summary>Max bytes in one line, excluding its <c>\n</c> (1 MiB).</summary>
    public const int MaxLineBytes = 1024 * 1024;

    /// <summary>
    /// Max bytes in one <c>result</c> line the worker sends, excluding its <c>\n</c> (64 KiB; amendment "G4 vs (h)"). A
    /// result that would be longer is sent as that file's <c>error</c>, so an in-contract worker always fits the parent's
    /// G4 output budget: this much plus one byte (the line's <c>\n</c>) per request, plus a fixed 1 MiB for the
    /// <c>ready</c> and <c>done</c> lines.
    /// </summary>
    public const int MaxResultLineBytes = 64 * 1024;

    /// <summary>Max hits in one <see cref="WorkerResult"/>.</summary>
    public const int MaxHitsPerFile = 1024;

    /// <summary>Max chars in a rule name, a namespace, a tag, and every string field of <see cref="WorkerReady"/>.</summary>
    public const int MaxNameChars = 256;

    /// <summary>Max tags on one <see cref="WorkerHit"/>.</summary>
    public const int MaxTagsPerHit = 64;

    /// <summary>Max chars in a <c>reason</c> (result or fatal).</summary>
    public const int MaxReasonChars = 512;

    /// <summary>The <see cref="WorkerReady.Canary"/> of a real engine whose canary rule hit.</summary>
    public const string CanaryPassed = "passed";

    /// <summary>The <see cref="WorkerReady.Canary"/> of an engine that ran no canary (the T1 stub).</summary>
    public const string CanarySkipped = "skipped";

    private const string Ellipsis = "...";

    // Any scalar is at most 4 UTF-8 bytes, so a chunk this size always makes progress in IsWellFormedUtf16.
    private const int ScratchBytes = 1024;
    #endregion
}
