namespace Silvergun.MCPServer;

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

using ModelContextProtocol.Protocol;

/// <summary>The one closed status vocabulary every tool answers in (task D10).</summary>
public enum ToolStatus
{
    Succeeded,
    Queued,
    Running,
    Busy,
    NotFound,
    InvalidArgument,
    OutsideRoots,
    NotPermitted,
    NotAnalysed,
    Failed,
    Cancelled
}

/// <summary>
/// Builds every tool result (task D10): <c>ok</c>, <c>status</c> and <c>retry</c> first, then the tool's own fields, as
/// <c>structuredContent</c> and the same JSON in one text block. Errors are values: a non-ok status is an
/// <c>isError</c> result, never a throw. Logs the call's shape (name, status, elapsed), never its content.
/// </summary>
public static class ToolEnvelope
{
    #region Methods
    /// <summary>
    /// The result of <paramref name="tool"/>. <paramref name="data"/>'s fields follow the envelope's and must not reuse
    /// its names. <paramref name="message"/> is Silvergun-authored text; <paramref name="reason"/> is text that is or quotes
    /// package or agent input, and is always wrapped by <see cref="Untrusted"/> (task D6.2). Both are escaped and cut to
    /// <see cref="MaxMessageChars"/>. <paramref name="bulk"/>, when set, is a second text block: package text already inside
    /// its <see cref="UntrustedFence"/> (task D6.3).
    /// </summary>
    public static CallToolResult Create(string tool, ToolStatus status, Stopwatch elapsed, JsonObject? data = null, string? message = null, string? reason = null,
        string? bulk = null)
    {
        var body = new JsonObject
        {
            ["ok"] = IsOk(status),
            ["status"] = status.ToString(),
            ["retry"] = Retry(status)
        };
        if (message is not null)
            body["message"] = UntrustedText.EscapeBounded(message, MaxMessageChars);
        if (reason is not null)
            body["reason"] = Untrusted(reason, MaxMessageChars);
        foreach (var (key, value) in data ?? [])
            body.Add(key, value?.DeepClone());

        Runtime.Info("mcp: {0} {1} in {2} ms.", tool, status.ToString(), elapsed.ElapsedMilliseconds);
        var element = JsonSerializer.SerializeToElement(body, jsonOptions);
        return new CallToolResult
        {
            IsError = !IsOk(status),
            StructuredContent = element,
            Content = bulk is null
                ? [new TextContentBlock { Text = element.GetRawText() }]
                : [new TextContentBlock { Text = element.GetRawText() }, new TextContentBlock { Text = bulk }]
        };
    }

    /// <summary>
    /// <c>{"untrusted": "&lt;escaped&gt;"}</c>: the one form package- or agent-derived text takes in structured output (task
    /// D6.2). Escaped losslessly, then the invisible code points <see cref="UntrustedText"/> lets through too (S2 review W5,
    /// closed for MCP output at S3), and cut at an escape boundary.
    /// </summary>
    public static JsonObject Untrusted(string text, int maxChars) => new() { ["untrusted"] = Escaped(text, maxChars) };

    /// <summary>
    /// The text of <see cref="Untrusted"/>: <see cref="UntrustedText.EscapeBounded(string, int)"/>'s form, with the invisible
    /// code points escaped too, within <paramref name="maxChars"/> and, when cut, its suffix for the whole input (ADR 0037 a5).
    /// </summary>
    public static string Escaped(string text, int maxChars)
    {
        var escaped = UntrustedText.EscapeBounded(text, maxChars);
        // The common case: nothing EscapeBounded kept is invisible, so its own cut and suffix stand (S3 review W1).
        if (ReferenceEquals(Jobs.ExtractedFile.Displayable(escaped), escaped))
            return escaped;

        // Otherwise piece by piece, as EscapeBounded goes, each piece made displayable before it is counted.
        var sb = new System.Text.StringBuilder(Math.Min(text.Length, maxChars) + 8);
        var i = 0;
        while (i < text.Length)
        {
            // EscapeBounded's own pieces, without its per-call hash (S3 review round 2, W1): the one hash is the suffix's.
            var c = text[i];
            var n = char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]) ? 2 : 1;
            var piece = c == '\\' ? @"\\"
                : n == 1 && char.IsSurrogate(c) ? "\\u" + ((int)c).ToString("X4")
                : Jobs.ExtractedFile.Displayable(UntrustedText.Escape(text.Substring(i, n)));
            if (sb.Length + piece.Length > maxChars)
                break;
            sb.Append(piece);
            i += n;
        }
        return i < text.Length ? sb.Append(UntrustedText.CutSuffix(text, text.Length - i)).ToString() : sb.ToString();
    }

    // No default arm (task D10): a new member must be mapped here or the build warns (CS8509), and an unnamed value
    // throws SwitchExpressionException at the boundary rather than picking an answer.
#pragma warning disable CS8524
    /// <summary>
    /// <c>ok</c>: the call did what was asked (a job handle counts). Always <c>!isError</c>; <c>status</c> says why not.
    /// </summary>
    public static bool IsOk(ToolStatus status) => status switch
    {
        ToolStatus.Succeeded or ToolStatus.Queued or ToolStatus.Running => true,
        ToolStatus.Busy or ToolStatus.NotFound or ToolStatus.InvalidArgument or ToolStatus.OutsideRoots or ToolStatus.NotPermitted
            or ToolStatus.NotAnalysed or ToolStatus.Failed or ToolStatus.Cancelled => false
    };

    /// <summary>Whether the same call may succeed later unchanged: only for transient states.</summary>
    public static bool Retry(ToolStatus status) => status switch
    {
        ToolStatus.Queued or ToolStatus.Running or ToolStatus.Busy => true,
        ToolStatus.Succeeded or ToolStatus.NotFound or ToolStatus.InvalidArgument or ToolStatus.OutsideRoots or ToolStatus.NotPermitted
            or ToolStatus.NotAnalysed or ToolStatus.Failed or ToolStatus.Cancelled => false
    };
#pragma warning restore CS8524
    #endregion

    #region Fields
    /// <summary>The cap on a failure message, after escaping (task D10).</summary>
    public const int MaxMessageChars = 400;

    // The default encoder, deliberately: it writes every non-ASCII char (bidi, zero-width, homoglyphs) and '<', '>', '+'
    // as \uXXXX, so a key or value a tool forgot to wrap still cannot reach the agent raw, and a forged fence cannot
    // appear verbatim in the JSON (S0 review round 2).
    private static readonly JsonSerializerOptions jsonOptions = new() { WriteIndented = false };
    #endregion
}

/// <summary>
/// Bulk package text between fences (task D6.3), with a nonce from <see cref="RandomNumberGenerator"/>, one per response.
/// Inside, every fence marker (in any case) is escaped, and the nonce is drawn again until it occurs nowhere in the content
/// (S2 review W1), so only the real fences carry either.
/// </summary>
public sealed class UntrustedFence
{
    #region Constructors
    /// <summary>Fences <paramref name="text"/>, which is already escaped for display.</summary>
    public UntrustedFence(string text)
    {
        Content = Neutralize(text);
        do
            Nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
        while (Content.Contains(Nonce, StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Properties
    public string Nonce { get; }

    /// <summary>The text with every fence marker escaped: at most a quarter longer than it was.</summary>
    public string Content { get; }

    public string Open => $"<<<UNTRUSTED nonce={Nonce}>>>";

    public string Close => $"<<<END UNTRUSTED nonce={Nonce}>>>";

    /// <summary>The text block: the opening fence, the content and the closing fence, one per line.</summary>
    public string Block => $"{Open}\n{Content}\n{Close}";
    #endregion

    #region Methods
    /// <summary><paramref name="text"/> with the fence markers escaped, in any case.</summary>
    public static string Neutralize(string text) => text
        .Replace("<<<UNTRUSTED", @"<<\x3cUNTRUSTED", StringComparison.OrdinalIgnoreCase)
        .Replace("<<<END UNTRUSTED", @"<<\x3cEND UNTRUSTED", StringComparison.OrdinalIgnoreCase);
    #endregion
}
