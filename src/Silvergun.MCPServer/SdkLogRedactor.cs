namespace Silvergun.MCPServer;

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Logging;

using ModelContextProtocol.Protocol;

/// <summary>
/// Wraps the log provider so the host's log events carry shape, not content (task D9). The SDK puts agent-chosen text
/// (method, tool and resource names, client info, exception messages that repeat them) into its Information-and-above
/// messages, raw, so one call could forge a log line. For <c>ModelContextProtocol*</c> categories the message is rebuilt
/// from its template: numbers, booleans, enums, durations and the protocol's own names (<see cref="KnownNames"/>) stay;
/// every other value becomes <c>len:N sha256:&lt;8&gt;</c>, or, under <c>--debug</c>, its
/// <see cref="UntrustedText.EscapeBounded(string, int)"/> form. In every category an exception keeps only its type name
/// and its message rendered the same way; its stack trace is dropped, as are scopes.
/// </summary>
public sealed class SdkLogRedactor(ILoggerProvider inner, bool debug) : ILoggerProvider
{
    #region Properties
    /// <summary>
    /// Values logged verbatim: the protocol's request and notification method names, our tool names and the guide's URI.
    /// An agent can send these, but they are fixed tokens that cannot carry anything else.
    /// </summary>
    public static FrozenSet<string> KnownNames { get; } =
        new[] { typeof(RequestMethods), typeof(NotificationMethods), typeof(ToolNames) }
            .SelectMany(t => t.GetFields(BindingFlags.Public | BindingFlags.Static))
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .Append(GuideResource.Uri)
            .ToFrozenSet(StringComparer.Ordinal);
    #endregion

    #region Methods
    public ILogger CreateLogger(string categoryName) =>
        new RedactingLogger(inner.CreateLogger(categoryName), debug, categoryName.StartsWith(SdkCategoryPrefix, StringComparison.OrdinalIgnoreCase));

    /// <summary>Does nothing: the inner provider belongs to <see cref="Runtime"/>.</summary>
    public void Dispose() { }

    /// <summary>The message <paramref name="state"/> logs, with every hole filled by <see cref="Render"/>.</summary>
    public static string Redact<TState>(TState state, bool debug) =>
        state is IReadOnlyList<KeyValuePair<string, object?>> values
            && values.FirstOrDefault(kv => kv.Key == OriginalFormatKey).Value is string format
            ? hole.Replace(format, m => values.FirstOrDefault(kv => kv.Key == m.Groups[1].Value) is { Key: not null } kv ? Render(kv.Value, debug) : "?")
            : "(an SDK log event with no template)";

    /// <summary>A value as the redacted log shows it.</summary>
    public static string Render(object? value, bool debug) => value switch
    {
        null => "null",
        bool or byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal or Enum or TimeSpan
            => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "?",
        _ => Convert.ToString(value, CultureInfo.InvariantCulture) is { } s
            ? KnownNames.Contains(s) ? s
            : debug ? UntrustedText.EscapeBounded(s, MaxDebugValueChars) : $"len:{s.Length} sha256:{Digest(s)}"
            : "?"
    };

    /// <summary>An exception as every redacted log line ends: <c> [TypeName: &lt;rendered message&gt;]</c>, no stack trace.</summary>
    public static string RenderException(Exception exception, bool debug) => $" [{exception.GetType().Name}: {Render(exception.Message, debug)}]";

    // The 8-hex sha256 UntrustedText puts in its cut suffix, so a digest here matches one in an escaped, cut value.
    private static string Digest(string s) => UntrustedText.HashOnly(s) is var suffix ? suffix[(suffix.LastIndexOf(':') + 1)..^1] : "";
    #endregion

    #region Fields
    private const string SdkCategoryPrefix = "ModelContextProtocol";

    private const string OriginalFormatKey = "{OriginalFormat}";

    private const int MaxDebugValueChars = 256;

    // A template hole, {Name} or {Name:format} (with an optional @ or $), and its name.
    private static readonly Regex hole = new(@"\{[@$]?([A-Za-z0-9_]+)(?:[,:][^{}]*)?\}", RegexOptions.CultureInvariant);
    #endregion

    #region Types
    // SDK categories: the message is rebuilt from its template. Others (the host's own, whose templates are fixed text):
    // the message is kept, but the exception is reduced all the same, since it may carry what an SDK exception carried.
    private sealed class RedactingLogger(ILogger inner, bool debug, bool sdk) : ILogger
    {
        // Scope state may hold agent text: it is not forwarded.
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
                return;
            var message = (sdk ? Redact(state, debug) : formatter(state, null))
                + (exception is null ? "" : RenderException(exception, debug));
            inner.Log(logLevel, eventId, message, null, (m, _) => m);
        }
    }
    #endregion
}
