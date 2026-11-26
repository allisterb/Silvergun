namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Logging;

/// <summary>
/// D9 "log shape, not content", in-process: <see cref="SdkLogRedactor"/> rebuilds every <c>ModelContextProtocol*</c> log
/// event from its template, keeping numbers, booleans, enums and durations, and reducing every other value to a length and
/// digest (or, under <c>--debug</c>, an escaped and bounded copy). Other categories pass through untouched.
/// </summary>
public sealed class SdkLogRedactorTests
{
    #region Methods
    public static TheoryData<object?, string> KeptValues() => new()
    {
        { null, "null" },
        { true, "True" },
        { (byte)7, "7" },
        { (short)-3, "-3" },
        { 42, "42" },
        { -7L, "-7" },
        { 42UL, "42" },
        { 3.5, "3.5" },
        { 2.25f, "2.25" },
        { 1.25m, "1.25" },
        { LogLevel.Warning, "Warning" },
        { TimeSpan.FromSeconds(90), "00:01:30" },
    };

    [Theory]
    [MemberData(nameof(KeptValues))]
    public void Render_KeepsNumbersBoolsEnumsAndDurations_InBothModes(object? value, string expected)
    {
        Assert.Equal(expected, SdkLogRedactor.Render(value, debug: false));
        Assert.Equal(expected, SdkLogRedactor.Render(value, debug: true));
    }

    [Fact]
    public void Render_AString_IsLengthAndDigest_WithoutDebug()
    {
        var value = "tools/call" + (char)10 + "[ERR] FORGED" + (char)0x202E;

        var rendered = SdkLogRedactor.Render(value, debug: false);

        var m = Regex.Match(rendered, "^len:(\\d+) sha256:([0-9a-f]{8})$");
        Assert.True(m.Success, rendered);
        Assert.Equal(value.Length, int.Parse(m.Groups[1].Value));
        Assert.EndsWith("sha256:" + m.Groups[2].Value + "]", UntrustedText.HashOnly(value));   // the digest UntrustedText's cut suffix carries
        Assert.DoesNotContain("FORGED", rendered);
    }

    [Fact]
    public void Render_DistinctStrings_HaveDistinctDigests() =>
        Assert.NotEqual(SdkLogRedactor.Render("alpha", false), SdkLogRedactor.Render("alphb", false));

    [Fact]
    public void Render_AShortString_IsEscaped_UnderDebug()
    {
        var value = "c" + (char)10 + "[ERR] FORGED" + (char)0x202E;

        var rendered = SdkLogRedactor.Render(value, debug: true);

        Assert.Equal("c" + Backslash + "n[ERR] FORGED" + Backslash + "u202e", rendered);
    }

    [Fact]
    public void Render_ALongString_IsBoundedTo256PlusTheCutSuffix_UnderDebug()
    {
        var rlo = (char)0x202E;
        var value = string.Concat(Enumerable.Repeat("x" + rlo, 500));

        var rendered = SdkLogRedactor.Render(value, debug: true);

        Assert.DoesNotContain(rlo, rendered);
        var cutAt = rendered.IndexOf(Ellipsis + "[+", StringComparison.Ordinal);
        Assert.True(cutAt > 0 && cutAt <= 256, $"kept {cutAt} chars before the suffix: {rendered}");
        Assert.Matches("^(x|" + Regex.Escape(Backslash + "u202e") + ")+$", rendered[..cutAt]);
        Assert.Matches(@"^\[\+\d+ chars, sha256:[0-9a-f]{8}\]$", rendered[(cutAt + 1)..]);
    }

    [Fact]
    public void Render_ANonStringObject_IsRedactedLikeAString()
    {
        var value = new Uri("silvergun://not-the-guide");   // not a known name, so hashed

        Assert.Equal(SdkLogRedactor.Render(value.ToString(), false), SdkLogRedactor.Render(value, false));
    }

    [Fact]
    public void Redact_FillsEveryHole_WithRenderedValues()
    {
        var method = "bogus/method" + (char)10 + "[ERR] FORGED";
        var state = new List<KeyValuePair<string, object?>>
        {
            new("Method", method),
            new("ElapsedMs", 21.3872),
            new("IsError", false),
            new("{OriginalFormat}", "method '{Method}' completed in {ElapsedMs:0.00}ms (error {IsError}, missing {Missing}, {@Method})."),
        };

        var plain = SdkLogRedactor.Redact(state, debug: false);
        var debug = SdkLogRedactor.Redact(state, debug: true);

        var p = SdkLogRedactor.Render(method, false);
        Assert.Equal($"method '{p}' completed in 21.3872ms (error False, missing ?, {p}).", plain);
        var d = SdkLogRedactor.Render(method, true);
        Assert.Equal($"method '{d}' completed in 21.3872ms (error False, missing ?, {d}).", debug);
        Assert.DoesNotContain((char)10, plain + debug);
    }

    [Fact]
    public void Redact_AStateWithNoTemplate_IsAFixedPlaceholder()
    {
        var a = SdkLogRedactor.Redact("raw [ERR] FORGED text", debug: true);
        var b = SdkLogRedactor.Redact(new List<KeyValuePair<string, object?>> { new("Name", "FORGED") }, debug: true);

        Assert.Equal(a, b);
        Assert.DoesNotContain("FORGED", a);
        Assert.False(string.IsNullOrWhiteSpace(a));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CreateLogger_ANonSdkCategory_KeepsItsMessage_ButReducesTheException(bool debug)
    {
        var inner = new CapturingProvider();
        using var redactor = new SdkLogRedactor(inner, debug);
        var exception = Thrown(new InvalidOperationException("boom" + (char)10 + "[ERR] FORGED" + (char)0x202E));

        var logger = redactor.CreateLogger("Microsoft.Hosting.Lifetime");
        using (logger.BeginScope("scope {X}", "FORGED-SCOPE"))
            logger.LogError(exception, "host step {Step} failed", 3);

        var entry = Assert.Single(inner.Entries);
        Assert.Equal("Microsoft.Hosting.Lifetime", entry.Category);
        Assert.Equal("host step 3 failed" + SdkLogRedactor.RenderException(exception, debug), entry.Message);
        Assert.StartsWith("host step 3 failed [InvalidOperationException: ", entry.Message);
        Assert.Null(entry.Exception);
        Assert.Equal(0, inner.Scopes);
        Assert.DoesNotContain((char)10, entry.Message);
        Assert.DoesNotContain((char)0x202E, entry.Message);
        Assert.DoesNotContain(exception.StackTrace!, entry.Message);
        Assert.DoesNotContain(nameof(Thrown), entry.Message);   // a stack frame's method name
        if (debug)
            Assert.Contains("boom" + Backslash + "n[ERR] FORGED" + Backslash + "u202e", entry.Message);
        else
            Assert.DoesNotContain("FORGED", entry.Message);
    }

    [Fact]
    public void CreateLogger_ANonSdkCategory_PassesAPlainMessageThroughUnchanged()
    {
        var inner = new CapturingProvider();
        using var redactor = new SdkLogRedactor(inner, debug: false);

        redactor.CreateLogger("Silvergun.MCPServer").LogInformation("mcp: {Tool} {Status} in {Ms} ms.", "get_server_info", "Succeeded", 2);

        Assert.Equal("mcp: get_server_info Succeeded in 2 ms.", Assert.Single(inner.Entries).Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RenderException_IsTypeAndRenderedMessage_NoStackTrace(bool debug)
    {
        var exception = Thrown(new ArgumentException("bad" + (char)10 + "x"));

        var rendered = SdkLogRedactor.RenderException(exception, debug);

        Assert.Equal($" [ArgumentException: {SdkLogRedactor.Render(exception.Message, debug)}]", rendered);
        Assert.DoesNotContain(nameof(Thrown), rendered);
        Assert.DoesNotContain((char)10, rendered);
    }

    [Theory]
    [InlineData("tools/call")]
    [InlineData("initialize")]
    [InlineData("tools/list")]
    [InlineData("resources/read")]
    [InlineData("notifications/initialized")]
    [InlineData(ToolNames.GetServerInfo)]
    [InlineData(GuideResource.Uri)]
    public void Render_AKnownName_IsVerbatim_InBothModes(string name)
    {
        Assert.True(SdkLogRedactor.KnownNames.Contains(name), $"'{name}' is not a known name");
        Assert.Equal(name, SdkLogRedactor.Render(name, debug: false));
        Assert.Equal(name, SdkLogRedactor.Render(name, debug: true));
    }

    [Theory]
    [InlineData("tools/call ")]
    [InlineData("Tools/Call")]
    [InlineData(" initialize")]
    [InlineData("get_server_info2")]
    [InlineData("silvergun://guide/")]
    public void Render_ANearMissOfAKnownName_IsHashed(string name)
    {
        Assert.False(SdkLogRedactor.KnownNames.Contains(name), $"'{name}' is a known name");
        Assert.Matches("^len:\\d+ sha256:[0-9a-f]{8}$", SdkLogRedactor.Render(name, debug: false));
    }

    [Fact]
    public void Render_AKnownNameWithAppendedText_IsHashed() =>
        Assert.StartsWith("len:", SdkLogRedactor.Render("tools/call" + (char)10 + "[ERR] FORGED", debug: false));

    [Theory]
    [InlineData("modelcontextprotocol.x")]
    [InlineData("MODELCONTEXTPROTOCOL.Server")]
    [InlineData("ModelContextProtocol")]
    public void CreateLogger_AnSdkCategoryInAnyCase_IsRedacted(string category)
    {
        var inner = new CapturingProvider();
        using var redactor = new SdkLogRedactor(inner, debug: false);
        var client = "c" + (char)10 + "[ERR] FORGED";

        redactor.CreateLogger(category).LogInformation("Client ({Client}) method '{Method}'.", client, "tools/call");

        Assert.Equal($"Client ({SdkLogRedactor.Render(client, false)}) method 'tools/call'.", Assert.Single(inner.Entries).Message);
    }

    [Fact]
    public void CreateLogger_AnSdkCategory_RedactsMessageAndException_AndDropsScopes()
    {
        var inner = new CapturingProvider();
        using var redactor = new SdkLogRedactor(inner, debug: false);
        var client = "c" + (char)10 + "[ERR] FORGED-CLIENT";

        var logger = redactor.CreateLogger("ModelContextProtocol.Server.McpServer");
        using (logger.BeginScope("scope {Client}", client))
            logger.LogWarning(new InvalidOperationException("no tool " + client), "Client ({Client}) failed after {Ms} ms.", client, 12);

        var entry = Assert.Single(inner.Entries);
        Assert.Equal("ModelContextProtocol.Server.McpServer", entry.Category);
        Assert.Equal(LogLevel.Warning, entry.Level);
        var c = SdkLogRedactor.Render(client, false);
        Assert.Equal($"Client ({c}) failed after 12 ms. [InvalidOperationException: {SdkLogRedactor.Render("no tool " + client, false)}]", entry.Message);
        Assert.Null(entry.Exception);   // no stack trace, no raw exception message
        Assert.Equal(0, inner.Scopes);
        Assert.DoesNotContain("FORGED", entry.Message);
    }

    [Fact]
    public void CreateLogger_AnSdkCategory_HonoursTheInnerLevel()
    {
        var inner = new CapturingProvider { MinLevel = LogLevel.Information };
        using var redactor = new SdkLogRedactor(inner, debug: true);

        var logger = redactor.CreateLogger("ModelContextProtocol");
        logger.LogTrace("message body {Body}", "{\"jsonrpc\":\"2.0\"}");

        Assert.False(logger.IsEnabled(LogLevel.Trace));
        Assert.True(logger.IsEnabled(LogLevel.Information));
        Assert.Empty(inner.Entries);
    }
    #endregion

    #region Methods: helpers
    // An exception with a real stack trace (one frame: this method).
    private static Exception Thrown(Exception exception)
    {
        try
        {
            throw exception;
        }
        catch (Exception caught)
        {
            return caught;
        }
    }
    #endregion

    #region Nested types
    private sealed record Entry(string Category, LogLevel Level, string Message, Exception? Exception);

    // Records what reaches it, formatted with the caller's own formatter, as a real sink would.
    private sealed class CapturingProvider : ILoggerProvider
    {
        public LogLevel MinLevel { get; init; } = LogLevel.Trace;

        public List<Entry> Entries { get; } = [];

        public Dictionary<string, ILogger> Loggers { get; } = [];

        public int Scopes { get; set; }

        public ILogger CreateLogger(string categoryName) => Loggers[categoryName] = new CapturingLogger(this, categoryName);

        public void Dispose() { }
    }

    private sealed class CapturingLogger(CapturingProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            owner.Scopes++;
            return null;
        }

        public bool IsEnabled(LogLevel logLevel) => logLevel >= owner.MinLevel;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
                owner.Entries.Add(new Entry(category, logLevel, formatter(state, exception), exception));
        }
    }
    #endregion

    #region Fields
    private const string Backslash = @"\";

    private static readonly string Ellipsis = ((char)0x2026).ToString();
    #endregion
}
