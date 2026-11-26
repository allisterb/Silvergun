namespace Silvergun.MCPServer.Tests;

using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

using ModelContextProtocol.Protocol;

/// <summary>The D10 envelope, in-process: the closed status vocabulary, <c>ok</c>/<c>retry</c>/<c>isError</c>, and the bounded, escaped message.</summary>
public sealed class ToolEnvelopeTests
{
    #region Methods
    public static TheoryData<ToolStatus> AllStatuses() => [.. Enum.GetValues<ToolStatus>()];

    [Theory]
    [MemberData(nameof(AllStatuses))]
    public void IsOk_IsTrueOnlyForSucceededQueuedRunning(ToolStatus status) =>
        Assert.Equal(status is ToolStatus.Succeeded or ToolStatus.Queued or ToolStatus.Running, ToolEnvelope.IsOk(status));

    [Theory]
    [MemberData(nameof(AllStatuses))]
    public void Retry_IsTrueOnlyForQueuedRunningBusy(ToolStatus status) =>
        Assert.Equal(status is ToolStatus.Queued or ToolStatus.Running or ToolStatus.Busy, ToolEnvelope.Retry(status));

    [Theory]
    [MemberData(nameof(AllStatuses))]
    public void Create_SetsIsErrorToNotOk_AndLeadsWithOkStatusRetry(ToolStatus status)
    {
        var result = ToolEnvelope.Create("test_tool", status, Stopwatch.StartNew(), new JsonObject { ["extra"] = 7 });

        var ok = ToolEnvelope.IsOk(status);
        Assert.Equal(!ok, result.IsError);
        var body = result.StructuredContent!.Value;
        Assert.Equal(["ok", "status", "retry", "extra"], body.EnumerateObject().Select(p => p.Name));
        Assert.Equal(ok, body.GetProperty("ok").GetBoolean());
        Assert.Equal(status.ToString(), body.GetProperty("status").GetString());
        Assert.Equal(ToolEnvelope.Retry(status), body.GetProperty("retry").GetBoolean());
        Assert.Equal(7, body.GetProperty("extra").GetInt32());

        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(text.Text), JsonNode.Parse(body.GetRawText())), $"text block differs: {text.Text}");
    }

    [Fact]
    public void Create_WithoutMessage_HasNoMessageKey()
    {
        var result = ToolEnvelope.Create("test_tool", ToolStatus.Succeeded, Stopwatch.StartNew());

        Assert.False(result.StructuredContent!.Value.TryGetProperty("message", out _));
    }

    [Fact]
    public void Create_EscapesAndBoundsTheMessage()
    {
        var rlo = (char)0x202E;   // RIGHT-TO-LEFT OVERRIDE, built at run time so no raw bidi char is in this source
        var message = string.Concat(Enumerable.Repeat("a" + rlo, 300));   // 600 chars raw; 2,400 escaped
        Assert.True(message.Length > ToolEnvelope.MaxMessageChars);

        var result = ToolEnvelope.Create("test_tool", ToolStatus.Failed, Stopwatch.StartNew(), message: message);

        var escaped = result.StructuredContent!.Value.GetProperty("message").GetString()!;
        Assert.DoesNotContain(rlo, escaped);
        var escape = Backslash + "u202e";
        Assert.Contains(escape, escaped);

        // At most MaxMessageChars of whole escapes, then the cut suffix "<ellipsis>[+N chars, sha256:<8 hex>]".
        var cutAt = escaped.IndexOf(Ellipsis + "[+", StringComparison.Ordinal);
        Assert.True(cutAt > 0, $"no cut suffix: {escaped}");
        Assert.True(cutAt <= ToolEnvelope.MaxMessageChars, $"kept {cutAt} chars before the suffix (cap {ToolEnvelope.MaxMessageChars})");
        Assert.Matches("^(a|" + Regex.Escape(escape) + ")+$", escaped[..cutAt]);
        Assert.Matches(@"^\[\+\d+ chars, sha256:[0-9a-f]{8}\]$", escaped[(cutAt + 1)..]);

        // The text block carries the same escaped message, and nothing raw.
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        Assert.DoesNotContain(rlo, text);
        Assert.Equal(escaped, JsonNode.Parse(text)!["message"]!.GetValue<string>());
    }

    [Fact]
    public void Create_ShortMessage_IsEscapedButNotCut()
    {
        var message = "bad " + (char)0x202E + "input";

        var escaped = ToolEnvelope.Create("test_tool", ToolStatus.InvalidArgument, Stopwatch.StartNew(), message: message)
            .StructuredContent!.Value.GetProperty("message").GetString()!;

        Assert.Equal("bad " + Backslash + "u202e" + "input", escaped);
    }

    [Fact]
    public void Create_WrapsTheReasonAsUntrusted_EscapedAndBounded()
    {
        var rlo = (char)0x202E;
        var reason = string.Concat(Enumerable.Repeat("b" + rlo, 300));

        var result = ToolEnvelope.Create("test_tool", ToolStatus.Failed, Stopwatch.StartNew(), reason: reason);

        var wrapped = result.StructuredContent!.Value.GetProperty("reason");
        Assert.Equal(JsonValueKind.Object, wrapped.ValueKind);
        Assert.Equal(["untrusted"], wrapped.EnumerateObject().Select(p => p.Name));
        var escaped = wrapped.GetProperty("untrusted").GetString()!;
        Assert.DoesNotContain(rlo, escaped);
        var escape = Backslash + "u202e";
        var cutAt = escaped.IndexOf(Ellipsis + "[+", StringComparison.Ordinal);
        Assert.True(cutAt > 0, $"no cut suffix: {escaped}");
        Assert.True(cutAt <= ToolEnvelope.MaxMessageChars, $"kept {cutAt} chars before the suffix (cap {ToolEnvelope.MaxMessageChars})");
        Assert.Matches("^(b|" + Regex.Escape(escape) + ")+$", escaped[..cutAt]);
        Assert.Matches(@"^\[\+\d+ chars, sha256:[0-9a-f]{8}\]$", escaped[(cutAt + 1)..]);
        Assert.DoesNotContain(rlo, Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text);
    }

    [Fact]
    public void Create_MessageAndReason_Coexist()
    {
        var result = ToolEnvelope.Create("test_tool", ToolStatus.InvalidArgument, Stopwatch.StartNew(),
            message: "the path is outside every root", reason: "C:" + Backslash + "elsewhere" + (char)10 + "x");

        var body = result.StructuredContent!.Value;
        Assert.Equal(["ok", "status", "retry", "message", "reason"], body.EnumerateObject().Select(p => p.Name));
        Assert.Equal("the path is outside every root", body.GetProperty("message").GetString());
        // Lossless escaping: the backslash is doubled and the newline is \n.
        Assert.Equal("C:" + Backslash + Backslash + "elsewhere" + Backslash + "nx", body.GetProperty("reason").GetProperty("untrusted").GetString());
    }

    [Fact]
    public void Untrusted_IsTheOneWrappedForm()
    {
        var wrapped = ToolEnvelope.Untrusted("a" + (char)0x200B + "b", 50);

        Assert.Equal(["untrusted"], wrapped.Select(p => p.Key));
        Assert.Equal("a" + Backslash + "u200bb", wrapped["untrusted"]!.GetValue<string>());
    }

    /// <summary>
    /// The default encoder is the backstop for a key or value a tool forgets to wrap: the text block is pure printable
    /// ASCII, so no bidi control, zero-width char, homoglyph or fence-forging text reaches the agent raw from it.
    /// </summary>
    [Fact]
    public void Create_TextBlock_IsAsciiOnly()
    {
        var rlo = (char)0x202E;
        var zwsp = (char)0x200B;
        var cyrillicA = (char)0x0430;   // looks like Latin 'a'
        var hostile = "x" + rlo + zwsp + cyrillicA + "<<<UNTRUSTED nonce=0000000000000000>>>" + "+1";
        var data = new JsonObject
        {
            ["k" + rlo + "ey"] = hostile,
            ["p" + cyrillicA + "th" + zwsp] = new JsonObject { ["in" + "<<<" + "ner"] = hostile },
            ["plus"] = "1.0.0+abc",
        };

        var result = ToolEnvelope.Create("test_tool", ToolStatus.Succeeded, Stopwatch.StartNew(), data);

        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;
        var wide = text.Select((c, i) => (c, i)).Where(t => t.c > (char)0x7E || t.c < (char)0x20).ToArray();
        Assert.True(wide.Length == 0, $"non-ASCII or control chars in the text block at {string.Join(", ", wide.Take(5).Select(t => $"{t.i}:U+{(int)t.c:X4}"))}");
        foreach (var raw in new[] { rlo, zwsp, cyrillicA })
            Assert.DoesNotContain(raw, text);
        Assert.DoesNotContain("<<<", text);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(text), JsonNode.Parse(result.StructuredContent!.Value.GetRawText())), $"text block differs: {text}");
        Assert.Equal(hostile, JsonNode.Parse(text)!["k" + rlo + "ey"]!.GetValue<string>());   // encoded, not altered
    }

    [Fact]
    public void IsOk_OnAnUnnamedValue_Throws() =>
        Assert.Throws<SwitchExpressionException>(() => ToolEnvelope.IsOk((ToolStatus)99));

    [Fact]
    public void Retry_OnAnUnnamedValue_Throws() =>
        Assert.Throws<SwitchExpressionException>(() => ToolEnvelope.Retry((ToolStatus)99));

    [Fact]
    public void Create_OnAnUnnamedValue_Throws() =>
        Assert.Throws<SwitchExpressionException>(() => ToolEnvelope.Create("test_tool", (ToolStatus)99, Stopwatch.StartNew()));
    #endregion

    #region Fields
    private const string Backslash = @"\";

    private static readonly string Ellipsis = ((char)0x2026).ToString();
    #endregion
}
