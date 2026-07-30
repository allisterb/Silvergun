namespace Silvergun.CLI.Tests;

using System;
using System.Linq;
using System.Text.Json;

using Silvergun.CLI;
using Silvergun.CLI.Reports;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// Unit tests for <see cref="Program.WithCompleteness"/> — the TEXTUAL SPLICE that adds the ADR 0024
/// <c>Completeness</c> block to a report's <c>--json</c> output.
/// <para>
/// Two properties are asserted here, and they are the reason the splice exists rather than a re-serialization:
/// </para>
/// <list type="number">
///   <item><description><b>Every degenerate payload is either returned UNCHANGED or produces JSON that parses.</b>
///     A corrupt report is worse than a missing completeness block, so there is no third outcome. The splice reads
///     the payload's own line ending and indentation off its last line, which is exactly the kind of string
///     arithmetic that breaks on empty / compact / non-object / LF-only input — so each of those is a case below
///     instead of a claim in a comment.</description></item>
///   <item><description><b>Pre-existing bytes come through untouched — including <c>&lt;</c>, <c>&gt;</c>,
///     <c>&amp;</c> and <c>'</c> in existing string values.</b> This is the trap that rules out both obvious
///     alternatives: re-serializing through <c>JsonNode</c> rewrites <c>AnalyzedAt</c>'s <c>+00:00</c> as
///     <c>+</c>, and switching to <c>UnsafeRelaxedJsonEscaping</c> to fix that would stop escaping these four
///     characters, which legitimately occur in shipped fields (generic type names in <c>CalledApi</c>) — trading one
///     silent corruption for another. The golden tests in <see cref="CompletenessCliTests"/> only cover this
///     incidentally, via whatever the corpus assembly happens to contain; it is pinned explicitly here.</description></item>
/// </list>
/// </summary>
public sealed class CompletenessJsonSpliceTests
{
    #region Methods — payloads that cannot be spliced into (returned unchanged)
    // Anything without a top-level object carrying at least one property is returned VERBATIM: there is either no
    // place to append a property or no observed formatting to imitate. Emitting a repaired-looking document, or
    // throwing on the way out of a completed analysis, would both be worse than omitting the block.
    [Theory]
    [InlineData("")]                     // nothing at all
    [InlineData("   ")]                  // whitespace only
    [InlineData("\r\n")]                 // a line ending only
    [InlineData("[1,2]")]                // a top-level array, not an object
    [InlineData("\"x\"")]                // a top-level string
    [InlineData("123")]                  // a top-level number
    [InlineData("{}")]                   // an object with no property to append after
    [InlineData("{\r\n}")]               // ... the same, spread over CRLF lines
    [InlineData("{\n}")]                 // ... and over an LF line
    [InlineData("{\"a\": 1")]            // truncated: no closing brace, so the payload is already broken
    public void WithCompleteness_WhenThePayloadCannotBeSplicedInto_ReturnsItUnchanged(string json) =>
        Assert.Equal(json, Program.WithCompleteness(json, Assessment));

    // Defensive, and reachable only if a report's ToJson() ever returned null: the splice must not NRE on the way out
    // of an otherwise successful analysis.
    [Fact]
    public void WithCompleteness_WhenThePayloadIsNull_ReturnsNull() =>
        Assert.Null(Program.WithCompleteness(null!, Assessment));
    #endregion

    #region Methods — payloads that are spliced into (must stay parseable, with Completeness last)
    [Theory]
    [InlineData("{\"a\":1}")]                                            // compact, single line: no newline to observe
    [InlineData("{\r\n  \"a\": 1\r\n}")]                                 // the shipped shape (CRLF, 2-space indent)
    [InlineData("{\n  \"a\": 1\n}")]                                     // LF-only
    [InlineData("{\n\"a\": 1\n}")]                                       // unindented
    [InlineData("{\r\n    \"a\": 1\r\n}")]                               // 4-space indent
    [InlineData("{\r\n  \"a\": {\r\n    \"b\": 2\r\n  }\r\n}")]          // last line is a nested value's closing brace
    [InlineData("{\r\n  \"a\": [\r\n    1\r\n  ]\r\n}")]                 // ... or a nested array's bracket
    [InlineData("{\r\n  \"a\": 1\r\n}\r\n")]                             // trailing newline after the document
    public void WithCompleteness_WhenSpliceable_ProducesParseableJsonWithCompletenessLast(string json)
    {
        var result = Program.WithCompleteness(json, Assessment);

        using var doc = JsonDocument.Parse(result);
        var properties = doc.RootElement.EnumerateObject().Select(p => p.Name).ToArray();
        Assert.Equal("Completeness", properties[^1]);                    // appended, never inserted
        Assert.Single(properties, name => name == "Completeness");        // and exactly once
        Assert.True(doc.RootElement.TryGetProperty("a", out _), "the pre-existing property must survive the splice.");
        Assert.StartsWith(Body(json), result, StringComparison.Ordinal);  // ... byte-for-byte
    }

    // The block carries the real assessment, not a placeholder: a caveat a pipeline cannot read is a caveat nobody
    // acts on (spec criterion 5).
    [Fact]
    public void WithCompleteness_SplicedBlockCarriesTheAssessment()
    {
        var result = Program.WithCompleteness("{\r\n  \"a\": 1\r\n}", Assessment);

        using var doc = JsonDocument.Parse(result);
        var completeness = doc.RootElement.GetProperty("Completeness");

        Assert.False(completeness.GetProperty("IsComplete").GetBoolean());
        Assert.Equal(120, completeness.GetProperty("MethodsTotal").GetInt32());
        Assert.Equal(
            new[] { "3 of 120 method(s) could not be analyzed" },
            completeness.GetProperty("Caveats").EnumerateArray().Select(e => e.GetString()!));
    }

    // The payload's line ending wins, in both directions: the block is re-lined to match, so an LF-only report never
    // acquires CRs (the serializer's own indented output uses Environment.NewLine, which on this platform is CRLF).
    [Fact]
    public void WithCompleteness_WithAnLfOnlyPayload_IntroducesNoCarriageReturns()
    {
        var result = Program.WithCompleteness("{\n  \"a\": 1\n}", Assessment);

        Assert.DoesNotContain("\r", result, StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(result);                      // ... and it is still valid JSON
        Assert.Equal("Completeness", doc.RootElement.EnumerateObject().Last().Name);
    }

    [Fact]
    public void WithCompleteness_WithACrLfPayload_KeepsEveryLineEndingCrLf()
    {
        var result = Program.WithCompleteness("{\r\n  \"a\": 1\r\n}", Assessment);

        // No bare LF survived: with every CRLF removed there must be no line feed left anywhere.
        Assert.DoesNotContain("\n", result.Replace("\r\n", string.Empty), StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(result);
        Assert.Equal("Completeness", doc.RootElement.EnumerateObject().Last().Name);
    }
    #endregion

    #region Methods — the encoder trap (byte-identity of existing string values)
    // '<', '>', '&' and '\'' are escaped by JavaScriptEncoder.Default and NOT by UnsafeRelaxedJsonEscaping, so which
    // encoder the completeness block is serialized with is invisible here ONLY because the payload is never
    // re-serialized. If the splice ever became a re-serialization, this test fails on the byte comparison — which is
    // the whole point: the shipped fields that contain these characters are generic type names in CalledApi, i.e.
    // exactly the untrusted, attacker-influenced strings a reviewer reads most closely.
    [Fact]
    public void WithCompleteness_PreservesMarkupCharactersInExistingStringValues()
    {
        const string api = "System.Collections.Generic.List<T>.Add & 'x' > y";
        var json = "{\r\n  \"CalledApi\": \"" + api + "\"\r\n}";

        var result = Program.WithCompleteness(json, Assessment);

        Assert.StartsWith(Body(json), result, StringComparison.Ordinal);
        Assert.DoesNotContain("\\u003C", result, StringComparison.OrdinalIgnoreCase);   // '<'
        Assert.DoesNotContain("\\u003E", result, StringComparison.OrdinalIgnoreCase);   // '>'
        Assert.DoesNotContain("\\u0026", result, StringComparison.OrdinalIgnoreCase);   // '&'
        Assert.DoesNotContain("\\u0027", result, StringComparison.OrdinalIgnoreCase);   // '\''
        using var doc = JsonDocument.Parse(result);
        Assert.Equal(api, doc.RootElement.GetProperty("CalledApi").GetString());
    }

    // The other half of the same trap, on the field that actually broke: STJ writes a DateTimeOffset's "+00:00"
    // literally, but re-serializing it as a string escapes the '+' as +. The splice never touches it.
    [Fact]
    public void WithCompleteness_PreservesAnIso8601OffsetsPlusSign()
    {
        const string json = "{\r\n  \"AnalyzedAt\": \"1970-01-01T00:00:00+00:00\"\r\n}";

        var result = Program.WithCompleteness(json, Assessment);

        Assert.Contains("\"1970-01-01T00:00:00+00:00\"", result, StringComparison.Ordinal);
        Assert.DoesNotContain("\\u002B", result, StringComparison.OrdinalIgnoreCase);
    }
    #endregion

    #region Methods — helpers
    // The payload minus its closing brace and any trailing whitespace: everything the splice must reproduce verbatim.
    private static string Body(string json) => json[..json.LastIndexOf('}')].TrimEnd();
    #endregion

    #region Fields
    // An INCOMPLETE assessment, so the block has a non-empty Caveats array to carry (and a false IsComplete to find).
    private static readonly CompletenessAssessment Assessment =
        CompletenessAssessment.ForAssembly(AssemblyReport(methodsTotal: 120, methodsSkipped: 3));
    #endregion
}
