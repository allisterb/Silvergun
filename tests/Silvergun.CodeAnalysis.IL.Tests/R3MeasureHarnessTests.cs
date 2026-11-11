namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// The pure helpers of the harness's <c>r3-measure</c> mode (<see cref="R3Measure"/>, reachability R3 S3): the wire index a
/// folder record carried, the JSON span measurement over the CLI's <c>--json</c> stdout, the ratio, the markdown cell, the
/// protocol's own wire context and the replica beside it (review W3), the <c>--timeout</c> value (N3), and the member
/// removal and masking behind the acceptance 5/6 output check (N5). The mode's end-to-end run is a measurement, done by
/// hand through the guard.
/// </summary>
public sealed class R3MeasureHarnessTests
{
    #region Methods
    [Fact]
    public void WireIndexes_NumbersSentFoldersFromZero_SkippingCopiesAndUnsentFolders()
    {
        var indexes = R3Measure.WireIndexes(
        [
            (FolderOutcome.NotRun, false),        // unsendable: never in a request
            (FolderOutcome.Analyzed, false),
            (FolderOutcome.Analyzed, true),       // SameAs copy: never sent
            (FolderOutcome.NothingLoaded, false), // a record with a null report is still a record
            (FolderOutcome.Analyzed, false),
        ]);

        Assert.Equal([null, 0, null, 1, 2], indexes);
    }

    [Theory]
    [InlineData(FolderOutcome.Crashed)]
    [InlineData(FolderOutcome.TimedOut)]
    public void WireIndexes_AfterAFailedFolder_TheNextWorkerStartsAtZero(FolderOutcome failure)
    {
        var indexes = R3Measure.WireIndexes([(FolderOutcome.Analyzed, false), (FolderOutcome.Analyzed, false), (failure, false), (FolderOutcome.Analyzed, false)]);

        Assert.Equal([0, 1, null, 0], indexes);
    }

    [Fact]
    public void MemberSpan_ReturnsTheExactBytesOfATopLevelValue_NotANestedNamesake()
    {
        const string json = "{\r\n  \"A\": { \"Reachability\": 1 },\r\n  \"Reachability\": {\r\n    \"Folders\": []\r\n  },\r\n  \"B\": 2\r\n}";
        var bytes = Encoding.UTF8.GetBytes(json);

        var span = R3Measure.MemberSpan(bytes, "Reachability");

        Assert.NotNull(span);
        Assert.Equal("{\r\n    \"Folders\": []\r\n  }", Encoding.UTF8.GetString(bytes, span.Value.Start, span.Value.Length));
    }

    [Fact]
    public void MemberSpan_OfAStringValue_IncludesItsQuotes()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"S\":\"Incomplete\"}");

        var span = R3Measure.MemberSpan(bytes, "S")!.Value;

        Assert.Equal("\"Incomplete\"", Encoding.UTF8.GetString(bytes, span.Start, span.Length));
    }

    // Console output can begin with a UTF-8 BOM; the span is still an offset into the bytes as written.
    [Fact]
    public void MemberSpan_AfterABom_IsAnOffsetIntoTheOriginalBytes()
    {
        byte[] bytes = [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes("{\"X\":[1,2]}")];

        var span = R3Measure.MemberSpan(bytes, "X")!.Value;

        Assert.Equal("[1,2]", Encoding.UTF8.GetString(bytes, span.Start, span.Length));
    }

    [Theory]
    [InlineData("{\"Other\":1}")]
    [InlineData("[{\"X\":1}]")]
    [InlineData("{}")]
    public void MemberSpan_WhenTheMemberIsAbsentOrTheJsonIsNotAnObject_IsNull(string json)
    {
        Assert.Null(R3Measure.MemberSpan(Encoding.UTF8.GetBytes(json), "X"));
    }

    [Fact]
    public void ElementLengths_MeasuresEachElementOfTheArrayMember()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"Folders\": [ {\"a\":1}, {\"bb\": \"xy\"} ], \"Dropped\": 0}");

        Assert.Equal([7L, 12L], R3Measure.ElementLengths(bytes, "Folders")); // {"a":1} and {"bb": "xy"}, the inner space counted
        Assert.Empty(R3Measure.ElementLengths(bytes, "Missing"));
        Assert.Empty(R3Measure.ElementLengths(bytes, "Dropped"));
    }

    [Theory]
    [InlineData(1000L, 100L, "10.0x")]
    [InlineData(150L, 100L, "1.5x")]
    [InlineData(1L, 3L, "0.3x")]
    [InlineData(100L, 0L, "-")]
    [InlineData(null, 100L, "-")]
    [InlineData(100L, null, "-")]
    public void Ratio_IsRawOverSummaryToOneDecimal(long? raw, long? summary, string expected)
    {
        Assert.Equal(expected, R3Measure.Ratio(raw, summary));
    }

    // A folder name is package-controlled: a pipe must not split the table row, and a hidden character must show.
    [Fact]
    public void Cell_EscapesPackageText_AndCutsIt()
    {
        Assert.Equal("lib/a\\|b", R3Measure.Cell("lib/a|b"));
        Assert.Equal("a\\u{202e}b", R3Measure.Cell("a" + RightToLeftOverride + "b"));
        Assert.Equal("abc...", R3Measure.Cell("abcdef", 3));
        Assert.Equal(string.Empty, R3Measure.Cell(null));
        Assert.Equal(163, R3Measure.Cell(new string('x', 500)).Length);
    }
    #endregion

    #region Methods: the wire bytes (review W3)
    // The raw sizes are exact only through the protocol's own context, reached by reflection: a rename or move of
    // GraphWorkerJsonContext must break this test, not quietly turn a measurement approximate.
    [Fact]
    public void WireTypeInfo_ReachesTheProtocolsOwnContext()
    {
        var wire = R3Measure.WireTypeInfo();

        Assert.NotNull(wire);
        Assert.Equal(typeof(GraphWorkerMessage), wire.Type);
        Assert.StartsWith("{\"type\":\"folder\",", Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes<GraphWorkerMessage>(SampleRecord(), wire)), StringComparison.Ordinal);
    }

    // The replica the harness falls back on writes the same bytes for a record with a report, every enum of it included.
    [Fact]
    public void RecordBytes_ThroughTheWireContext_EqualTheReplicas_ForASampleRecord()
    {
        var record = SampleRecord();

        var (bytes, replica) = R3Measure.RecordBytes(record, R3Measure.WireTypeInfo());

        Assert.NotNull(bytes);
        Assert.Equal(replica, bytes);
        Assert.Equal(JsonSerializer.SerializeToUtf8Bytes<GraphWorkerMessage>(record, R3Measure.WireTypeInfo()!).LongLength, bytes);
        Assert.True(bytes > 500, $"a sample record of {bytes} bytes");   // not vacuous: the report is in it
    }

    [Fact]
    public void RecordBytes_WithoutTheWireContext_AreTheReplicas()
    {
        var (bytes, replica) = R3Measure.RecordBytes(SampleRecord(), null);

        Assert.NotNull(replica);
        Assert.Equal(replica, bytes);
    }
    #endregion

    #region Methods: --timeout (review N3)
    [Theory]
    [InlineData("900", 900.0)]
    [InlineData("0.5", 0.5)]
    [InlineData("2700", 2700.0)]
    [InlineData("1e3", 1000.0)]
    public void ParseTimeout_TakesInvariantSecondsOverZero(string text, double seconds)
    {
        Assert.Equal(TimeSpan.FromSeconds(seconds), R3Measure.ParseTimeout(text));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("abc")]
    [InlineData("")]
    [InlineData("NaN")]
    [InlineData("Infinity")]
    [InlineData("1e308")]
    [InlineData("1,5")]
    public void ParseTimeout_RejectsZeroNegativeNonNumericAndUnwaitable(string text)
    {
        Assert.Null(R3Measure.ParseTimeout(text));
    }

    [Fact]
    public void ParseTimeout_AcceptsUpToTheLongestWait_AndNoMore()
    {
        Assert.Equal(TimeSpan.FromSeconds(R3Measure.MaxTimeoutSeconds), R3Measure.ParseTimeout(R3Measure.MaxTimeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        Assert.Null(R3Measure.ParseTimeout((R3Measure.MaxTimeoutSeconds + 1).ToString(System.Globalization.CultureInfo.InvariantCulture)));
    }

    // Bad usage is exit 2 and touches nothing: these paths do not exist.
    [Theory]
    [InlineData("--timeout", "0")]
    [InlineData("--timeout", "-5")]
    [InlineData("--timeout", "soon")]
    [InlineData("--wait", "60")]
    public void Execute_WithABadTimeout_GivesUsage_AndExitsTwo(string flag, string value)
    {
        Assert.Equal(2, R3Measure.Execute([R3Measure.Verb, @"Z:\no\such.nupkg", @"Z:\no\out", flag, value]));
    }

    [Fact]
    public void Execute_WithTheWrongArgumentCount_ExitsTwo()
    {
        Assert.Equal(2, R3Measure.Execute([R3Measure.Verb, @"Z:\no\such.nupkg"]));
        Assert.Equal(2, R3Measure.Execute([R3Measure.Verb, @"Z:\no\such.nupkg", @"Z:\no\out", "--timeout"]));
    }
    #endregion

    #region Methods: member removal and masking (review N5)
    // The CLI's own shape: indented, CRLF, a trailing newline, Reachability and ReachabilityStatus adjacent mid-object.
    [Fact]
    public void WithoutMembers_LeavesWhatASerializerThatNeverWroteThemWrites()
    {
        var with = Utf8(Lines(
            "{",
            "  \"Package\": {",
            "    \"Id\": \"A\"",
            "  },",
            "  \"AnalyzedAt\": \"2026-11-11T07:25:41.4814217+00:00\",",
            "  \"Assemblies\": [],",
            "  \"ScriptScanStatus\": \"Completed\",",
            "  \"Reachability\": {",
            "    \"Folders\": []",
            "  },",
            "  \"ReachabilityStatus\": \"Completed\",",
            "  \"YaraFindings\": [],",
            "  \"Completeness\": {",
            "    \"X\": 1",
            "  }",
            "}") + "\r\n");

        var stripped = R3Measure.WithoutMembers(with, "Reachability", "ReachabilityStatus", "AnalyzedAt");

        Assert.Equal(
            Lines(
                "{",
                "  \"Package\": {",
                "    \"Id\": \"A\"",
                "  },",
                "  \"Assemblies\": [],",
                "  \"ScriptScanStatus\": \"Completed\",",
                "  \"YaraFindings\": [],",
                "  \"Completeness\": {",
                "    \"X\": 1",
                "  }",
                "}") + "\r\n",
            Encoding.UTF8.GetString(stripped!));
    }

    [Theory]
    [InlineData("{\"A\":1,\"B\":2,\"C\":3}", "A", "{\"B\":2,\"C\":3}")]
    [InlineData("{\"A\":1,\"B\":2,\"C\":3}", "B", "{\"A\":1,\"C\":3}")]
    [InlineData("{\"A\":1,\"B\":2,\"C\":3}", "C", "{\"A\":1,\"B\":2}")]
    [InlineData("{\n  \"A\": [1, 2],\n  \"B\": 2\n}", "A", "{\n  \"B\": 2\n}")]
    [InlineData("{ \"A\": {\"B\": 1} }", "A", "{}")]
    [InlineData("{\"X\":{\"A\":1},\"A\":\"s\"}", "A", "{\"X\":{\"A\":1}}")]
    public void WithoutMembers_RemovesTheFirstMiddleLastOrOnlyTopLevelMember(string json, string name, string expected)
    {
        Assert.Equal(expected, Encoding.UTF8.GetString(R3Measure.WithoutMembers(Utf8(json), name)!));
    }

    [Fact]
    public void WithoutMembers_RemovesSeveralInTurn_TheFirstTwoIncluded()
    {
        Assert.Equal("{\"C\":3}", Encoding.UTF8.GetString(R3Measure.WithoutMembers(Utf8("{\"A\":1,\"B\":2,\"C\":3}"), "A", "B")!));
        Assert.Equal("{\"B\":2}", Encoding.UTF8.GetString(R3Measure.WithoutMembers(Utf8("{\"A\":1,\"B\":2,\"C\":3}"), "C", "A")!));
    }

    [Fact]
    public void WithoutMembers_KeepsALeadingBom()
    {
        byte[] json = [0xEF, 0xBB, 0xBF, .. Utf8("{\"A\":1,\"B\":2}")];

        Assert.Equal([0xEF, 0xBB, 0xBF, .. Utf8("{\"A\":1}")], R3Measure.WithoutMembers(json, "B"));
    }

    [Theory]
    [InlineData("{\"A\":1}", "B")]                // absent
    [InlineData("{\"X\":{\"B\":1}}", "B")]        // only a nested namesake
    [InlineData("[{\"B\":1}]", "B")]              // not an object
    [InlineData("{}", "B")]
    public void WithoutMembers_WhenAMemberIsNotATopLevelOne_IsNull(string json, string name)
    {
        Assert.Null(R3Measure.WithoutMembers(Utf8(json), name));
    }

    [Fact]
    public void WithoutMembers_WhenOneOfSeveralIsAbsent_IsNull()
    {
        Assert.Null(R3Measure.WithoutMembers(Utf8("{\"A\":1,\"B\":2}"), "A", "Z"));
    }

    [Fact]
    public void WithoutMembers_OnTruncatedJson_Throws()
    {
        Assert.ThrowsAny<JsonException>(() => R3Measure.WithoutMembers(Utf8("{\"A\":1,\"B\":"), "B"));
    }

    [Fact]
    public void MaskVolatile_MasksAnalyzedAtValues_TheExtractionName_AndTheRunTemp()
    {
        var json = "{\"AnalyzedAt\": \"2026-11-11T07:25:41.4814217+00:00\", \"R\": {\"AnalyzedAt\":\"2026-11-11T07:25:18Z\"}, " +
            "\"FullPath\": \"C:" + Bs + "Temp" + Bs + "silvergun-r3-0123456789abcdef0123456789abcdef" + Bs + "silvergun" + Bs + "pkg-mxi8aojlgegl" + Bs + "A.nupkg\"}";

        Assert.Equal(
            "{\"AnalyzedAt\": \"TIMESTAMP\", \"R\": {\"AnalyzedAt\":\"TIMESTAMP\"}, " +
            "\"FullPath\": \"C:" + Bs + "Temp" + Bs + "silvergun-r3-MASKED" + Bs + "silvergun" + Bs + "pkg-MASKED" + Bs + "A.nupkg\"}",
            R3Measure.MaskVolatile(json));
    }

    // Exact otherwise: other timestamps, near-miss extraction names, and an AnalyzedAt inside a string value stay.
    [Theory]
    [InlineData("{\"Published\": \"2026-11-11T07:25:41Z\"}")]
    [InlineData("{\"P\": \"pkg-short\"}")]
    [InlineData("{\"P\": \"pkg-ABCDEFGHIJKL\"}")]
    [InlineData("{\"P\": \"pkg-abcdefghijklm\"}")]
    [InlineData("{\"P\": \"xpkg-abcdefghijkl\"}")]
    [InlineData("{\"P\": \"silvergun-r3-0123\"}")]
    [InlineData("{\"AnalyzedAt\": \"yesterday\"}")]
    public void MaskVolatile_LeavesEverythingElse(string json)
    {
        Assert.Equal(json, R3Measure.MaskVolatile(json));
    }

    [Fact]
    public void MaskVolatile_LeavesAnAnalyzedAtInsideAStringValue()
    {
        const string q = @"\" + "\"";   // an escaped quote inside a JSON string
        var json = "{\"D\": \"x " + q + "AnalyzedAt" + q + ": " + q + "2026-11-11T07:25:41Z" + q + " y\"}";

        Assert.Equal(json, R3Measure.MaskVolatile(json));
    }

    [Fact]
    public void StrippedOutputsEqual_Holds_WhenOnlyReachabilityAndPerRunFieldsDiffer()
    {
        var with = Scan("A", reachability: true, at: "2026-11-11T07:25:41.1+00:00", nested: "2026-11-11T07:25:18.2+00:00", pkg: "pkg-mxi8aojlgegl");
        var without = Scan("A", reachability: false, at: "2026-11-11T07:25:49.3+00:00", nested: "2026-11-11T07:25:44.4+00:00", pkg: "pkg-y19bzxznu5ea");

        var (held, detail) = R3Measure.StrippedOutputsEqual(with, without);

        Assert.True(held, detail);
    }

    [Fact]
    public void StrippedOutputsEqual_Fails_OnAnyOtherDifference_AndSaysWhere()
    {
        var with = Scan("A", reachability: true);
        var without = Scan("B", reachability: false);

        var (held, detail) = R3Measure.StrippedOutputsEqual(with, without);

        Assert.False(held);
        Assert.Contains("differ at char", detail, StringComparison.Ordinal);
    }

    // The check is not vacuous: with no Reachability member in the with run, or no AnalyzedAt, it fails.
    [Fact]
    public void StrippedOutputsEqual_Fails_WhenAMemberToRemoveIsMissing()
    {
        Assert.False(R3Measure.StrippedOutputsEqual(Scan("A", reachability: false), Scan("A", reachability: false)).Held);
        Assert.False(R3Measure.StrippedOutputsEqual(Scan("A", reachability: true), Utf8("{\"Package\": {}}")).Held);
    }

    [Fact]
    public void StrippedOutputsEqual_Fails_OnTruncatedOutput()
    {
        var with = Scan("A", reachability: true);

        var (held, detail) = R3Measure.StrippedOutputsEqual(with[..(with.Length / 2)], Scan("A", reachability: false));

        Assert.False(held);
        Assert.Contains("not JSON", detail, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: helpers
    // A folder record with a report: every enum the wire writes (RootClass, Capability, ReachEvidence, OpacityKind,
    // RootClassVerdict), a load failure, a partial reason and a null.
    private static GraphWorkerFolder SampleRecord()
    {
        var coverage = new GraphCoverage(new IndexCoverage(0, 0, 0), 0, 0, 0, 0, ResolutionCounts.None, 0, 0, 0, 0, 0, 0, 0, false, null);
        var path = new ReachPath("App.R", ReachEvidence.Bound, true, [new ReachHop("App.R", "App", null, 0), new ReachHop("Ext.Sink", null, null, 0)], 2, false, OpacityKind.IndirectCall);
        var report = new ReachabilityReport(
            [new CapabilityReach(RootClass.NativeEntry, Capability.Network, 2, 2, 2, 1, [path]), new CapabilityReach(RootClass.Finalizer, null, 1, 1, 1, 1, [])],
            [], false,
            [new RootClassStatus(RootClass.NativeEntry, 2, RootClassVerdict.Reaches, []), new RootClassStatus(RootClass.LoadTime, 0, RootClassVerdict.Unknown, ["a reason"])],
            0, [], 0, coverage, true, "the report is partial");
        return new GraphWorkerFolder(3, "lib/net8.0", ["lib/net8.0/a.dll"], [new PackageGraphLoadFailure("lib/net8.0/b.dll", "not managed")], report, 10, 20);
    }

    // A scan-package --json stdout in the CLI's shape, with or without the reachability members.
    private static byte[] Scan(string id, bool reachability, string at = "2026-11-11T07:25:41.1+00:00", string nested = "2026-11-11T07:25:18.2+00:00", string pkg = "pkg-mxi8aojlgegl")
    {
        var lines = new List<string>
        {
            "{",
            "  \"Package\": {",
            $"    \"Id\": \"{id}\"",
            "  },",
            $"  \"AnalyzedAt\": \"{at}\",",
            "  \"Assemblies\": [",
            "    {",
            $"      \"FullPath\": \"C:{Bs}Temp{Bs}silvergun{Bs}{pkg}{Bs}a.dll\",",
            $"      \"AnalyzedAt\": \"{nested}\"",
            "    }",
            "  ],",
            "  \"ScriptScanStatus\": \"Completed\",",
        };
        if (reachability)
            lines.AddRange(["  \"Reachability\": {", "    \"Folders\": []", "  },", "  \"ReachabilityStatus\": \"Completed\","]);
        lines.AddRange(["  \"Completeness\": {}", "}"]);
        return Utf8(Lines([.. lines]) + "\r\n");
    }

    private static string Lines(params string[] lines) => string.Join("\r\n", lines);

    private static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);
    #endregion

    #region Fields
    // Built from its number, so no raw bidi character is ever in this file.
    private const char RightToLeftOverride = (char)0x202E;

    // A JSON-escaped backslash, as the CLI writes one in a path.
    private const string Bs = @"\\";
    #endregion
}
