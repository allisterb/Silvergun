namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// Graph worker protocol v1 on the wire (<c>docs/agent/tasks/graph-worker.md</c> G2): a real <see cref="ReachabilityReport"/>
/// round-trips through the strict source-generated <c>GraphWorkerJsonContext</c> byte for byte, the context refuses every
/// record that is not exactly the schema, and <c>GraphWorkerWriter</c> writes a record whole or not at all.
/// </summary>
public sealed class GraphWorkerProtocolTests
{
    #region Constructors
    public GraphWorkerProtocolTests() => Runtime.Initialize("Silvergun", "TESTS");
    #endregion

    #region Methods: round trip
    /// <summary>
    /// The mechanism fixture plus its Dependency, built and analysed in-process, as a <c>folder</c> record: deserialized and
    /// written again, the bytes are identical, and the report really carries reaches, example paths with hops, profiles and
    /// verdicts (so the round trip is not vacuous).
    /// </summary>
    [Fact]
    public void AFolderRecordWithARealReport_RoundTrips_ByteIdentical()
    {
        var record = MechanismRecord.Value;
        var first = GraphJson.Of(record);

        var back = JsonSerializer.Deserialize(first, GraphWorkerJsonContext.Default.GraphWorkerMessage);

        var folder = Assert.IsType<GraphWorkerFolder>(back);
        Assert.Equal(first, GraphJson.Of(folder));
        Assert.NotNull(folder.Report);
        Assert.NotEmpty(folder.Report!.Reaches);
        Assert.Contains(folder.Report.Reaches, r => r.Examples.Any(e => e.Hops.Count > 1));
        Assert.NotEmpty(folder.Report.Classes);
        Assert.Equal(record.Nodes, folder.Nodes);
        Assert.Equal(record.Edges, folder.Edges);
        Assert.True(folder.Nodes > 0 && folder.Edges > 0);
    }

    /// <summary>Every message type and the request round-trip byte for byte, the discriminator first.</summary>
    [Fact]
    public void EveryMessageAndTheRequest_RoundTrip_WithTheDiscriminatorFirst()
    {
        GraphWorkerMessage[] messages =
        [
            new GraphWorkerReady(1, 3),
            new GraphWorkerDone(3),
            new GraphWorkerFatal("why"),
            new GraphWorkerFolder(2, "lib/net8.0", [], [new PackageGraphLoadFailure("lib/net8.0/a.dll", "not managed")], null, 0, 0),
        ];
        foreach (var message in messages)
        {
            var json = GraphJson.Of(message);
            Assert.StartsWith("{\"type\":\"", json, StringComparison.Ordinal);
            Assert.Equal(json, GraphJson.Of(JsonSerializer.Deserialize(json, GraphWorkerJsonContext.Default.GraphWorkerMessage)!));
        }

        var request = new GraphWorkerRequest(1, new GraphWorkerBudget(10, 20, 30),
            [new GraphWorkerFolderRequest("lib/net8.0", [new GraphWorkerAssembly("lib/net8.0/a.dll", @"C:\x\a.dll")])]);
        var line = JsonSerializer.Serialize(request, GraphWorkerJsonContext.Default.GraphWorkerRequest);
        Assert.Equal("{\"protocol\":1,\"budget\":{\"maxNodes\":10,\"maxEdges\":20,\"maxDispatchWork\":30},\"folders\":[{\"folder\":\"lib/net8.0\",\"assemblies\":[{\"relativePath\":\"lib/net8.0/a.dll\",\"fullPath\":\"C:\\\\x\\\\a.dll\"}]}]}", line);
        Assert.Equal(line, JsonSerializer.Serialize(JsonSerializer.Deserialize(line, GraphWorkerJsonContext.Default.GraphWorkerRequest)!, GraphWorkerJsonContext.Default.GraphWorkerRequest));
    }

    /// <summary>Nulls are written, never omitted: a record without a report says <c>"report":null</c>.</summary>
    [Fact]
    public void ANullReport_IsWritten_NotOmitted()
    {
        var json = GraphJson.Of(new GraphWorkerFolder(0, "", [], [], null, 0, 0));

        Assert.Equal("{\"type\":\"folder\",\"index\":0,\"folder\":\"\",\"assemblies\":[],\"loadFailures\":[],\"report\":null,\"nodes\":0,\"edges\":0}", json);
    }
    #endregion

    #region Methods: strictness
    // Each malformed record, built from the valid one when the test runs (not at discovery, which would build a graph).
    private static readonly System.Collections.Generic.Dictionary<string, Func<string>> malformed = new()
    {
        ["an unknown top-level member"] = () => Edit(Valid, "{\"type\":\"folder\",", "{\"type\":\"folder\",\"extra\":1,"),
        ["an unknown member inside the report"] = () => Edit(Valid, "\"graph\":{", "\"graph\":{\"extra\":1,"),
        ["a missing constructor parameter (edges)"] = () => Without(Valid, "edges"),
        ["a missing nullable constructor parameter (report)"] = () => Without(Valid, "report"),
        ["a missing ready count"] = () => "{\"type\":\"ready\",\"protocol\":1}",
        ["a duplicate property"] = () => Edit(Valid, ",\"nodes\":", ",\"nodes\":0,\"nodes\":"),
        ["a duplicate discriminator"] = () => Edit(Valid, "{\"type\":\"folder\",", "{\"type\":\"folder\",\"type\":\"folder\","),
        ["a wrong-case discriminator value"] = () => Edit(Valid, "{\"type\":\"folder\",", "{\"type\":\"Folder\","),
        ["an unknown discriminator"] = () => "{\"type\":\"progress\",\"count\":1}",
        ["no discriminator"] = () => "{\"count\":1}",
        ["the discriminator not first"] = () => "{\"count\":1,\"type\":\"done\"}",
        ["a wrong-case property name"] = () => Edit(Valid, ",\"nodes\":", ",\"Nodes\":"),
        ["a null non-nullable string"] = () => Edit(Valid, "\"folder\":\"lib/net10.0\"", "\"folder\":null"),
        ["a null non-nullable list"] = () => Edit(Valid, "\"loadFailures\":[]", "\"loadFailures\":null"),
        ["a string for an int"] = () => Replace(Valid, "nodes", JsonValue.Create("1")),
        ["a fraction for an int"] = () => Replace(Valid, "nodes", JsonValue.Create(1.5)),
        ["a trailing comma"] = () => "{\"type\":\"done\",\"count\":1,}",
        ["a comment"] = () => "{\"type\":\"done\",\"count\":1/* c */}",
        ["over-depth nesting"] = () => "{\"type\":\"fatal\",\"reason\":" + new string('[', 64) + new string(']', 64) + "}",
        ["not an object"] = () => "[1]",
        ["two records on one line"] = () => "{\"type\":\"done\",\"count\":1}{\"type\":\"done\",\"count\":1}",
    };

    public static TheoryData<string> Malformed() => [.. malformed.Keys];

    /// <summary>
    /// The context refuses every off-schema record. It may throw <see cref="JsonException"/> or, for a polymorphic record
    /// without a leading discriminator, <see cref="NotSupportedException"/> (the abstract base cannot be built): a reader
    /// must treat both as a protocol violation, as the YARA reader does.
    /// </summary>
    [Theory]
    [MemberData(nameof(Malformed))]
    public void TheContext_RejectsARecordThatIsNotExactlyTheSchema(string what)
    {
        var json = malformed[what]();

        var parsed = Record.Exception(() => JsonSerializer.Deserialize(json, GraphWorkerJsonContext.Default.GraphWorkerMessage));

        Assert.True(parsed is JsonException or NotSupportedException, $"{what}: {(parsed is null ? "accepted" : "threw " + parsed.GetType().Name)}");
    }

    /// <summary>A bare <c>null</c> deserializes to null, which the parent's reader turns into a protocol violation itself.</summary>
    [Fact]
    public void ABareNull_DeserializesToNull_ForTheReaderToRefuse() =>
        Assert.Null(JsonSerializer.Deserialize("null", GraphWorkerJsonContext.Default.GraphWorkerMessage));

    /// <summary>
    /// Enums inside the report are part of the schema too (ADR 0033 style: <c>WorkerScanStatusConverter</c> exists because
    /// <see cref="System.Text.Json.Serialization.JsonStringEnumConverter"/> also accepts integers and any letter case). A
    /// verdict sent as an integer, as an undefined integer, or in another case is not what any worker writes, so the strict
    /// reader must refuse it rather than carry an undefined value into the report.
    /// </summary>
    [Theory]
    [InlineData("an integer verdict", "1")]
    [InlineData("an undefined integer verdict", "999")]
    [InlineData("a lower-case verdict name", "\"reaches\"")]
    public void TheContext_RejectsAnEnumThatIsNotItsExactName(string what, string verdict)
    {
        var node = JsonNode.Parse(Valid)!;
        var classes = node["report"]!["classes"]!.AsArray();
        Assert.NotEmpty(classes);
        classes[0]!["verdict"] = JsonNode.Parse(verdict);
        var json = node.ToJsonString();

        var parsed = Record.Exception(() => JsonSerializer.Deserialize(json, GraphWorkerJsonContext.Default.GraphWorkerMessage));

        Assert.True(parsed is JsonException, $"{what} ({verdict}) was accepted by the strict reader");
    }

    /// <summary>
    /// Review N10: <see cref="RootClass"/> is a [Flags] enum, so a loose converter would also read a comma-joined
    /// combination. The exact converter reads a class only as one of its defined names: not a combination, not an integer,
    /// not another letter case.
    /// </summary>
    [Theory]
    [InlineData("a comma-joined flags combination", "\"LoadTime, HostContract\"")]
    [InlineData("a comma-joined combination without a space", "\"LoadTime,HostContract\"")]
    [InlineData("an integer", "1")]
    [InlineData("the integer of a combination", "3")]
    [InlineData("a lower-case name", "\"loadTime\"")]
    [InlineData("an upper-case name", "\"LOADTIME\"")]
    [InlineData("a name with a space", "\" LoadTime\"")]
    [InlineData("an empty name", "\"\"")]
    public void TheContext_RejectsAFlagsClassThatIsNotOneExactName(string what, string value)
    {
        var node = JsonNode.Parse(Valid)!;
        var classes = node["report"]!["classes"]!.AsArray();
        Assert.NotEmpty(classes);
        classes[0]!["class"] = JsonNode.Parse(value);
        var json = node.ToJsonString();

        var parsed = Record.Exception(() => JsonSerializer.Deserialize(json, GraphWorkerJsonContext.Default.GraphWorkerMessage));

        Assert.True(parsed is JsonException, $"{what} ({value}): {(parsed is null ? "accepted" : "threw " + parsed.GetType().Name)}");
    }

    /// <summary>The control for the test above: every class's exact name is read back as itself.</summary>
    [Fact]
    public void TheContext_ReadsEveryExactClassName()
    {
        foreach (var name in Enum.GetNames<RootClass>())
        {
            var node = JsonNode.Parse(Valid)!;
            node["report"]!["classes"]!.AsArray()[0]!["class"] = name;

            var folder = (GraphWorkerFolder)JsonSerializer.Deserialize(node.ToJsonString(), GraphWorkerJsonContext.Default.GraphWorkerMessage)!;

            Assert.Equal(Enum.Parse<RootClass>(name), folder.Report!.Classes[0].Class);
        }
    }

    /// <summary>A record whose class is a combination of flags is no single defined name: writing it throws and writes nothing.</summary>
    [Fact]
    public void TheWriter_RefusesACombinedFlagsValue_AndWritesNothing()
    {
        var record = MechanismRecord.Value;
        var report = record.Report!;
        var combined = record with { Report = report with { Classes = [report.Classes[0] with { Class = RootClass.LoadTime | RootClass.HostContract }, .. report.Classes.Skip(1)] } };
        using var stream = new MemoryStream();

        var thrown = Record.Exception(() => new GraphWorkerWriter(stream, GraphWorkerProtocol.MaxRecordLineBytes).Write(combined));

        Assert.IsType<JsonException>(thrown);
        Assert.Equal(0, stream.Length);
    }

    /// <summary>
    /// Item 6: an escaped lone surrogate in a string (<c>"\uD800"</c>, valid JSON text but not well-formed UTF-16 once
    /// unescaped) is refused as a <see cref="JsonException"/>, the one exception type the parent's reader turns into a
    /// protocol violation besides <see cref="NotSupportedException"/>. In a reason, in a folder name, and in a report string.
    /// </summary>
    [Theory]
    [InlineData("fatal")]
    [InlineData("folder")]
    [InlineData("report")]
    public void TheContext_RejectsAnEscapedLoneSurrogate_AsAJsonException(string where)
    {
        var json = where switch
        {
            "fatal" => "{\"type\":\"fatal\",\"reason\":\"a \\uD800 b\"}",
            "folder" => Edit(Valid, "\"folder\":\"lib/net10.0\"", "\"folder\":\"lib/\\uD800\""),
            _ => Edit(Valid, "\"partialReason\":null", "\"partialReason\":\"\\uDC00\""),
        };

        var parsed = Record.Exception(() => JsonSerializer.Deserialize(json, GraphWorkerJsonContext.Default.GraphWorkerMessage));

        Assert.True(parsed is JsonException, $"{where}: {(parsed is null ? "accepted" : "threw " + parsed.GetType().FullName + ": " + parsed.Message)}");
    }

    /// <summary>The context's configured depth is the protocol's: 16, about twice the deepest record (a hop of an example path).</summary>
    [Fact]
    public void TheContext_MaxDepthIs16_AndTheDeepestRealRecordFits()
    {
        Assert.Equal(16, GraphWorkerJsonContext.Default.Options.MaxDepth);
        Assert.Null(Record.Exception(() => JsonSerializer.Deserialize(Valid, GraphWorkerJsonContext.Default.GraphWorkerMessage)));
    }

    [Theory]
    [InlineData("an unknown member", "{\"protocol\":1,\"budget\":{\"maxNodes\":1,\"maxEdges\":1,\"maxDispatchWork\":1},\"folders\":[],\"extra\":0}")]
    [InlineData("a missing budget", "{\"protocol\":1,\"folders\":[]}")]
    [InlineData("a missing full path", "{\"protocol\":1,\"budget\":{\"maxNodes\":1,\"maxEdges\":1,\"maxDispatchWork\":1},\"folders\":[{\"folder\":\"a\",\"assemblies\":[{\"relativePath\":\"a/b.dll\"}]}]}")]
    [InlineData("a duplicate protocol", "{\"protocol\":1,\"protocol\":1,\"budget\":{\"maxNodes\":1,\"maxEdges\":1,\"maxDispatchWork\":1},\"folders\":[]}")]
    [InlineData("a null folder list", "{\"protocol\":1,\"budget\":{\"maxNodes\":1,\"maxEdges\":1,\"maxDispatchWork\":1},\"folders\":null}")]
    public void TheContext_RejectsAMalformedRequest(string what, string json) =>
        Assert.True(Record.Exception(() => JsonSerializer.Deserialize(json, GraphWorkerJsonContext.Default.GraphWorkerRequest)) is JsonException, what);
    #endregion

    #region Methods: the writer
    /// <summary>A record over the writer's limit throws and writes nothing; one exactly at the limit is written, with its <c>\n</c>.</summary>
    [Fact]
    public void TheWriter_RefusesALineOverItsLimit_AndWritesNothing()
    {
        var fatal = new GraphWorkerFatal(new string('a', 100));
        var size = Encoding.UTF8.GetByteCount(GraphJson.Of(fatal));
        using var over = new MemoryStream();
        using var exact = new MemoryStream();

        Assert.Throws<InvalidDataException>(() => new GraphWorkerWriter(over, size - 1).Write(fatal));
        new GraphWorkerWriter(exact, size).Write(fatal);

        Assert.Equal(0, over.Length);
        Assert.Equal(Encoding.UTF8.GetBytes(GraphJson.Of(fatal) + "\n"), exact.ToArray());
    }

    /// <summary>A string that is not well-formed UTF-16 cannot be written as itself: the writer throws and writes nothing.</summary>
    [Fact]
    public void TheWriter_RefusesIllFormedUtf16_AndWritesNothing()
    {
        using var stream = new MemoryStream();

        var thrown = Record.Exception(() => new GraphWorkerWriter(stream, GraphWorkerProtocol.MaxRecordLineBytes).Write(new GraphWorkerFatal("lone \uD800 surrogate")));

        Assert.True(thrown is not null, $"no exception; the writer wrote: {Encoding.UTF8.GetString(stream.ToArray()).TrimEnd('\n')}");
        Assert.Equal(0, stream.Length);
    }

    /// <summary>Lines are compact UTF-8 with no BOM, each ending in exactly one <c>\n</c>, and successive writes append.</summary>
    [Fact]
    public void TheWriter_WritesCompactBomFreeLines()
    {
        using var stream = new MemoryStream();
        var writer = new GraphWorkerWriter(stream, GraphWorkerProtocol.MaxRecordLineBytes);

        writer.Write(new GraphWorkerReady(1, 0));
        writer.Write(new GraphWorkerDone(0));

        Assert.Equal("{\"type\":\"ready\",\"protocol\":1,\"folders\":0}\n{\"type\":\"done\",\"count\":0}\n", Encoding.UTF8.GetString(stream.ToArray()));
        Assert.NotEqual(0xEF, stream.ToArray()[0]);
    }
    #endregion

    #region Methods: helpers
    private static string Edit(string json, string find, string replace)
    {
        var at = json.IndexOf(find, StringComparison.Ordinal);
        Assert.True(at >= 0, $"'{find}' is not in the valid record");
        return json[..at] + replace + json[(at + find.Length)..];
    }

    private static string Without(string json, string property)
    {
        var node = JsonNode.Parse(json)!.AsObject();
        Assert.True(node.Remove(property), $"'{property}' is not in the valid record");
        return node.ToJsonString();
    }

    private static string Replace(string json, string property, JsonNode value)
    {
        var node = JsonNode.Parse(json)!.AsObject();
        Assert.True(node.ContainsKey(property), $"'{property}' is not in the valid record");
        node[property] = value;
        return node.ToJsonString();
    }
    #endregion

    #region Fields
    // The in-process folder record for the mechanism fixture and its Dependency in one lib/net10.0 (built once per run).
    private static readonly Lazy<GraphWorkerFolder> MechanismRecord = new(() =>
    {
        Runtime.Initialize("Silvergun", "TESTS");
        return GraphJson.InProcess(0, "lib/net10.0",
        [
            ($"lib/net10.0/{GraphStage.MechanismDependency}", GraphStage.Beside(GraphStage.MechanismDependency)),
            ($"lib/net10.0/{GraphStage.MechanismFixture}", GraphStage.Beside(GraphStage.MechanismFixture)),
        ]);
    });

    private static string Valid => GraphJson.Of(MechanismRecord.Value);
    #endregion
}
