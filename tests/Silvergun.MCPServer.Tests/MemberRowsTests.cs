namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;

using Silvergun.CodeAnalysis.IL;
using Silvergun.MCPServer.Jobs;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// <see cref="MemberRows.Write"/> and <see cref="PackageFindings.Write"/>'s caller tokens on synthetic findings over the
/// inspect entry's real report and assembly (task S3): evidence narrows overloads and an absent piece of evidence keeps
/// them all; an indicator matches case-insensitively; a resource, an unknown caller or an assembly not walked has no
/// tokens; findings without a members walk have no <c>callerTokens</c> key; and member and string rows of worst-case names
/// stay within the row bound with their filter keys whole.
/// </summary>
[Collection(InspectCollection.Name)]
public sealed class MemberRowsTests(InspectFixture fixture) : IDisposable
{
    #region Methods
    [Fact]
    public void CallerTokens_EvidenceNoOverloadCarries_ListsEveryOverload()
    {
        var finding = new ApiCallFinding(Capability.Network, ApiCallKind.Call, InspectFixtures.OverloadsType, "Go", "System.Net.Http.HttpClient.GetStringAsync");

        var rows = Write(f => f with { Report = f.Report! with { Findings = [finding] } });

        Assert.Equal([Token("Go", "(System.Int32)"), Token("Go", "(System.String)")], Tokens(rows.CallerTokens(finding, 8)));
        Assert.Equal(2, Found(rows, finding).Total);
    }

    [Fact]
    public void CallerTokens_TheCalledApi_NarrowsAmongOverloads()
    {
        var start = new ApiCallFinding(Capability.ProcessExecution, ApiCallKind.Call, InspectFixtures.OverloadsType, "Go", "System.Diagnostics.Process.Start");
        var read = new ApiCallFinding(Capability.FileSystem, ApiCallKind.Call, InspectFixtures.OverloadsType, "Go", "System.IO.File.ReadAllText");

        var rows = Write(f => f with { Report = f.Report! with { Findings = [start, read] } });

        Assert.Equal([Token("Go", "(System.Int32)")], Tokens(rows.CallerTokens(start, 8)));
        Assert.Equal([Token("Go", "(System.String)")], Tokens(rows.CallerTokens(read, 8)));
    }

    /// <summary>
    /// S3 review C2: an indicator narrows by the exact value the indicator pass produces from a method's strings
    /// (<see cref="IndicatorAnalysis.ValuesIn"/>), not by a substring. A value the pass would never produce from either
    /// overload (the upper-case form of a host, which the pass normalises to lower case, or a fragment) narrows nothing.
    /// </summary>
    [Fact]
    public void CallerTokens_AnIndicatorsValue_NarrowsByTheValuesThePassProduces()
    {
        var category = Scan().Indicators!.Findings.First().Category;
        Assert.Contains("alpha.example", IndicatorAnalysis.ValuesIn("https://alpha.example/a"));
        Assert.DoesNotContain("ALPHA.EXAMPLE", IndicatorAnalysis.ValuesIn("https://alpha.example/a"));
        var exact = new IndicatorFinding(category, "alpha.example", "x", InspectFixtures.OverloadsType, "Host", 1);
        var beta = new IndicatorFinding(category, "beta.example", "x", InspectFixtures.OverloadsType, "Host", 1);
        var upper = new IndicatorFinding(category, "ALPHA.EXAMPLE", "x", InspectFixtures.OverloadsType, "Host", 1);
        var fragment = new IndicatorFinding(category, "alpha", "x", InspectFixtures.OverloadsType, "Host", 1);
        var neither = new IndicatorFinding(category, "gamma.example", "x", InspectFixtures.OverloadsType, "Host", 1);

        var rows = Write(f => f with { Indicators = f.Indicators! with { Findings = [exact, beta, upper, fragment, neither] } });

        Assert.Equal([Token("Host", "(System.Int32)")], Tokens(rows.CallerTokens(exact, 8)));
        Assert.Equal([Token("Host", "(System.String)")], Tokens(rows.CallerTokens(beta, 8)));
        var both = new List<string> { Token("Host", "(System.Int32)"), Token("Host", "(System.String)") };
        Assert.Equal(both, Tokens(rows.CallerTokens(upper, 8)));
        Assert.Equal(both, Tokens(rows.CallerTokens(fragment, 8)));
        Assert.Equal(both, Tokens(rows.CallerTokens(neither, 8)));
    }

    /// <summary>
    /// Hidden content: a whole constant narrows by its length; a substring finding keeps every overload; a field-data or
    /// resource finding never names a method (S3 review W5), even when its caller name is a method's.
    /// </summary>
    [Fact]
    public void CallerTokens_HiddenContent_ByConstantLength_AndNoneFromFieldDataOrAResource()
    {
        var shorter = new ObfuscationFinding(HiddenContentKind.EncodedExecutable, "Windows PE", InspectFixtures.OverloadsType, "Blob", 512, 5.9, HiddenContentSource.Constant);
        var longer = shorter with { EncodedLength = 1024 };
        var substring = shorter with { Source = HiddenContentSource.Substring };
        var resource = new ObfuscationFinding(HiddenContentKind.EncodedExecutable, "Windows PE", "<resource>", "Payload.resources", 400, 7.9, HiddenContentSource.Resource);
        var fieldData = shorter with { Source = HiddenContentSource.FieldData };
        var namedResource = shorter with { Source = HiddenContentSource.Resource };

        var rows = Write(f => f with { Obfuscation = f.Obfuscation! with { Findings = [shorter, longer, substring, resource, fieldData, namedResource] } });

        Assert.Equal([Token("Blob", "(System.Int32)")], Tokens(rows.CallerTokens(shorter, 8)));
        Assert.Equal([Token("Blob", "(System.String)")], Tokens(rows.CallerTokens(longer, 8)));
        Assert.Equal(2, Found(rows, substring).Total);
        foreach (var none in new[] { resource, fieldData, namedResource })
            Assert.Equal((0, 0), (Found(rows, none).Tokens.Count, Found(rows, none).Total));
        // Nor are they counted on a member: each Blob is counted for its constant and the substring finding only.
        foreach (var parameter in new[] { "(System.Int32)", "(System.String)" })
            Assert.Equal(2, Assert.Single(Drill.Lines(dir, JobProtocol.MembersFile), m => Drill.Str(m["token"]) == Token("Blob", parameter))["hiddenContent"]!.GetValue<int>());
    }

    /// <summary>P/Invoke and native-export findings narrow by the member's special flag, not by evidence.</summary>
    [Fact]
    public void CallerTokens_NativeFindings_NarrowBySpecialFlag()
    {
        var import = Scan().Report!.Findings.Single(f => f.Kind == ApiCallKind.NativeImport);
        var export = Scan().Report!.Findings.Single(f => f.Kind == ApiCallKind.NativeExport);
        // Named as the type's two Finalize methods: neither is a P/Invoke, so nothing narrows and both are listed.
        var notNative = import with { CallerMethod = "Finalize" };

        var rows = Write(f => f with { Report = f.Report! with { Findings = [import, export, notNative] } });

        Assert.Equal([fixture.Token(InspectFixtures.SpecialType, "Beep")], Tokens(rows.CallerTokens(import, 8)));
        Assert.Equal([fixture.Token(InspectFixtures.SpecialType, "Exported")], Tokens(rows.CallerTokens(export, 8)));
        Assert.Equal(2, Found(rows, notNative).Total);
    }

    [Fact]
    public void CallerTokens_ACallerNoMemberIs_IsEmpty_AndAtMost8AreKept_WithTheTotal()
    {
        var unknown = new ApiCallFinding(Capability.ProcessExecution, ApiCallKind.Call, InspectFixtures.OverloadsType, "NoSuchMethod", "System.Diagnostics.Process.Start");
        var many = new ApiCallFinding(Capability.ProcessExecution, ApiCallKind.Call, InspectFixtures.OverloadsType, "Many", "System.Diagnostics.Process.Start");

        var rows = Write(f => f with { Report = f.Report! with { Findings = [unknown, many] } });

        Assert.Equal((0, 0), (Found(rows, unknown).Tokens.Count, Found(rows, unknown).Total));
        Assert.Equal(3, Found(rows, many, 3).Tokens.Count);
        Assert.Equal(InspectFixtures.ManyParameterTypes.Length, Found(rows, many, 3).Total);
        // Each finding keeps at most 8, whatever is asked for; the total is beside them.
        Assert.Equal(8, Found(rows, many, 100).Tokens.Count);
        Assert.Equal(InspectFixtures.ManyParameterTypes.Length, Found(rows, many, 100).Total);
        Assert.Null(rows.CallerTokens(new object(), 8));
    }

    /// <summary>
    /// An assembly whose file cannot be loaded is counted notRead and has no rows. Its findings were not walked, so they have
    /// no answer at all (null), and <see cref="PackageFindings.Write"/> leaves their callerTokens out rather than say [].
    /// </summary>
    [Fact]
    public void Write_AnAssemblyThatCannotBeLoaded_IsNotRead_AndItsFindingsHaveNoCallerTokensKey()
    {
        var scan = Scan();
        // Its own finding instances: tokens are kept per finding object.
        var gone = scan with
        {
            Assembly = scan.Assembly with { FullPath = Path.Combine(dir, "gone.dll"), RelativePath = "lib/net8.0/Gone.dll" },
            Report = scan.Report! with { Findings = [.. scan.Report!.Findings.Select(f => f with { })] },
            Indicators = null,
            Obfuscation = null,
        };
        var report = Report() with { Assemblies = [scan, gone] };
        var paths = Paths(report);

        var rows = MemberRows.Write(dir, report, paths);

        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"assemblies":2,"read":1,"notRead":1,"methodsUnreadable":1}"""), rows.Members["pass"]));
        Assert.True(JsonNode.DeepEquals(rows.Members["pass"], rows.Strings["pass"]));
        Assert.Equal(InspectFixtures.MethodCount, rows.Members["rows"]!.GetValue<int>());
        Assert.All(Drill.Lines(dir, JobProtocol.MembersFile), r => Assert.Equal(InspectFixtures.FixtureDll, Drill.U(r, "assembly")));
        Assert.All(gone.Report!.Findings, f => Assert.Null(rows.CallerTokens(f, 8)));
        Assert.All(scan.Report!.Findings, f => Assert.True(Found(rows, f).Total > 0, $"{f.CallerMethod}: no tokens"));

        var findings = Directory.CreateDirectory(Path.Combine(dir, "findings")).FullName;
        PackageFindings.Write(findings, report, new HashSet<IndicatorCategory>(), paths, [], rows);
        var capabilities = Drill.Lines(findings, "findings-capabilities.jsonl");
        var goneRows = capabilities.Where(r => Drill.U(r, "assembly")!.EndsWith("Gone.dll", StringComparison.Ordinal)).ToList();
        Assert.Equal(gone.Report!.Findings.Count, goneRows.Count);
        Assert.All(goneRows, r => Assert.False(r.AsObject().ContainsKey("callerTokens") || r.AsObject().ContainsKey("callerTokensTotal"), r.ToJsonString()));
        var walked = capabilities.Except(goneRows).ToList();
        Assert.Equal(scan.Report!.Findings.Count, walked.Count);
        Assert.All(walked, r => Assert.True(r["callerTokens"] is JsonArray { Count: > 0 }, r.ToJsonString()));
    }

    [Fact]
    public void Write_EveryRow_IsWithinTheRowBound_AndMatchesTheIndex()
    {
        var rows = Write();

        var members = Drill.Lines(dir, JobProtocol.MembersFile);
        var strings = Drill.Lines(dir, JobProtocol.StringsFile);
        Assert.Equal(rows.Members["rows"]!.GetValue<int>(), members.Count);
        Assert.Equal(rows.Strings["rows"]!.GetValue<int>(), strings.Count);
        Assert.False(rows.Members["truncated"]!.GetValue<bool>());
        Assert.All(members.Concat(strings), r => Assert.True(RowFile.Chars(r) <= RowWriter.MaxRowChars));
        Assert.Equal(members.Select(m => Drill.Str(m["token"])).Order(StringComparer.Ordinal), members.Select(m => Drill.Str(m["token"])));
    }

    [Fact]
    public void PackageFindings_WithoutMembers_HasNoCallerTokens_AndWithThemEveryPerAssemblyRowHas()
    {
        var report = Report();
        var paths = Paths(report);
        var without = Directory.CreateDirectory(Path.Combine(dir, "without")).FullName;
        var with = Directory.CreateDirectory(Path.Combine(dir, "with")).FullName;

        PackageFindings.Write(without, report, new HashSet<IndicatorCategory>(), paths, []);
        PackageFindings.Write(with, report, new HashSet<IndicatorCategory>(), paths, [], MemberRows.Write(with, report, paths));

        foreach (var kind in new[] { "capabilities", "indicators", "hidden-content" })
        {
            var bare = Drill.Lines(without, $"findings-{kind}.jsonl");
            var tokened = Drill.Lines(with, $"findings-{kind}.jsonl");
            Assert.NotEmpty(bare);
            Assert.Equal(bare.Count, tokened.Count);
            Assert.All(bare, r => Assert.False(r.AsObject().ContainsKey("callerTokens") || r.AsObject().ContainsKey("callerTokensTotal"), r.ToJsonString()));
            foreach (var (b, t) in bare.Zip(tokened))
            {
                Assert.True(t["callerTokens"] is JsonArray, t.ToJsonString());
                var stripped = (JsonObject)t.DeepClone();
                stripped.Remove("callerTokens");
                stripped.Remove("callerTokensTotal");
                Assert.True(JsonNode.DeepEquals(b, stripped), $"{kind}: the tokens changed the row:\n{b.ToJsonString()}\n{t.ToJsonString()}");
            }
        }
    }

    /// <summary>
    /// The worst case for a member row (S2 review C1, as the S2 bounds tests do): a type and method of 600 Cyrillic chars
    /// (six chars each as served) and a 3,000-char Cyrillic constant. Every row fits, and the filter keys (<c>assembly</c>,
    /// <c>type</c>) are whole.
    /// </summary>
    [Fact]
    public void Write_WorstCaseNames_FitTheRowBound_WithTheFilterKeysWhole()
    {
        var (rows, served, wideType) = WriteWide("lib/net8.0/Drill.Wide.dll");

        AssertWideRowsWhole(rows, served, wideType);
    }

    /// <summary>
    /// The same, at the inventory's path bound: a 512-char CJK assembly path (as S2's bounds tests use) beside the 512-char
    /// Cyrillic type. Both are filter keys, so neither may be cut; the row must still be listed, or list_members' assembly
    /// filter silently loses that method.
    /// </summary>
    [Fact]
    public void Write_AWorstCaseTypeInAWorstCasePath_IsStillListed_WithTheFilterKeysWhole()
    {
        var (rows, served, wideType) = WriteWide(DrillFixtures.LongCjk(509) + "000");

        AssertWideRowsWhole(rows, served, wideType);
    }

    public void Dispose()
    {
        try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
    #endregion

    #region Methods: helpers
    // The entry's report, each assembly's FullPath moved to the entry: the report names the job's temporary directory, which
    // was renamed into the entry when the job committed.
    private PackageCapabilityReport Report()
    {
        var report = PackageCapabilityReport.FromJson(File.ReadAllText(Path.Combine(fixture.EntryDir, JobProtocol.ReportFile)))!;
        var files = Path.Combine(fixture.EntryDir, JobProtocol.FilesDir, JobProtocol.PackageFile);
        return report with
        {
            Assemblies = [.. report.Assemblies.Select(a => a.NotInventoried ? a
                : a with { Assembly = a.Assembly with { FullPath = Path.Combine(files, a.Assembly.RelativePath.Replace('/', Path.DirectorySeparatorChar)) } })],
        };
    }

    private AssemblyScanResult Scan() => Assert.Single(Report().Assemblies, a => a.Assembly.RelativePath == InspectFixtures.FixtureDll);

    private static PackagePaths Paths(PackageCapabilityReport report)
    {
        var paths = new PackagePaths();
        foreach (var a in report.Assemblies.Where(a => a.Assembly.FullPath.Length > 0))
            paths.Add(a.Assembly.FullPath, a.Assembly.RelativePath, a.Assembly.RelativePath);
        return paths;
    }

    // The members walk of the fixture assembly alone, changed by `change`.
    private MemberRows Write(Func<AssemblyScanResult, AssemblyScanResult>? change = null)
    {
        var report = Report() with { Assemblies = [(change ?? (a => a))(Scan())] };
        return MemberRows.Write(dir, report, Paths(report));
    }

    private string Token(string name, string idEnd) => fixture.Token(InspectFixtures.OverloadsType, name, idEnd);

    private static List<string> Tokens((JsonArray Tokens, int Total)? found) => [.. Assert.NotNull(found).Tokens.Select(t => t!.GetValue<string>())];

    // The caller tokens of a finding of a walked assembly: never null.
    private static (JsonArray Tokens, int Total) Found(MemberRows rows, object finding, int max = 8) => Assert.NotNull(rows.CallerTokens(finding, max));

    // The S2 drill assembly (its Wide type and method are 600 Cyrillic chars) as the only assembly, served at `served`.
    private (MemberRows Rows, string Served, string WideType) WriteWide(string served)
    {
        var path = Path.Combine(dir, "Drill.Wide.dll");
        File.WriteAllBytes(path, DrillFixtures.Assembly(3, "Drill.Wide"));
        var scan = Scan();
        var wide = new AssemblyScanResult(scan.Assembly with { FullPath = path, RelativePath = "lib/net8.0/Drill.Wide.dll" },
            scan.Report! with { Findings = [], AssemblyPath = path }, null, null, null, null);
        var report = Report() with { Assemblies = [wide] };
        var paths = new PackagePaths();
        paths.Add(path, wide.Assembly.RelativePath, served);
        return (MemberRows.Write(dir, report, paths), served, "Wide" + DrillFixtures.LongNonAscii(600));
    }

    private void AssertWideRowsWhole(MemberRows rows, string served, string wideType)
    {
        Assert.False(rows.Members.ContainsKey("unfitted"), $"member rows were dropped: {rows.Members.ToJsonString()}");
        Assert.False(rows.Strings.ContainsKey("unfitted"), $"string rows were dropped: {rows.Strings.ToJsonString()}");
        var members = Drill.Lines(dir, JobProtocol.MembersFile);
        var strings = Drill.Lines(dir, JobProtocol.StringsFile);
        Assert.All(members.Concat(strings), r =>
        {
            Assert.True(RowFile.Chars(r) <= RowWriter.MaxRowChars, $"a row of {RowFile.Chars(r)} chars");
            Assert.Equal(served, Drill.U(r, "assembly"));
        });
        // A member row's type is bounded at 256 (as reachability folder names are), so it and a whole path always fit.
        var type = ToolEnvelope.Escaped(wideType, 256);
        Assert.True(type.Length < wideType.Length, "the wide type was not cut at its bound");
        var row = Assert.Single(members, r => Drill.U(r, "type") == type);
        Assert.StartsWith("Wide", Drill.U(row, "name"));
        Assert.Contains(strings, r => Drill.U(r, "value")!.StartsWith("http://wide.example/", StringComparison.Ordinal));
    }
    #endregion

    #region Fields
    private readonly string dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "members-" + Guid.NewGuid().ToString("N"))).FullName;
    #endregion
}
