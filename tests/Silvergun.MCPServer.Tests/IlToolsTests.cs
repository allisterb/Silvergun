namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

using ModelContextProtocol.Protocol;

using Silvergun.CodeAnalysis.IL;
using Silvergun.MCPServer.Jobs;

/// <summary>
/// The S3 tools over <see cref="InspectFixture"/>'s completed entry (task S3), in-process, with <c>disassemble</c> running
/// a real <c>__worker inspect</c> child per call: <c>list_members</c> and <c>search_strings</c> page every row exactly once,
/// filter, and carry their pass; <c>disassemble</c> lists exactly what <see cref="MethodListing"/> lists, follows a finding's
/// caller tokens, pages a long method, and refuses bad tokens, offsets and paths as values; every result passes
/// <see cref="Drill.Checked"/>. Nothing here changes the entry.
/// </summary>
[Collection(InspectCollection.Name)]
public sealed class IlToolsTests(InspectFixture fixture)
{
    #region Methods
    // ---- list_members ----

    [Fact]
    public void ListMembers_PagesEveryRowExactlyOnce_WithoutAssembly_AndThePassBesideTheRows()
    {
        var (rows, pages, last) = Drill.PageAll(c => fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.FixtureDll, cursor: c));

        var expected = Served(fixture.Members());
        Drill.SameRows(expected, rows, "list_members");
        Assert.True(pages >= 2, $"{rows.Count} rows in {pages} page(s)");
        Assert.Equal(InspectFixtures.MethodCount, rows.Count);
        Assert.All(rows, r => Assert.False(r.AsObject().ContainsKey("assembly") || r.AsObject().ContainsKey("pathForm"), r.ToJsonString()));
        var index = Index()["members"]!;
        Assert.Equal(index["rows"]!.GetValue<int>(), last.GetProperty("total").GetInt32());
        Assert.True(JsonNode.DeepEquals(index["pass"], JsonNode.Parse(last.GetProperty("pass").GetRawText())), last.GetProperty("pass").ToString());
        // The two assemblies the capability pass read (the unloadable one has no capability report, so it is not counted); one
        // body unreadable.
        var pass = last.GetProperty("pass");
        Assert.Equal((2, 2, 0, 1),(pass.GetProperty("assemblies").GetInt32(), pass.GetProperty("read").GetInt32(), pass.GetProperty("notRead").GetInt32(),
            pass.GetProperty("methodsUnreadable").GetInt32()));
        Assert.False(pass.TryGetProperty("assembliesNotWhole", out _));
    }

    [Fact]
    public void ListMembers_EveryPage_CarriesThePass()
    {
        string? cursor = null;
        do
        {
            var s = Drill.S(Drill.Checked(fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.FixtureDll, cursor: cursor)));
            Assert.Equal(JsonValueKind.Object, s.GetProperty("pass").ValueKind);
            cursor = s.TryGetProperty("next", out var next) ? next.GetString() : null;
        }
        while (cursor is not null);
    }

    [Theory]
    [InlineData("overloads", 18)]
    [InlineData("INSPECT.LISTING", 7)]
    [InlineData("Special", 9)]
    [InlineData("nope", 0)]
    [InlineData("LongLLL", 1)]
    public void ListMembers_TypePattern_IsACaseInsensitiveSubstringOfTheServedType(string pattern, int count)
    {
        var (rows, _, last) = Drill.PageAll(c => fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.FixtureDll, pattern, c));

        var expected = Served(fixture.Members().Where(r => Drill.U(r, "type")!.Contains(pattern, StringComparison.OrdinalIgnoreCase)));
        Drill.SameRows(expected, rows, $"typePattern {pattern}");
        Assert.Equal(count, rows.Count);
        // total is the whole list's, every assembly's rows, before filters.
        Assert.Equal(Index()["members"]!["rows"]!.GetValue<int>(), last.GetProperty("total").GetInt32());
    }

    [Fact]
    public void ListMembers_AnotherAssemblysPath_HasNoRows()
    {
        foreach (var path in new[] { InspectFixtures.BrokenDll, "lib/net8.0/nope.dll", InspectFixtures.FixtureDll.ToUpperInvariant() })
        {
            var (rows, _, _) = Drill.PageAll(c => fixture.Tools.ListMembers(fixture.JobId, path, cursor: c));
            Assert.Empty(rows);
        }
    }

    public static TheoryData<string, string, string?, string> MemberFacts() => new()
    {
        { InspectFixtures.OverloadsType, "Go", "(System.Int32)", """{"visibility":"public","static":true,"body":"il","ilBytes":12,"capabilities":{"processExecution":1}}""" },
        { InspectFixtures.OverloadsType, "Go", "(System.String)", """{"visibility":"public","static":true,"body":"il","ilBytes":12,"capabilities":{"fileSystem":1}}""" },
        { InspectFixtures.OverloadsType, "Twin", "(System.String)", """{"visibility":"public","static":true,"body":"il","ilBytes":12,"capabilities":{"processExecution":1}}""" },
        { InspectFixtures.OverloadsType, "Host", "(System.Int32)", """{"visibility":"public","static":true,"body":"il","ilBytes":6,"indicators":1}""" },
        { InspectFixtures.OverloadsType, "Blob", "(System.String)", """{"visibility":"public","static":true,"body":"il","ilBytes":6,"hiddenContent":1}""" },
        { InspectFixtures.SpecialType, "Beep", null, """{"visibility":"public","static":true,"special":"pinvoke","body":"none","ilBytes":0,"capabilities":{"nativeInterop":1}}""" },
        { InspectFixtures.SpecialType, "Exported", null, """{"visibility":"public","static":true,"special":"nativeExport","body":"il","ilBytes":2,"capabilities":{"nativeInterop":1}}""" },
        { InspectFixtures.SpecialType, ".ctor", null, """{"visibility":"public","special":"constructor","body":"il","ilBytes":7}""" },
        { InspectFixtures.SpecialType, ".cctor", null, """{"visibility":"private","static":true,"special":"typeInitializer","body":"il","ilBytes":1}""" },
        { InspectFixtures.SpecialType, "Finalize", "Finalize()", """{"visibility":"family","virtual":true,"special":"finalizer","body":"il","ilBytes":1}""" },
        { InspectFixtures.ShapeType, "Area", null, """{"visibility":"public","virtual":true,"abstract":true,"body":"none","ilBytes":0}""" },
        { InspectFixtures.BodiesType, "Broken", null, """{"visibility":"public","static":true,"body":"unreadable","ilBytes":0}""" },
        { InspectFixtures.ListingType, "Sample", null, """{"visibility":"public","static":true,"body":"il","ilBytes":31}""" },
    };

    /// <summary>A row's facts, flags present only when true and counts only when nonzero: everything but token, type, name and id, exactly.</summary>
    [Theory]
    [MemberData(nameof(MemberFacts))]
    public void ListMembers_ARowsFacts_AreExact(string type, string name, string? idEnd, string facts)
    {
        var rows = Drill.PageAll(c => fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.FixtureDll, type, c)).Rows;

        var row = Assert.Single(rows, r => Drill.U(r, "type") == type && Drill.U(r, "name") == name && (idEnd is null || Drill.U(r, "id")!.EndsWith(idEnd, StringComparison.Ordinal))).AsObject();
        Assert.Matches("^0x06[0-9a-f]{6}$", Drill.Str(row["token"]));
        Assert.StartsWith(type + ".", Drill.U(row, "id"));
        var rest = (JsonObject)row.DeepClone();
        foreach (var key in new[] { "token", "type", "name", "id" })
            rest.Remove(key);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(facts), rest), $"{type}::{name}: {rest.ToJsonString()}");
    }

    [Fact]
    public void ListMembers_ACursorFromAnotherQuery_IsInvalidArgument()
    {
        var cursor = Drill.S(Drill.Checked(fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.FixtureDll))).GetProperty("next").GetString()!;

        foreach (var call in new Func<CallToolResult>[]
        {
            () => fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.FixtureDll, "Inspect", cursor),
            () => fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.BrokenDll, cursor: cursor),
            () => fixture.Tools.SearchStrings(fixture.JobId, InspectFixtures.FixtureDll, cursor: cursor),
            () => fixture.Tools.ListFiles(fixture.JobId, cursor: cursor),
        })
            Assert.Equal("InvalidArgument", Drill.Status(Drill.Checked(call())));
    }

    [Theory]
    [InlineData("")]
    [InlineData("long")]
    public void ListMembers_AnEmptyOrOverlongArgument_IsInvalidArgument(string what)
    {
        var result = Drill.Checked(what == "long"
            ? fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.FixtureDll, new string('t', 2_100))
            : fixture.Tools.ListMembers(fixture.JobId, what));

        Assert.Equal("InvalidArgument", Drill.Status(result));
    }

    // ---- search_strings ----

    [Theory]
    [InlineData(null, "line ")]
    [InlineData(InspectFixtures.FixtureDll, null)]
    [InlineData(null, "LINE 07")]
    [InlineData(null, "alpha.EXAMPLE")]
    [InlineData(InspectFixtures.BrokenDll, null)]
    [InlineData(null, "nothing has this")]
    public void SearchStrings_PagesEveryMatchOnce_AndTotalStaysUnfiltered(string? assembly, string? contains)
    {
        var (rows, pages, last) = Drill.PageAll(c => fixture.Tools.SearchStrings(fixture.JobId, assembly, contains, c));

        var all = Drill.Lines(fixture.EntryDir, JobProtocol.StringsFile);
        var expected = all.Where(r => (assembly is null || Drill.U(r, "assembly") == assembly)
            && (contains is null || Drill.U(r, "value")!.Contains(contains, StringComparison.OrdinalIgnoreCase))).ToList();
        Drill.SameRows(expected, rows, $"search_strings {assembly} {contains}");
        Assert.Equal(all.Count, last.GetProperty("total").GetInt32());
        Assert.True(JsonNode.DeepEquals(Index()["strings"]!["pass"], JsonNode.Parse(last.GetProperty("pass").GetRawText())));
        if (contains is "line " || (assembly is not null && contains is null && assembly == InspectFixtures.FixtureDll))
        {
            Assert.True(pages >= 5, $"{rows.Count} rows in {pages} page(s)");
            Assert.True(rows.Count >= InspectFixtures.LongPairs);
        }
        if (contains == "LINE 07")
            Assert.Equal(100, rows.Count);   // line 0700 .. line 0799
        if (contains == "alpha.EXAMPLE")
            Assert.Equal(fixture.Token(InspectFixtures.OverloadsType, "Host", "System.Int32"), Drill.Str(Assert.Single(rows)["callerToken"]));
    }

    [Fact]
    public void SearchStrings_ARow_IsTheDistinctConstantWithItsCallerFirstOffsetAndOccurrences()
    {
        var rows = Drill.PageAll(c => fixture.Tools.SearchStrings(fixture.JobId, InspectFixtures.FixtureDll, cursor: c)).Rows;
        var token = fixture.Token(InspectFixtures.ListingType, "Strings");

        var mine = rows.Where(r => Drill.Str(r["callerToken"]) == token).ToList();

        Assert.Equal(2, mine.Count);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse($$"""
            {"assembly":{"untrusted":"lib/net8.0/Inspect.Fixture.dll"},"value":{"untrusted":"a"},"length":1,"callerToken":"{{token}}","callerType":{"untrusted":"Inspect.Listing"},"callerMethod":{"untrusted":"Strings"},"offset":0,"occurrences":3}
            """), mine[0]), mine[0].ToJsonString());
        Assert.Equal((6, 1), (mine[1]["offset"]!.GetValue<int>(), mine[1]["occurrences"]!.GetValue<int>()));
        // Every caller token is a listed member's.
        var tokens = fixture.Members().Select(m => Drill.Str(m["token"])).ToHashSet();
        Assert.All(rows, r => Assert.Contains(Drill.Str(r["callerToken"]), tokens));
    }

    [Fact]
    public void SearchStrings_AValueIsCutAt1024_AndLengthIsTheWhole()
    {
        var big = Assert.Single(Drill.PageAll(c => fixture.Tools.SearchStrings(fixture.JobId, contains: "zzzz", cursor: c)).Rows);

        Assert.Equal(InspectFixtures.HugeConstant.Length, big["length"]!.GetValue<int>());
        Assert.Equal(ToolEnvelope.Escaped(InspectFixtures.HugeConstant, 1024), Drill.U(big, "value"));
        Assert.StartsWith(new string('z', 1024), Drill.U(big, "value"));
        Assert.Contains("sha256:", Drill.U(big, "value"));

        // A constant of exactly 1,024 chars (768 bytes of base64) is whole.
        var rows = Drill.PageAll(c => fixture.Tools.SearchStrings(fixture.JobId, contains: "TVqQ", cursor: c)).Rows;
        var blob = Assert.Single(rows, r => r["length"]!.GetValue<int>() == 1024);
        Assert.Equal(1024, Drill.U(blob, "value")!.Length);
        Assert.Contains(rows, r => r["length"]!.GetValue<int>() == 512 && Drill.U(r, "value")!.Length == 512);
    }

    // ---- disassemble ----

    /// <summary>Accept, end to end: the fenced listing from the inspect child is exactly the in-process listing of the same file.</summary>
    [Fact]
    public void Disassemble_TheSampleMethod_IsExactlyTheInProcessListing_Fenced()
    {
        var token = fixture.Token(InspectFixtures.ListingType, "Sample");

        var result = Disassemble(token);

        var s = Drill.S(result);
        Assert.Equal("Succeeded", Drill.Status(result));
        using (var assembly = InspectFixtures.Load(EntryFile(InspectFixtures.FixtureDll)))
        {
            var page = MethodListing.Render(assembly, uint.Parse(token[2..], System.Globalization.NumberStyles.HexNumber), 0, McpLimits.BulkBudgetChars * 4 / 5, InspectFixtures.Display);
            Assert.Equal(UntrustedFence.Neutralize(page.Text), Drill.Inner(result));
        }
        Assert.StartsWith(".method Inspect.Listing.Sample(System.Int32)  // token 0x06000002\n", Drill.Inner(result));
        Assert.EndsWith("\n.try IL_0000 to IL_0015 catch [0x01000005] System.Exception handler IL_0015 to IL_001d", Drill.Inner(result));
        Assert.Equal(token, s.GetProperty("token").GetString());
        Assert.Equal(InspectFixtures.FixtureDll, s.GetProperty("assembly").GetProperty("untrusted").GetString());
        // The names are in the listing's header line (above), not repeated in the data (S3 review W2).
        foreach (var key in new[] { "type", "name", "id" })
            Assert.False(s.TryGetProperty(key, out _), $"the data carries {key}");
        Assert.False(s.TryGetProperty("handlersNotShown", out _));
        Assert.Equal(("il", 31, 2, 1, 14, 14, 0), (s.GetProperty("body").GetString(), s.GetProperty("ilBytes").GetInt32(), s.GetProperty("maxStack").GetInt32(),
            s.GetProperty("locals").GetInt32(), s.GetProperty("instructions").GetInt32(), s.GetProperty("shown").GetInt32(), s.GetProperty("offset").GetInt32()));
        Assert.False(s.GetProperty("truncated").GetBoolean());
        Assert.False(s.TryGetProperty("next", out _));
        Assert.False(s.TryGetProperty("readerAssertions", out _));
        Assert.Equal(Drill.Inner(result).Length, s.GetProperty("content").GetProperty("chars").GetInt32());
    }

    [Fact]
    public void Disassemble_ALongMethod_PagesByNext_EveryInstructionOnce()
    {
        var token = fixture.Token(InspectFixtures.ListingType, "Long");
        var lines = new List<string>();
        long offset = 0;
        var pages = 0;

        while (true)
        {
            var result = Disassemble(token, offset);
            var s = Drill.S(result);
            Assert.Equal(offset, s.GetProperty("offset").GetInt64());
            var shown = Drill.Inner(result).Split('\n').Where(l => Regex.IsMatch(l, "^IL_[0-9a-f]{4}: ")).ToList();
            Assert.Equal(s.GetProperty("shown").GetInt32(), shown.Count);
            lines.AddRange(shown);
            pages++;
            if (!s.TryGetProperty("next", out var next))
            {
                Assert.False(s.GetProperty("truncated").GetBoolean());
                break;
            }
            Assert.True(s.GetProperty("truncated").GetBoolean());
            Assert.True(next.GetInt64() > offset, $"next {next} does not move on from {offset}");
            offset = next.GetInt64();
            Assert.True(pages < 100);
        }

        Assert.Equal(2 * InspectFixtures.LongPairs + 1, lines.Count);
        Assert.Equal(lines.Count, lines.Distinct().Count());
        Assert.True(pages >= 5, $"{pages} pages");
        Assert.Equal("IL_12c0: ret", lines[^1]);
    }

    /// <summary>Every capability finding of the fixture names its callers by token, and each token's listing holds the finding's call.</summary>
    [Fact]
    public void Disassemble_FollowsEachCapabilityFindingsCallerTokens_ToTheCall()
    {
        var findings = Drill.PageAll(c => fixture.Tools.GetFindings(fixture.JobId, "capabilities", InspectFixtures.FixtureDll, cursor: c)).Rows;
        Assert.True(findings.Count >= 7, $"{findings.Count} findings");   // Broken's call is in its unreadable body

        foreach (var f in findings.Where(f => Drill.Str(f["kind"]) == "call"))
        {
            var tokens = f["callerTokens"]!.AsArray().Select(t => t!.GetValue<string>()).ToList();
            Assert.NotEmpty(tokens);
            var api = Drill.U(f, "calledApi")!;
            foreach (var token in tokens.Take(2))
            {
                var listing = Drill.Inner(Disassemble(token));
                Assert.True(listing.Split('\n').Any(l => Regex.IsMatch(l, @"^IL_[0-9a-f]{4}: call") && l.Contains(api, StringComparison.Ordinal)),
                    $"{token} ({Drill.U(f, "callerMethod")}) has no call to {api}:\n{listing}");
            }
        }
    }

    [Fact]
    public void Disassemble_ACallIntoThePackage_CanBeFollowedByItsToken()
    {
        var evil = Drill.Inner(Disassemble(HostileToken(Hostile3.MethodName), assembly: InspectFixtures.HostileDll));

        var callee = Regex.Match(evil, @"call \[(0x06[0-9a-f]{6})\]").Groups[1].Value;

        Assert.Equal(HostileToken(Hostile3.CalleeName), callee);
        Assert.Contains("callee ", Drill.Inner(Disassemble(callee, assembly: InspectFixtures.HostileDll)));
    }

    /// <summary>S3 review W4: the closing page of a method with 80 handlers serves handlersNotShown, the exact 16 past the cap of 64.</summary>
    [Fact]
    public void Disassemble_MoreThan64Handlers_ServesHandlersNotShownOnTheClosingPage()
    {
        var token = fixture.Token(InspectFixtures.GuardedType, "Guarded");
        long offset = 0;
        JsonElement last;
        var pages = 0;
        while (true)
        {
            var result = Disassemble(token, offset);
            last = Drill.S(result);
            pages++;
            if (!last.TryGetProperty("next", out var next))
            {
                Assert.EndsWith($"\n// {InspectFixtures.ManyHandlerCount - 64} more exception handlers not shown", Drill.Inner(result));
                break;
            }
            Assert.False(last.TryGetProperty("handlersNotShown", out _), "a page that does not close the listing counts handlers");
            offset = next.GetInt64();
            Assert.True(pages < 50);
        }

        Assert.Equal(InspectFixtures.ManyHandlerCount - 64, last.GetProperty("handlersNotShown").GetInt32());
    }

    [Theory]
    [InlineData("Beep", "none", "// no IL body")]
    [InlineData("Broken", "unreadable", "// the body could not be read")]
    public void Disassemble_AMethodWithNoReadableBody_IsItsHeaderAndANote(string name, string body, string note)
    {
        var type = name == "Beep" ? InspectFixtures.SpecialType : InspectFixtures.BodiesType;

        var result = Disassemble(fixture.Token(type, name));

        var s = Drill.S(result);
        Assert.Equal(body, s.GetProperty("body").GetString());
        Assert.Equal(0, s.GetProperty("shown").GetInt32());
        Assert.StartsWith(note, Drill.Inner(result).Split('\n')[1]);
    }

    public static TheoryData<string, string, long, string> BadArguments() => new()
    {
        { "fixture", "", 0, "InvalidArgument" },
        { "fixture", "garbage", 0, "InvalidArgument" },
        { "fixture", "0x02000001", 0, "InvalidArgument" },
        { "fixture", "0x0a000002", 0, "InvalidArgument" },
        { "fixture", "0x06000000", 0, "InvalidArgument" },
        { "fixture", "0x0600000g", 0, "InvalidArgument" },
        { "fixture", "0x1006000002", 0, "InvalidArgument" },
        { "fixture", "-0x06000002", 0, "InvalidArgument" },
        { "fixture", "0x06000002", -1, "InvalidArgument" },
        { "fixture", "0x06000002", 1L + uint.MaxValue, "InvalidArgument" },
        { "fixture", "0x06FFFFFF", 0, "NotFound" },
        { "fixture", "0x06000100", 0, "NotFound" },
        { "", "0x06000002", 0, "InvalidArgument" },
        { "long", "0x06000002", 0, "InvalidArgument" },
        { "lib/net8.0/nope.dll", "0x06000002", 0, "NotFound" },
        { "lib/net8.0/inspect.fixture.dll", "0x06000002", 0, "NotFound" },
        { "../job.json", "0x06000002", 0, "NotFound" },
        { "the absolute file", "0x06000002", 0, "NotFound" },
        { InspectFixtures.Readme, "0x06000002", 0, "InvalidArgument" },
        { "mcp.inspect.nuspec", "0x06000002", 0, "InvalidArgument" },
    };

    [Theory]
    [MemberData(nameof(BadArguments))]
    public void Disassemble_ABadTokenOffsetOrPath_IsAValue(string assembly, string token, long offset, string status)
    {
        assembly = assembly switch
        {
            "fixture" => InspectFixtures.FixtureDll,
            "long" => "lib/" + new string('a', 2_100),
            "the absolute file" => EntryFile(InspectFixtures.FixtureDll),
            _ => assembly,
        };

        var result = Drill.Checked(Call(assembly, token, offset));

        Assert.True(Drill.Status(result) == status, $"{assembly} {token} {offset}: {Drill.S(result)}");
        Assert.True(result.IsError);
        Assert.False(Drill.S(result).GetProperty("retry").GetBoolean());
        Assert.Null(Drill.Bulk(result));
        Assert.True(Directory.Exists(fixture.EntryDir), "a refusal discarded the entry");
    }

    /// <summary>
    /// An offset past the method's IL is a bad offset, as it is for read_file: it must not be served as a page (it would show
    /// the header and the handlers, with no instruction, as if the method ended there).
    /// </summary>
    [Fact]
    public void Disassemble_AnOffsetPastTheIlSize_IsInvalidArgument()
    {
        var token = fixture.Token(InspectFixtures.ListingType, "Sample");
        Assert.Equal("Succeeded", Drill.Status(Disassemble(token, 31)));   // the IL size itself: the handlers' page

        var result = Drill.Checked(Call(InspectFixtures.FixtureDll, token, 32));

        Assert.True(Drill.Status(result) == "InvalidArgument", $"offset 32 of a 31-byte method: {Drill.S(result)}\n{Drill.Bulk(result)}");
        Assert.Equal("offset is past the end of the method's IL, which is 31 bytes", Drill.S(result).GetProperty("message").GetString());
        Assert.Null(Drill.Bulk(result));
        Assert.Equal("InvalidArgument", Drill.Status(Drill.Checked(Call(InspectFixtures.FixtureDll, token, uint.MaxValue))));
    }

    /// <summary>Accept: a fixture that crashes the reader (an unloadable .dll the job listed as an assembly) is isError with an escaped reason.</summary>
    [Fact]
    public void Disassemble_AFileTheReaderCannotLoad_IsFailed_AndTheServerKeepsServing()
    {
        var kind = Drill.Str(Assert.Single(Drill.Lines(fixture.EntryDir, JobProtocol.InventoryFile), r => Drill.U(r, "path") == InspectFixtures.BrokenDll)["kind"]);
        Assert.Equal("assembly", kind);

        var result = Drill.Checked(Call(InspectFixtures.BrokenDll, "0x06000001"));

        Assert.True(result.IsError);
        Assert.Equal("Failed", Drill.Status(result));
        // The child's words are untrusted (D10): a fixed message, and the child's text in reason.
        Assert.Equal(FailedMessage, Drill.S(result).GetProperty("message").GetString());
        var reason = Drill.S(result).GetProperty("reason").GetProperty("untrusted").GetString()!;
        Assert.Contains("could not be loaded", reason);
        Assert.DoesNotContain(fixture.CacheDir, reason, StringComparison.OrdinalIgnoreCase);
        Assert.Null(Drill.Bulk(result));
        Assert.Equal("Succeeded", Drill.Status(Disassemble(fixture.Token(InspectFixtures.ListingType, "Sample"))));
    }

    [Fact]
    public void Disassemble_TheDecimalFormOfAToken_IsTheSameMethod()
    {
        var token = fixture.Token(InspectFixtures.ListingType, "Sample");

        var result = Drill.Checked(Call(InspectFixtures.FixtureDll, Convert.ToUInt32(token, 16).ToString()));

        Assert.Equal(token, Drill.S(result).GetProperty("token").GetString());
    }

    [Fact]
    public void AnUnknownOrMalformedJob_IsAValue_ForEveryS3Tool()
    {
        var unknown = new string('0', 64) + "-standard";
        foreach (var (job, status) in new[] { (unknown, "NotFound"), ("nope", "InvalidArgument"), (fixture.JobId + "\n", "InvalidArgument") })
        {
            Assert.Equal(status, Drill.Status(Drill.Checked(fixture.Tools.ListMembers(job, InspectFixtures.FixtureDll))));
            Assert.Equal(status, Drill.Status(Drill.Checked(fixture.Tools.SearchStrings(job))));
            Assert.Equal(status, Drill.Status(Drill.Checked(Call(InspectFixtures.FixtureDll, "0x06000002", job: job))));
        }
    }

    // ---- caller tokens, from the real job ----

    [Fact]
    public void CallerTokens_OverloadsAreNarrowedByTheirEvidence()
    {
        var capabilities = Findings("capabilities");

        Assert.Equal([fixture.Token(InspectFixtures.OverloadsType, "Go", "System.Int32")],
            Tokens(Assert.Single(capabilities, f => Drill.U(f, "callerMethod") == "Go" && Drill.Str(f["capability"]) == "processExecution")));
        Assert.Equal([fixture.Token(InspectFixtures.OverloadsType, "Go", "System.String")],
            Tokens(Assert.Single(capabilities, f => Drill.U(f, "callerMethod") == "Go" && Drill.Str(f["capability"]) == "fileSystem")));
        Assert.Equal([fixture.Token(InspectFixtures.SpecialType, "Beep")], Tokens(Assert.Single(capabilities, f => Drill.U(f, "callerMethod") == "Beep")));
        Assert.Equal([fixture.Token(InspectFixtures.SpecialType, "Exported")], Tokens(Assert.Single(capabilities, f => Drill.U(f, "callerMethod") == "Exported")));

        var indicators = Findings("indicators");
        foreach (var (host, parameter) in new[] { ("alpha.example", "System.Int32"), ("beta.example", "System.String") })
            Assert.Equal([fixture.Token(InspectFixtures.OverloadsType, "Host", parameter)], Tokens(Assert.Single(indicators, f => Drill.U(f, "value") == host)));

        var blobs = Findings("hidden-content").Where(f => Drill.U(f, "callerMethod") == "Blob").ToList();
        Assert.Equal(2, blobs.Count);
        Assert.Equal([fixture.Token(InspectFixtures.OverloadsType, "Blob", "System.Int32")], Tokens(Assert.Single(blobs, b => b["encodedLength"]!.GetValue<int>() == 512)));
        Assert.Equal([fixture.Token(InspectFixtures.OverloadsType, "Blob", "System.String")], Tokens(Assert.Single(blobs, b => b["encodedLength"]!.GetValue<int>() == 1024)));
    }

    [Fact]
    public void CallerTokens_AnAmbiguousPair_ListsBoth()
    {
        var twin = Assert.Single(Findings("capabilities"), f => Drill.U(f, "callerMethod") == "Twin");

        Assert.Equal([fixture.Token(InspectFixtures.OverloadsType, "Twin", "System.Int32"), fixture.Token(InspectFixtures.OverloadsType, "Twin", "System.String")], Tokens(twin));
        Assert.False(twin.AsObject().ContainsKey("callerTokensTotal"));
    }

    [Fact]
    public void CallerTokens_MoreThan8Overloads_Are8_WithTheTotalBeside()
    {
        var many = Assert.Single(Findings("capabilities"), f => Drill.U(f, "callerMethod") == "Many");

        var tokens = Tokens(many);
        Assert.Equal(8, tokens.Count);
        Assert.Equal(InspectFixtures.ManyParameterTypes.Length, many["callerTokensTotal"]!.GetValue<int>());
        var all = fixture.Members().Where(m => Drill.U(m, "name") == "Many").Select(m => Drill.Str(m["token"])!).ToList();
        Assert.Equal(all.Take(8), tokens);
    }

    [Fact]
    public void CallerTokens_AreOnEveryPerAssemblyFindingRow_AndNameListedMembers()
    {
        var members = fixture.Members().Select(m => Drill.Str(m["token"])).ToHashSet();
        foreach (var kind in new[] { "capabilities", "indicators", "hidden-content" })
            foreach (var f in Findings(kind))
            {
                Assert.True(f["callerTokens"] is JsonArray, $"{kind}: a row without callerTokens: {f.ToJsonString()}");
                Assert.All(Tokens(f), t => Assert.Contains(t, members));
            }
        foreach (var kind in new[] { "scripts", "yara", "native", "anomalies", "vulnerabilities" })
            Assert.All(Drill.Lines(fixture.EntryDir, $"findings-{kind}.jsonl"), f => Assert.False(f.AsObject().ContainsKey("callerTokens")));
    }

    // ---- the untrusted contract (S3 Accept, D6) ----

    /// <summary>
    /// Hostile type and method names in members rows are wrapped, and are what <see cref="ToolEnvelope.Escaped"/> makes of
    /// them: the bidi override, zero-width space, newline, Tag char, U+061C and the variation selectors are escapes, and no
    /// forged fence opens. The type is bounded at 256 chars. The JSON text block is ASCII.
    /// </summary>
    [Fact]
    public void HostileNames_InMembersRows_AreWrapped_AsTheEscaperWritesThem()
    {
        var result = fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.HostileDll);

        var rows = Drill.S(result).GetProperty("rows").EnumerateArray().Select(r => JsonNode.Parse(r.GetRawText())!).ToList();
        Assert.Equal(2, rows.Count);
        Assert.False(Drill.S(result).GetProperty("truncated").GetBoolean());
        Assert.True(Assert.IsType<TextContentBlock>(result.Content[0]).Text.All(c => c < 0x80), "the JSON text block is not ASCII");
        Assert.All(rows, r => Assert.Equal(EscapedType(Hostile3.TypeName), Drill.U(r, "type")));
        var evil = Assert.Single(rows, r => Drill.U(r, "name") == Escaped(Hostile3.MethodName));
        Assert.Contains(Backslash + "n<<<UNTRUSTED nonce=ffffffffffffffff>>>", Drill.U(evil, "name"));
        foreach (var escape in new[] { "u202e", "u200b", "U000E0041", "n" })
            Assert.Contains(Backslash + escape, Drill.U(evil, "type"));
        Assert.DoesNotContain('\n', Drill.U(evil, "id")!);
        Assert.Equal(Escaped(Hostile3.TypeName) + "." + Escaped(Hostile3.MethodName) + "()", Drill.U(evil, "id"));
        // U+061C and both variation selector blocks are escapes too (ToolEnvelope.Escaped).
        foreach (var escape in new[] { "u061c", "ufe0f", "U000E0100" })
            Assert.Contains(Backslash + escape, Drill.U(evil, "type"));
    }

    [Fact]
    public void HostileConstants_InStringsRows_AreWrapped_AsTheEscaperWritesThem()
    {
        var result = fixture.Tools.SearchStrings(fixture.JobId, InspectFixtures.HostileDll, "cmd.exe /c");

        var row = JsonNode.Parse(Assert.Single(Drill.S(result).GetProperty("rows").EnumerateArray()).GetRawText())!;
        Assert.True(Assert.IsType<TextContentBlock>(result.Content[0]).Text.All(c => c < 0x80), "the JSON text block is not ASCII");
        Assert.Equal(ToolEnvelope.Escaped("cmd.exe /c " + Hostile3.Mix, 1024), Drill.U(row, "value"));
        Assert.Equal(Escaped(Hostile3.TypeName), Drill.U(row, "callerType"));
        Assert.Equal(Escaped(Hostile3.MethodName), Drill.U(row, "callerMethod"));
        Assert.Equal(("cmd.exe /c " + Hostile3.Mix).Length, row["length"]!.GetValue<int>());
    }

    /// <summary>
    /// S3 task, item 6: hostile names and constants "must come out escaped and wrapped in members and strings rows", U+061C
    /// and the variation selectors included. Every page passes <see cref="Drill.Checked"/> (no raw astral char in any served
    /// string), and every untrusted value is displayable by the server's own check, in members, strings and the same
    /// assembly's finding rows. Before <see cref="ToolEnvelope.Escaped"/> (S2 review W5's gap) U+E0100 arrived as a raw
    /// surrogate pair, and U+061C and U+FE0F raw.
    /// </summary>
    [Fact]
    public void HostileText_InMembersAndStringsRows_HasNoRawInvisibleCodePoint()
    {
        var members = Drill.PageAll(c => fixture.Tools.ListMembers(fixture.JobId, InspectFixtures.HostileDll, cursor: c)).Rows;
        var strings = Drill.PageAll(c => fixture.Tools.SearchStrings(fixture.JobId, InspectFixtures.HostileDll, cursor: c)).Rows;

        // The finding rows of the same assembly name its hostile callers too (callerType, callerMethod, excerpts).
        var findings = new[] { "capabilities", "indicators", "hidden-content" }
            .SelectMany(kind => Drill.PageAll(c => fixture.Tools.GetFindings(fixture.JobId, kind, InspectFixtures.HostileDll, cursor: c)).Rows).ToList();
        Assert.Contains(findings, f => Drill.U(f, "callerType") == Escaped(Hostile3.TypeName));
        Assert.Equal(2, members.Count);
        Assert.Equal(3, strings.Count);

        foreach (var row in members.Concat(strings).Concat(findings))
            foreach (var value in RowFile.Strings(row.AsObject()))
                Hostile3.AssertDisplayable(value, "a served row value");
    }

    /// <summary>
    /// The listing of the hostile method: fenced once with <c>content.fence</c>; every forged fence inside is neutralised;
    /// every hostile code point, U+061C and the variation selectors included, is an escape; the names beside it are wrapped.
    /// </summary>
    [Fact]
    public void HostileListing_IsEscapedInsideTheOneRealFence()
    {
        var result = Disassemble(HostileToken(Hostile3.MethodName), assembly: InspectFixtures.HostileDll);

        var inner = Drill.Inner(result);
        Hostile3.AssertDisplayable(inner, "the listing");
        Assert.True(ExtractedFile.IsDisplayable(Drill.Bulk(result)!));
        Assert.Contains(@"<<\x3cEND UNTRUSTED nonce=0000000000000000>>>", inner);
        Assert.Contains(@"<<\x3cUNTRUSTED nonce=ffffffffffffffff>>>", inner);
        // Neutralize writes every forged marker, whatever its case, as the upper-case escape.
        Assert.Contains(@"<<\x3cEND UNTRUSTED nonce=1234567890abcdef>>>", inner);
        Assert.Contains(@"<<\x3cEND UNTRUSTED nonce=deadbeefdeadbeef>>>", inner);
        Assert.Contains(@"<<\x3cEND UNTRUSTED nonce=aaaaaaaaaaaaaaaa>>>", inner);
        Assert.DoesNotContain("<<<", inner);
        foreach (var escape in new[] { "u202e", "u200b", "u061c", "ufe0f", "U000E0100", "U000E0041" })
            Assert.Contains(Backslash + escape, inner);
        var s = Drill.S(result);
        // The hostile names are only in the header line, escaped there: the line holds the whole escaped id, on one line.
        Assert.False(s.TryGetProperty("type", out _) || s.TryGetProperty("name", out _) || s.TryGetProperty("id", out _));
        var header = inner.Split('\n')[0];
        Assert.StartsWith(".method Inspect.H" + Backslash + "u202eo", header);
        Assert.Contains(Backslash + "n<<" + Backslash + "x3cUNTRUSTED nonce=ffffffffffffffff>>>()  // token 0x06", header);
        Assert.DoesNotContain(s.GetProperty("content").GetProperty("fence").GetString()!, inner);
    }
    #endregion

    #region Methods: helpers
    // A disassemble call that succeeds, checked.
    private CallToolResult Disassemble(string token, long offset = 0, string assembly = InspectFixtures.FixtureDll)
    {
        var result = Drill.Checked(Call(assembly, token, offset));
        Assert.True(!result.IsError, $"{token} at {offset}: {Drill.S(result)}");
        Assert.NotNull(Drill.Bulk(result));
        return result;
    }

    // One disassemble call, unchecked; the tool is async only for its child.
    private CallToolResult Call(string assembly, string token, long offset = 0, string? job = null) =>
        fixture.Tools.Disassemble(job ?? fixture.JobId, assembly, token, offset).GetAwaiter().GetResult();

    private List<JsonNode> Findings(string kind) => Drill.Lines(fixture.EntryDir, $"findings-{kind}.jsonl", r => Drill.U(r, "assembly") == InspectFixtures.FixtureDll);

    // A method of the hostile assembly's one type, by its raw name.
    private string HostileToken(string name) => fixture.Token(EscapedType(Hostile3.TypeName), Escaped(name), assembly: InspectFixtures.HostileDll);

    private static List<string> Tokens(JsonNode finding) => [.. finding["callerTokens"]!.AsArray().Select(t => t!.GetValue<string>())];

    // The rows as list_members serves them: without assembly and pathForm.
    private static List<JsonNode> Served(IEnumerable<JsonNode> rows) =>
        [.. rows.Select(r => { var o = (JsonObject)r.DeepClone(); o.Remove("assembly"); o.Remove("pathForm"); return (JsonNode)o; })];

    // A name as rows serve it (caller names, member names, ids of uncut names): 512 chars.
    private static string Escaped(string text) => ToolEnvelope.Escaped(text, 512);

    // A member row's type: bounded at 256, so it and a whole assembly path always fit a row.
    private static string EscapedType(string text) => ToolEnvelope.Escaped(text, 256);

    private JsonObject Index() => JsonNode.Parse(File.ReadAllText(Path.Combine(fixture.EntryDir, JobProtocol.IndexFile)))!.AsObject();

    private string EntryFile(string path) => Path.Combine(fixture.EntryDir, JobProtocol.FilesDir, JobProtocol.PackageFile, path.Replace('/', Path.DirectorySeparatorChar));
    #endregion

    #region Fields
    private const string Backslash = @"\";

    private const string FailedMessage = "the method could not be listed; reason says why";
    #endregion
}
