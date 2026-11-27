namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;

using Xunit.Abstractions;

/// <summary>The S3 review probes' fixtures, emitted at test time: one type each, no nesting.</summary>
internal static class ProbeFixtures
{
    #region Methods
    /// <summary>A type and method named in long non-ASCII (Cyrillic type, CJK method) whose body is long CJK constants: the worst listing page.</summary>
    public static byte[] Wide()
    {
        var (builder, module) = Begin("Probe.Wide");
        var type = module.DefineType(WideType, StaticClass);
        var il = type.DefineMethod(WideMethod, StaticMethod, typeof(void), Type.EmptyTypes).GetILGenerator();
        for (var i = 0; i < 300; i++)
        {
            il.Emit(OpCodes.Ldstr, DrillFixtures.LongCjk(150));
            il.Emit(OpCodes.Pop);
        }
        il.Emit(OpCodes.Ret);
        type.CreateType();
        return Save(builder);
    }

    /// <summary>S3 review C1: <see cref="BigMethods"/> methods, each loading the same <see cref="BigConstant"/> (one #US entry).</summary>
    public static byte[] Big()
    {
        var (builder, module) = Begin("Probe.Big");
        var type = module.DefineType(BigType, StaticClass);
        for (var i = 0; i < BigMethods; i++)
        {
            var il = type.DefineMethod($"M{i:D4}", StaticMethod, typeof(void), Type.EmptyTypes).GetILGenerator();
            il.Emit(OpCodes.Ldstr, BigConstant);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        }
        type.CreateType();
        return Save(builder);
    }

    /// <summary>
    /// S3 review C2: <see cref="IpOverloads"/> overloads of <c>Ip</c>. The first <see cref="SharedOverloads"/> each load the same
    /// four constants of 1,000 distinct public IPv4s; the last two load a constant of 10 other IPs.
    /// </summary>
    public static byte[] Ips()
    {
        var (builder, module) = Begin("Probe.Ips");
        var type = module.DefineType(IpsType, StaticClass);
        Type[] kinds = [typeof(int), typeof(long), typeof(short), typeof(byte), typeof(bool), typeof(double), typeof(float), typeof(char), typeof(string), typeof(object)];
        for (var i = 0; i < IpOverloads; i++)
        {
            // Arity 1 to 5 of one of 10 types: 50 distinct signatures.
            var il = type.DefineMethod("Ip", StaticMethod, typeof(void), [.. Enumerable.Repeat(kinds[i % 10], 1 + i / 10)]).GetILGenerator();
            foreach (var constant in i < SharedOverloads ? SharedIps : [OtherIps])
            {
                il.Emit(OpCodes.Ldstr, constant);
                il.Emit(OpCodes.Pop);
            }
            il.Emit(OpCodes.Ret);
        }
        type.CreateType();
        return Save(builder);
    }

    private static (PersistedAssemblyBuilder, ModuleBuilder) Begin(string name)
    {
        var builder = new PersistedAssemblyBuilder(new AssemblyName(name), typeof(object).Assembly);
        return (builder, builder.DefineDynamicModule(name + ".dll"));
    }

    private static byte[] Save(PersistedAssemblyBuilder builder)
    {
        using var stream = new MemoryStream();
        builder.Save(stream);
        return stream.ToArray();
    }
    #endregion

    #region Fields
    public const string BigType = "Probe.Big";
    public const int BigMethods = 1_000;
    public const string IpsType = "Probe.Ips";
    public const int IpOverloads = 50;
    public const int SharedOverloads = 48;

    public static readonly string WideType = "Wide" + DrillFixtures.LongNonAscii(600);
    public static readonly string WideMethod = DrillFixtures.LongCjk(600);

    /// <summary>200,000 chars of plain words: no indicator, no encoded content.</summary>
    public static readonly string BigConstant = string.Concat(Enumerable.Repeat("lorem ipsum dolor sit amet ", 10_000))[..200_000];

    public static readonly string[] SharedIps =
        [.. Enumerable.Range(0, 4).Select(k => string.Join(" ", Enumerable.Range(0, 1_000).Select(i => $"11.{k}.{i / 250}.{i % 250 + 1}")))];

    public static readonly string OtherIps = string.Join(" ", Enumerable.Range(1, 10).Select(i => $"12.0.0.{i}"));

    private const TypeAttributes StaticClass = TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed;
    private const MethodAttributes StaticMethod = MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig;
    #endregion
}

/// <summary>
/// The S3 review round 1 probes and budget test, each a real job in the CLI child (task S3): a worst-case disassemble page is
/// within the 20,000-char response budget (W2); a thousand methods loading one 200k-char constant stream through the members
/// walk (C1); thousands of IP indicators over 50 same-named overloads are attributed within the evidence budgets, with at
/// most 8 tokens each (C2). They run alone, so their times are their own; each records its measurement in the test output
/// and in <c>%TEMP%/silvergun-mcp-tests/s3-probes.txt</c>.
/// </summary>
[Collection(ProcessCountingCollection.Name)]
public sealed class S3ProbeTests(ITestOutputHelper output)
{
    #region Methods
    /// <summary>
    /// S3 review W2: the longest assembly path whose inventory row stays readable (about 430 CJK chars, six chars each as
    /// served; at 512 the row cannot keep its file column), and a method whose type and name are 600 non-ASCII chars with a
    /// body of long CJK constants. Every page of its listing, structured JSON and both text blocks, is at most 20,000 chars,
    /// and the first page uses the listing budget (it is the worst case, not a small one).
    /// </summary>
    [Fact]
    public async Task Disassemble_TheWorstCasePage_IsWithinTheResponseBudget()
    {
        using var dirs = new TestDirs();
        var path = "lib/" + DrillFixtures.LongCjk(200) + "/" + DrillFixtures.LongCjk(200) + "/" + DrillFixtures.LongCjk(20) + ".dll";
        var (manager, view) = await Run(dirs, "mcp.probe.wide", (path, ProbeFixtures.Wide()));
        var tools = new DrillTools(manager);
        var row = Assert.Single(Drill.Lines(view.EntryDir!, JobProtocol.InventoryFile), r => Drill.U(r, "path") == path);
        Assert.Equal("assembly", Drill.Str(row["kind"]));
        Assert.True(row["readable"]!.GetValue<bool>(), "the fixture's path is too long to be read: shorten it");
        var token = Drill.Str(Assert.Single(Drill.Lines(view.EntryDir!, JobProtocol.MembersFile), m => Drill.U(m, "name")!.StartsWith(DrillFixtures.LongCjk(10), StringComparison.Ordinal))["token"])!;

        long? offset = 0;
        var sizes = new List<int>();
        while (offset is { } at)
        {
            var result = Drill.Checked(await tools.Disassemble(view.JobId, path, token, at));
            Assert.True(!result.IsError, Drill.S(result).ToString());
            sizes.Add(Drill.Size(result));
            Assert.True(Drill.Size(result) <= McpLimits.ResponseBudgetChars, $"a page of {Drill.Size(result)} chars");
            Assert.True(Drill.Inner(result).Length <= McpLimits.BulkBudgetChars * 4 / 5, $"a listing of {Drill.Inner(result).Length} chars");
            if (at == 0)
            {
                Assert.True(Drill.Inner(result).Length >= InspectProtocol.MinChars, $"the first page used only {Drill.Inner(result).Length} chars");
                Assert.Contains(DrillFixtures.LongCjk(100), Drill.Inner(result).Split('\n')[0]);
            }
            offset = Drill.S(result).TryGetProperty("next", out var next) ? next.GetInt64() : null;
            Assert.True(sizes.Count < 100);
        }
        Record($"worst-case disassemble: {sizes.Count} pages, largest result {sizes.Max()} chars of {McpLimits.ResponseBudgetChars}");
        Assert.True(sizes.Count >= 3);
    }

    /// <summary>
    /// S3 review C1: 1,000 methods each load the same 200,000-char constant. The job completes, with one strings row per
    /// method: the whole length, the value cut at 1,024, each caller a listed member; and search_strings pages them all.
    /// </summary>
    [Fact]
    public async Task Probe_AThousandMethodsLoadingOneHugeConstant_StreamThroughTheMembersWalk()
    {
        using var dirs = new TestDirs();
        var clock = Stopwatch.StartNew();
        var (manager, view) = await Run(dirs, "mcp.probe.big", ("lib/net8.0/Probe.Big.dll", ProbeFixtures.Big()));
        var elapsed = clock.Elapsed;

        var strings = Drill.Lines(view.EntryDir!, JobProtocol.StringsFile, r => Drill.U(r, "callerType") == ProbeFixtures.BigType);
        var members = Drill.Lines(view.EntryDir!, JobProtocol.MembersFile, r => Drill.U(r, "type") == ProbeFixtures.BigType);
        Assert.Equal(ProbeFixtures.BigMethods, members.Count);
        Assert.Equal(ProbeFixtures.BigMethods, strings.Count);
        var value = ToolEnvelope.Escaped(ProbeFixtures.BigConstant, 1024);
        Assert.All(strings, s =>
        {
            Assert.Equal(ProbeFixtures.BigConstant.Length, s["length"]!.GetValue<int>());
            Assert.Equal((0, 1), (s["offset"]!.GetValue<int>(), s["occurrences"]!.GetValue<int>()));
            Assert.Equal(value, Drill.U(s, "value"));
        });
        Assert.Equal(members.Select(m => Drill.Str(m["token"])).Order(StringComparer.Ordinal), strings.Select(s => Drill.Str(s["callerToken"])).Order(StringComparer.Ordinal));
        var index = JsonNode.Parse(File.ReadAllText(Path.Combine(view.EntryDir!, JobProtocol.IndexFile)))!;
        Assert.False(index["strings"]!["truncated"]!.GetValue<bool>());
        Assert.Equal(0, index["members"]!["pass"]!["methodsUnreadable"]!.GetValue<int>());

        var tools = new DrillTools(manager);
        var (served, pages, _) = Drill.PageAll(c => tools.SearchStrings(view.JobId, "lib/net8.0/Probe.Big.dll", cursor: c));
        Drill.SameRows(strings, served, "search_strings of the C1 probe");
        Record($"C1 probe: job {view.Record!.ElapsedMs} ms (test {elapsed.TotalSeconds:0.0} s), {strings.Count} strings rows in {pages} pages");
    }

    /// <summary>
    /// S3 review C2: 50 overloads of Ip, 48 of which share four constants of 1,000 distinct IPv4s each, and 2 of which load 10
    /// others. Every indicator finding is attributed by its exact value: a shared IP to the 48 (8 listed, callerTokensTotal 48),
    /// one of the 10 to the 2. The job completes well within its 900 s budget.
    /// </summary>
    [Fact]
    public async Task Probe_ThousandsOfIpIndicatorsOver50Overloads_AreAttributedWithAtMost8Tokens()
    {
        using var dirs = new TestDirs();
        var (_, view) = await Run(dirs, "mcp.probe.ips", ("lib/net8.0/Probe.Ips.dll", ProbeFixtures.Ips()));

        var members = Drill.Lines(view.EntryDir!, JobProtocol.MembersFile, r => Drill.U(r, "type") == ProbeFixtures.IpsType)
            .OrderBy(m => Drill.Str(m["token"]), StringComparer.Ordinal).ToList();
        Assert.Equal(ProbeFixtures.IpOverloads, members.Count);
        var shared = members.Take(ProbeFixtures.SharedOverloads).Select(m => Drill.Str(m["token"])!).ToList();
        var others = members.Skip(ProbeFixtures.SharedOverloads).Select(m => Drill.Str(m["token"])!).ToList();
        var findings = Drill.Lines(view.EntryDir!, "findings-indicators.jsonl", r => Drill.U(r, "callerType") == ProbeFixtures.IpsType);
        var ip = new Regex(@"^1[12]\.\d+\.\d+\.\d+$");
        Assert.All(findings, f => Assert.Matches(ip, Drill.U(f, "value")));
        Assert.Equal(4 * 1_000 + 10, findings.Count);

        foreach (var f in findings)
        {
            var tokens = f["callerTokens"]!.AsArray().Select(t => t!.GetValue<string>()).ToList();
            Assert.True(tokens.Count <= 8, $"{tokens.Count} caller tokens");
            if (Drill.U(f, "value")!.StartsWith("11.", StringComparison.Ordinal))
            {
                Assert.Equal(shared.Take(8), tokens);
                Assert.Equal(ProbeFixtures.SharedOverloads, f["callerTokensTotal"]!.GetValue<int>());
            }
            else
            {
                Assert.Equal(others, tokens);
                Assert.False(f.AsObject().ContainsKey("callerTokensTotal"));
            }
        }
        Assert.All(members.Take(ProbeFixtures.SharedOverloads), m => Assert.Equal(4_000, m["indicators"]!.GetValue<int>()));
        Assert.All(members.Skip(ProbeFixtures.SharedOverloads), m => Assert.Equal(10, m["indicators"]!.GetValue<int>()));
        Assert.True(view.Record!.ElapsedMs < 450_000, $"the job took {view.Record.ElapsedMs} ms, over half its budget");
        Record($"C2 probe: job {view.Record.ElapsedMs} ms, {findings.Count} indicator findings over {members.Count} overloads");
    }
    #endregion

    #region Methods: helpers
    private static async Task<(JobManager Manager, JobView View)> Run(TestDirs dirs, string id, (string Entry, byte[] Bytes) assembly)
    {
        var manager = InProcess.Manager(dirs);
        var view = await InProcess.RunToEndAsync(manager, DrillFixtures.Nupkg(dirs.Root, id, "S3 probe.", [assembly]));
        Assert.True(view.State == JobState.Completed, $"{id}: {view.State} {view.Reason}");
        return (manager, view);
    }

    private void Record(string line)
    {
        var stamped = string.Create(CultureInfo.InvariantCulture, $"{DateTime.UtcNow:O} {line}");
        output.WriteLine(stamped);
        try
        {
            File.AppendAllText(Path.Combine(Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests")).FullName, "s3-probes.txt"), stamped + Environment.NewLine);
        }
        catch (IOException) { /* the record is a convenience; the assertions are the test */ }
    }
    #endregion
}
