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

using Silvergun.CodeAnalysis.IL;
using Silvergun.MCPServer.Jobs;
using Silvergun.PackageAnalysis.NuGet;

using Xunit.Abstractions;

/// <summary>
/// <see cref="MemberRows.Write"/>'s attribution after S3 review round 2, in-process on emitted assemblies with real indicator
/// reports (<see cref="IndicatorAnalysis"/>, so every finding's value is exactly the pass's): counting is O(1) per finding
/// (C1, with a time bound the old O(findings x overloads) code could not meet); the narrowing and evidence budgets, once
/// spent, stop narrowing; a finding every overload carries is not narrowed. Alone in the non-parallel collection, for the timing.
/// </summary>
[Collection(ProcessCountingCollection.Name)]
public sealed class S3AttributionTests(ITestOutputHelper output) : IDisposable
{
    #region Methods
    /// <summary>
    /// The reviewer's C1 shape: <see cref="SameNamed"/> methods all named M, one of which loads two constants of 5,000
    /// distinct IPv4s, so there are 10,000 indicator findings of the name M. The old attribution walked every overload for
    /// every finding and counted each: 10,000 x 20,000 = 2 x 10^8 dictionary updates, seconds at the least. Now each
    /// narrowing attempt is charged 2 x overloads to the 20M budget, so the first floor(20M / (2N)) = 500 findings narrow to
    /// the one method, and every later one counts once toward the whole name. The attribution's cost, over a walk of the same
    /// assembly with no findings, must stay under 1.5 s.
    /// </summary>
    [Fact]
    public void Attribution_ManyFindingsOverAHugeName_IsLinear_AndCountsTheNameOnEveryMember()
    {
        var path = Path.Combine(dir, "Probe.Huge.dll");
        File.WriteAllBytes(path, HugeName());
        var indicators = Indicators(path);
        var findings = indicators.Findings.Where(f => f.CallerMethod == "M").ToList();
        // 10,000: the indicator pass's distinct-indicator cap, met exactly and not passed.
        Assert.Equal(IndicatorAnalysis.MaxDistinctIndicators, findings.Count);
        Assert.False(indicators.Truncated);

        var bare = Directory.CreateDirectory(Path.Combine(dir, "bare")).FullName;
        var clock = Stopwatch.StartNew();
        MemberRows.Write(bare, Report((path, indicators with { Findings = [] })), Paths(path));
        var baseline = clock.Elapsed;
        var full = Directory.CreateDirectory(Path.Combine(dir, "full")).FullName;
        clock.Restart();
        var rows = MemberRows.Write(full, Report((path, indicators)), Paths(path));
        var elapsed = clock.Elapsed;

        var narrowedExpected = (int)Math.Min(findings.Count, MemberRows.MaxNarrowing / (2L * SameNamed));
        var members = Drill.Lines(full, JobProtocol.MembersFile).Where(m => Drill.U(m, "name") == "M").ToList();
        Assert.Equal(SameNamed, members.Count);
        var loader = Drill.Str(Assert.Single(members, m => m["ilBytes"]!.GetValue<int>() > 1)["token"]);
        var first8 = members.Take(8).Select(m => Drill.Str(m["token"])!).ToList();
        var narrowed = 0;
        foreach (var f in findings)
        {
            var (tokens, total) = Assert.NotNull(rows.CallerTokens(f, 8));
            var list = tokens.Select(t => t!.GetValue<string>()).ToList();
            Assert.True(list.Count <= 8);
            if (total == 1)
            {
                Assert.Equal([loader], list);
                narrowed++;
            }
            else
            {
                Assert.Equal(SameNamed, total);
                Assert.Equal(first8, list);
            }
        }
        Assert.Equal(narrowedExpected, narrowed);
        // The name's count is on every member of the name; the loader also has its own narrowed ones.
        Assert.All(members.Where(m => Drill.Str(m["token"]) != loader), m => Assert.Equal(findings.Count - narrowed, m["indicators"]!.GetValue<int>()));
        Assert.Equal(findings.Count, Assert.Single(members, m => Drill.Str(m["token"]) == loader)["indicators"]!.GetValue<int>());

        var attribution = elapsed - baseline;
        var line = string.Create(CultureInfo.InvariantCulture,
            $"C1 round 2: {SameNamed} same-named methods, {findings.Count} findings ({narrowed} narrowed): walk {baseline.TotalSeconds:0.00} s, with attribution {elapsed.TotalSeconds:0.00} s");
        Record(line);
        Assert.True(attribution < TimeSpan.FromSeconds(1.5), line);
    }

    /// <summary>
    /// The narrowing budget spent (maxNarrowing 0): a finding that would narrow to 2 of 50 overloads lists every overload (8
    /// plus the total), and it counts toward every member of the name.
    /// </summary>
    [Fact]
    public void Attribution_WithTheNarrowingBudgetSpent_ListsEveryOverload_AndCountsTowardEach()
    {
        var path = Path.Combine(dir, "Probe.Ips.dll");
        File.WriteAllBytes(path, ProbeFixtures.Ips());
        var indicators = Indicators(path);
        var other = indicators.Findings.Single(f => f.Value == "12.0.0.1");
        var shared = indicators.Findings.Single(f => f.Value == "11.0.0.1");
        var report = Report((path, indicators with { Findings = [other, shared] }));

        var narrowing = MemberRows.Write(Sub("narrowing"), report, Paths(path));
        var spent = MemberRows.Write(Sub("spent"), report, Paths(path), maxNarrowing: 0);

        var members = Drill.Lines(Sub("spent"), JobProtocol.MembersFile).Select(m => Drill.Str(m["token"])!).ToList();
        Assert.Equal(ProbeFixtures.IpOverloads, members.Count);
        AssertListed(members.TakeLast(2).ToList(), 2, narrowing, other);
        AssertListed(members.Take(8).ToList(), ProbeFixtures.SharedOverloads, narrowing, shared);
        AssertListed(members.Take(8).ToList(), ProbeFixtures.IpOverloads, spent, other);
        AssertListed(members.Take(8).ToList(), ProbeFixtures.IpOverloads, spent, shared);
        Assert.All(Drill.Lines(Sub("spent"), JobProtocol.MembersFile), m => Assert.Equal(2, m["indicators"]!.GetValue<int>()));
        var counted = Drill.Lines(Sub("narrowing"), JobProtocol.MembersFile).Select(m => m["indicators"]!.GetValue<int>()).ToList();
        Assert.Equal([.. Enumerable.Repeat(1, ProbeFixtures.SharedOverloads), 1, 1], counted);
    }

    /// <summary>
    /// The evidence budget spent in a first assembly: two copies of the 50-overload assembly, each with the same two findings.
    /// The first takes exactly 100 evidence entries (each member 1, plus 1 for the one target value its strings carry), so with
    /// maxEvidence 100 it narrows, and the second, given no evidence, narrows nothing.
    /// </summary>
    [Fact]
    public void Attribution_WithTheEvidenceBudgetSpentInAFirstAssembly_StopsNarrowingInTheNext()
    {
        var a = Path.Combine(Sub("a"), "Probe.Ips.dll");
        var b = Path.Combine(Sub("b"), "Probe.Ips.dll");
        File.WriteAllBytes(a, ProbeFixtures.Ips());
        File.WriteAllBytes(b, ProbeFixtures.Ips());
        IndicatorReport Two(string path)
        {
            var report = Indicators(path);
            return report with { Findings = [report.Findings.Single(f => f.Value == "12.0.0.1"), report.Findings.Single(f => f.Value == "11.0.0.1")] };
        }
        var (ia, ib) = (Two(a), Two(b));
        var report = Report((a, ia), (b, ib));
        var paths = Paths(a, b);

        var whole = MemberRows.Write(Sub("whole"), report, paths);
        var spent = MemberRows.Write(Sub("spent"), report, paths, maxEvidence: 100);

        foreach (var rows in new[] { whole, spent })
        {
            Assert.Equal(2, Listed(rows, ia.Findings[0]).Total);
            Assert.Equal(ProbeFixtures.SharedOverloads, Listed(rows, ia.Findings[1]).Total);
        }
        Assert.Equal(2, Listed(whole, ib.Findings[0]).Total);
        Assert.Equal(ProbeFixtures.SharedOverloads, Listed(whole, ib.Findings[1]).Total);
        Assert.Equal(ProbeFixtures.IpOverloads, Listed(spent, ib.Findings[0]).Total);
        Assert.Equal(ProbeFixtures.IpOverloads, Listed(spent, ib.Findings[1]).Total);
        // Two entries fewer: the budget is 0 before the first assembly's last member, which gets no evidence, so a name it
        // belongs to does not narrow there either (every overload must have evidence).
        var short2 = MemberRows.Write(Sub("short"), report, paths, maxEvidence: 98);
        Assert.Equal(ProbeFixtures.IpOverloads, Listed(short2, ia.Findings[0]).Total);
        Assert.Equal(ProbeFixtures.IpOverloads, Listed(short2, ia.Findings[1]).Total);
    }

    /// <summary>
    /// A finding whose evidence every overload carries is not narrowed: its tokens are the whole name's, and it counts once
    /// toward the name, so every member of the name shows it. All 10 Many overloads, and both Twin overloads, call
    /// Process.Start.
    /// </summary>
    [Fact]
    public void Attribution_AFindingEveryOverloadCarries_ListsThemAll_AndCountsTowardEach()
    {
        var fixture = InspectFixtures.Write(Sub("fixture"));
        var start = new ApiCallFinding(Capability.ProcessExecution, ApiCallKind.Call, InspectFixtures.OverloadsType, "Many", "System.Diagnostics.Process.Start");
        var twin = start with { CallerMethod = "Twin" };
        var calls = new AssemblyScanResult(new PackageAssembly(InspectFixtures.FixtureDll, fixture, "net8.0", PackageItemRole.Lib, ""),
            Capabilities(fixture, [start, twin]), null, null, null, null);
        var callRows = MemberRows.Write(Sub("calls"), new PackageCapabilityReport(null!, DateTimeOffset.UtcNow, [calls], [], []), Paths(fixture));

        var members = Drill.Lines(Sub("calls"), JobProtocol.MembersFile);
        var many = members.Where(m => Drill.U(m, "name") == "Many").ToList();
        var twins = members.Where(m => Drill.U(m, "name") == "Twin").ToList();
        AssertListed(many.Take(8).Select(m => Drill.Str(m["token"])!).ToList(), InspectFixtures.ManyParameterTypes.Length, callRows, start);
        AssertListed(twins.Select(m => Drill.Str(m["token"])!).ToList(), 2, callRows, twin);
        Assert.All(many.Concat(twins), m => Assert.Equal(1, m["capabilities"]!["processExecution"]!.GetValue<int>()));
        Assert.All(members.Where(m => Drill.U(m, "name") is not ("Many" or "Twin")), m => Assert.Null(m["capabilities"]));
    }

    public void Dispose()
    {
        try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
    #endregion

    #region Methods: helpers
    // SameNamed static methods named M with the same signature; the first loads two constants of 5,000 distinct IPv4s.
    private static byte[] HugeName()
    {
        var builder = new PersistedAssemblyBuilder(new AssemblyName("Probe.Huge"), typeof(object).Assembly);
        var module = builder.DefineDynamicModule("Probe.Huge.dll");
        var type = module.DefineType("Probe.Huge", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        for (var i = 0; i < SameNamed; i++)
        {
            var il = type.DefineMethod("M", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, typeof(void), Type.EmptyTypes).GetILGenerator();
            if (i == 0)
                for (var k = 0; k < 2; k++)
                {
                    il.Emit(OpCodes.Ldstr, string.Join(" ", Enumerable.Range(0, 5_000).Select(j => $"13.{k}.{j / 250}.{j % 250 + 1}")));
                    il.Emit(OpCodes.Pop);
                }
            il.Emit(OpCodes.Ret);
        }
        type.CreateType();
        using var stream = new MemoryStream();
        builder.Save(stream);
        return stream.ToArray();
    }

    private static IndicatorReport Indicators(string path)
    {
        using var assembly = InspectFixtures.Load(path);
        var report = new IndicatorAnalysis(assembly).Analyze();
        Assert.True(report.IsSuccess, report.Message);
        return report.Value;
    }

    private static CapabilityReport Capabilities(string path, IReadOnlyList<ApiCallFinding> findings) =>
        new(Path.GetFileNameWithoutExtension(path), path, DateTimeOffset.UtcNow, findings, 0, 0, 0, []);

    // A report of the given assemblies (each with no capability findings), as MemberRows reads one: only Assemblies is used.
    private static PackageCapabilityReport Report(params (string Path, IndicatorReport Indicators)[] assemblies) =>
        new(null!, DateTimeOffset.UtcNow,
            [.. assemblies.Select((a, i) => new AssemblyScanResult(new PackageAssembly($"lib/net8.0/a{i}/{Path.GetFileName(a.Path)}", a.Path, "net8.0", PackageItemRole.Lib, ""),
                Capabilities(a.Path, []), null, null, null, a.Indicators))],
            [], []);

    private static PackagePaths Paths(params string[] files)
    {
        var paths = new PackagePaths();
        foreach (var (file, i) in files.Select((f, i) => (f, i)))
            paths.Add(file, $"lib/net8.0/a{i}/{Path.GetFileName(file)}", $"lib/net8.0/a{i}/{Path.GetFileName(file)}");
        return paths;
    }

    private static void AssertListed(IEnumerable<string> tokens, int total, MemberRows rows, object finding)
    {
        var (listed, listedTotal) = Listed(rows, finding);
        Assert.Equal(tokens, listed);
        Assert.Equal(total, listedTotal);
    }

    private static (List<string> Tokens, int Total) Listed(MemberRows rows, object finding)
    {
        var (tokens, total) = Assert.NotNull(rows.CallerTokens(finding, 8));
        return ([.. tokens.Select(t => t!.GetValue<string>())], total);
    }

    private string Sub(string name) => Directory.CreateDirectory(Path.Combine(dir, name)).FullName;

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

    #region Fields
    // CCI's first read of a type's members is quadratic in same-named methods (5 s at 20,000 here, measured; an ext/ cost
    // below every pass, reported), so the probe stays at 20,000. The attribution cost is measured apart from that walk.
    private const int SameNamed = 20_000;

    private readonly string dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "attribution-" + Guid.NewGuid().ToString("N"))).FullName;
    #endregion
}
