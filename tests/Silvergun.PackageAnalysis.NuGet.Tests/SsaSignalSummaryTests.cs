namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet.Graph;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using S = Silvergun.PackageAnalysis.NuGet.Tests.ReachabilitySummaryTests;
using T = Silvergun.PackageAnalysis.NuGet.Tests.SsaSummaryTests;

/// <summary>
/// The value signals in the SSA summary (<c>docs/agent/tasks/recall-levers-1.md</c> §2, "Summary" and "Site selection"):
/// <see cref="SsaSiteSummary.Signals"/> and <see cref="FolderSsaSummary.Signals"/>, over hand-built facts. The classifier's
/// table is <c>SsaValueSignalsTests</c> in the IL tests; here only what the summary does with its answers: counts, kinds,
/// listing order under the caps, the JSON, and that a signal never moves completeness.
/// </summary>
public sealed class SsaSignalSummaryTests
{
    #region Methods: counts and kinds
    [Fact]
    public void Of_SignalSites_CarryTheirSignals_AndTheFolderCountsEach()
    {
        var summary = Summary(Shell("A.M()", 1), Shell("B.M()", 1), Secret("C.M()", 1), Plain("D.M()", 1));

        Assert.Equal(
            [(SsaSignal.ShellInterpreter, ReachStatementKind.Informational, 2), (SsaSignal.SecretEnvironmentName, ReachStatementKind.Informational, 1)],
            summary.Signals!.Select(s => (s.Signal, s.Kind, s.Sites)));
        Assert.Equal(
            ["A.M(): ShellInterpreter", "B.M(): ShellInterpreter", "C.M(): SecretEnvironmentName"],
            summary.Sites.Where(s => s.Signals is not null).Select(s => $"{s.Caller}: {string.Join(",", s.Signals!)}"));
        Assert.Null(Assert.Single(summary.Sites, s => s.Caller == "D.M()").Signals);
    }

    [Fact]
    public void Of_EverySignal_IsCounted_InEnumOrder()
    {
        var summary = Summary(Secret("A.M()", 1), Memory("B.M()", 1), Stealth("C.M()", 1), Shell("D.M()", 1));

        Assert.Equal(Enum.GetValues<SsaSignal>(), summary.Signals!.Select(s => s.Signal));
        Assert.All(summary.Signals!, s => Assert.Equal(1, s.Sites));
    }

    [Fact]
    public void Of_OneSiteWithTwoSignals_CountsItUnderEach()
    {
        var both = T.Fact(T.Site("A.M()", 1, Capability.ProcessExecution, "System.Diagnostics.ProcessStartInfo..ctor"), args: [T.Str("powershell.exe"), T.Str("-w hidden")]);

        var summary = Summary(both);

        Assert.Equal([SsaSignal.ShellInterpreter, SsaSignal.StealthArguments], Assert.Single(summary.Sites).Signals);
        Assert.Equal([(SsaSignal.ShellInterpreter, 1), (SsaSignal.StealthArguments, 1)], summary.Signals!.Select(s => (s.Signal, s.Sites)));
    }

    // The kinds come from the measurement (recall-levers-1 §4), not from the code: none passed yet, so all are information.
    [Fact]
    public void KindOf_EverySignal_IsInformational_UntilItsBenignMeasurementSaysOtherwise() =>
        Assert.All(Enum.GetValues<SsaSignal>(), s => Assert.Equal(ReachStatementKind.Informational, SsaSummary.KindOf(s)));

    [Fact]
    public void Of_NoSignalSites_HasNoSignals()
    {
        var summary = Summary(Plain("A.M()", 1), Plain("B.M()", 1));

        Assert.Null(summary.Signals);
        Assert.All(summary.Sites, s => Assert.Null(s.Signals));
    }

    // A site that was not analysed says nothing about its values, even when a crafted fact carries them.
    [Theory]
    [InlineData(SsaSiteStatus.MethodUnknown)]
    [InlineData(SsaSiteStatus.NotJoined)]
    [InlineData(SsaSiteStatus.NotRun)]
    public void Of_NotAnalyzedSiteWithShellValues_GivesNoSignal(SsaSiteStatus status)
    {
        var crafted = T.Fact(T.Site("A.M()", 1), status, args: [T.Str("cmd.exe")], reason: "r");

        Assert.Null(Summary(crafted).Signals);
    }

    // The value must be constant to be read: a parameter or a call result is no signal, and not "no signal" either.
    [Fact]
    public void Of_SiteWhoseValuesAreNotConstant_IsNotListed_AndHasNoSignal()
    {
        var summary = Summary(T.Fact(T.Site("A.M()", 1), args: [SsaValue.OfParameter(0), SsaValue.OfDynamic(SsaDynamicOrigin.CallResult)]));

        Assert.Null(summary.Signals);
        Assert.Empty(summary.Sites);
    }

    [Fact]
    public void Of_Copy_HasNoSignals_ItListsNoSites()
    {
        var ssa = Ssa(Shell("A.M()", 1));

        var copy = SsaSummary.Of(ssa, copy: true)!;

        Assert.Null(copy.Signals);
        Assert.Empty(copy.Sites);
        Assert.NotNull(SsaSummary.Of(ssa, copy: false)!.Signals);
    }

    [Fact]
    public void Of_FolderWithoutFacts_HasNoSignals() =>
        Assert.Null(SsaSummary.Of(new FolderSsa(SsaFolderOutcome.NotRun, null, "no graph"), copy: false)!.Signals);

    // A signal says what a value is, not that SSA finished: the folder is as complete as it was.
    [Fact]
    public void Incomplete_IsNotMovedBySignals()
    {
        Assert.False(Summary(Shell("A.M()", 1)).Incomplete());
        Assert.False(Summary(Plain("A.M()", 1)).Incomplete());
        Assert.True(SsaSummary.Of(Ssa(Shell("A.M()", 1), T.Fact(T.Site("B.M()", 1), SsaSiteStatus.NotRun, reason: "r")), copy: false)!.Incomplete());
    }

    [Fact]
    public void Of_IsDeterministic_WhateverTheFactOrder()
    {
        var facts = new[] { Secret("C.M()", 2), Shell("A.M()", 1), Plain("B.M()", 3), Memory("D.M()", 1), Shell("A.M()", 7) };

        Assert.Equal(Json(Summary(facts)), Json(Summary([.. facts.Reverse()])));
    }
    #endregion

    #region Methods: listing order and the caps
    // Signal sites first, then the usual order: capability, caller, offset, callee.
    [Fact]
    public void Of_SignalSites_AreListedBeforeTheOthers()
    {
        var summary = Summary(Plain("A.M()", 1, Capability.FileSystem), Plain("A.M()", 2, Capability.FileSystem), Secret("Z.M()", 1), Shell("Y.M()", 1));

        Assert.Equal(["Y.M()", "Z.M()", "A.M()", "A.M()"], summary.Sites.Select(s => s.Caller));
        Assert.Equal([SsaSignal.ShellInterpreter], summary.Sites[0].Signals);
    }

    // The caps list the first sites; a site with a signal sorts first, so the folder cap never hides one.
    [Fact]
    public void Of_UnderTheFolderCap_EverySignalSiteIsListed_AndCounted()
    {
        var plain = Enumerable.Range(0, 100).Select(i => Plain($"A{i:000}.M()", 1, Capability.FileSystem));
        var signals = Enumerable.Range(0, 5).Select(i => Shell($"Z{i}.M()", 1));

        var summary = Summary([.. plain, .. signals]);

        Assert.Equal((100, 5), (summary.Sites.Count, summary.SitesDropped));
        Assert.Equal(Enumerable.Range(0, 5).Select(i => $"Z{i}.M()"), summary.Sites.Take(5).Select(s => s.Caller));
        Assert.All(summary.Sites.Take(5), s => Assert.NotNull(s.Signals));
        Assert.All(summary.Sites.Skip(5), s => Assert.Null(s.Signals));
        Assert.Equal(5, Assert.Single(summary.Signals!).Sites);
    }

    // The count is of every Analyzed signal site, listed or not.
    [Fact]
    public void Of_MoreSignalSitesThanTheCap_CountsThemAll()
    {
        var summary = Summary([.. Enumerable.Range(0, 150).Select(i => Shell($"S{i:000}.M()", 1))]);

        Assert.Equal((100, 50), (summary.Sites.Count, summary.SitesDropped));
        Assert.Equal(150, Assert.Single(summary.Signals!).Sites);
    }

    // The package cap keeps each folder's first sites in folder order, so it may drop a late folder's listed signal site;
    // the folder's signal count still says it was there.
    [Fact]
    public void Capped_DroppedSignalSites_AreStillCounted()
    {
        var folders = Enumerable.Range(0, 10).Select(i => Folder($"lib/f{i:00}", 100, plain: true))
            .Append(Folder("lib/f10", 5, plain: false))
            .ToArray();

        var summary = ReachabilitySummary.From(new(folders));

        Assert.Equal(1_000, summary.Folders.Sum(f => f.Ssa!.Sites.Count));
        var last = summary.Folders[10].Ssa!;
        Assert.Equal((0, 5), (last.Sites.Count, last.SitesDropped));
        Assert.Equal([(SsaSignal.ShellInterpreter, 5)], last.Signals!.Select(s => (s.Signal, s.Sites)));
    }
    #endregion

    #region Methods: JSON
    // Not written when none, so a scan without signals reads as it did before.
    [Fact]
    public void Json_WithoutSignals_HasNoSignalsKey_AnywhereInTheReport()
    {
        var json = ReportWith(ReachabilitySummary.From(new([Analyzed(Plain("A.M()", 1))]))).ToJson();

        Assert.Contains("\"Ssa\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Signals\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Signal\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Json_WithSignals_HasTheFolderCountsAndTheSiteSignals()
    {
        var json = ReportWith(ReachabilitySummary.From(new([Analyzed(Shell("A.M()", 1), Plain("B.M()", 1, Capability.ProcessExecution))]))).ToJson();

        var ssa = JsonNode.Parse(json)!["Reachability"]!["Folders"]![0]!["Ssa"]!;
        var folder = Assert.Single(ssa["Signals"]!.AsArray())!;
        Assert.Equal(("ShellInterpreter", "Informational", 1), (folder["Signal"]!.GetValue<string>(), folder["Kind"]!.GetValue<string>(), folder["Sites"]!.GetValue<int>()));
        var sites = ssa["Sites"]!.AsArray();
        Assert.Equal("ShellInterpreter", Assert.Single(sites[0]!["Signals"]!.AsArray())!.GetValue<string>());
        Assert.False(sites[1]!.AsObject().ContainsKey("Signals"));
    }

    [Fact]
    public void Json_WithSignals_RoundTrips()
    {
        var json = ReportWith(ReachabilitySummary.From(new([Analyzed(Shell("A.M()", 1), Memory("B.M()", 1), Plain("C.M()", 1))]))).ToJson();

        var back = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(json, back.ToJson());
        var ssa = back.Reachability!.Folders[0].Ssa!;
        Assert.Equal([SsaSignal.ShellInterpreter, SsaSignal.ExecutableMemory], ssa.Signals!.Select(s => s.Signal));
        Assert.Equal([SsaSignal.ShellInterpreter], ssa.Sites[0].Signals);
    }

    // A report written before the signals existed: no key anywhere, and it reads as no signals.
    [Fact]
    public void Json_FromBeforeSignals_StillReads_WithNone()
    {
        var node = JsonNode.Parse(ReportWith(ReachabilitySummary.From(new([Analyzed(Shell("A.M()", 1))]))).ToJson())!;
        var ssa = node["Reachability"]!["Folders"]![0]!["Ssa"]!.AsObject();
        ssa.Remove("Signals");
        foreach (var site in ssa["Sites"]!.AsArray())
            site!.AsObject().Remove("Signals");

        var back = PackageCapabilityReport.FromJson(node.ToJsonString())!;

        var read = back.Reachability!.Folders[0].Ssa!;
        Assert.Null(read.Signals);
        Assert.Null(Assert.Single(read.Sites).Signals);
        Assert.DoesNotContain("\"Signals\"", back.ToJson(), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: helpers
    private static FolderSsaSummary Summary(params SsaSinkFact[] facts) => SsaSummary.Of(Ssa(facts), copy: false)!;

    private static FolderSsa Ssa(params SsaSinkFact[] facts) =>
        new(SsaFolderOutcome.Analyzed, new SsaFolderFacts(facts, facts.Length, false, facts.Length, [], false, false, false, 0), null);

    private static FolderReachability Analyzed(params SsaSinkFact[] facts) => S.Analyzed("lib/net8.0", S.Report([])) with { Ssa = Ssa(facts) };

    // `count` sites, each a shell start (or a plain read when `plain`), callers Own.M000() and on.
    private static FolderReachability Folder(string folder, int count, bool plain) =>
        S.Analyzed(folder, S.Report([])) with
        {
            Ssa = Ssa([.. Enumerable.Range(0, count).Select(i => plain ? Plain($"Own.M{i:000}()", 1, Capability.FileSystem) : Shell($"Own.M{i:000}()", 1))]),
        };

    private static SsaSinkFact Shell(string caller, uint offset) =>
        T.Fact(T.Site(caller, offset, Capability.ProcessExecution, "System.Diagnostics.Process.Start"), args: [T.Str("cmd.exe")]);

    private static SsaSinkFact Stealth(string caller, uint offset) =>
        T.Fact(T.Site(caller, offset, Capability.ProcessExecution, "System.Diagnostics.Process.Start"), args: [T.Str("tool.exe"), T.Str("-w hidden")]);

    private static SsaSinkFact Secret(string caller, uint offset) =>
        T.Fact(T.Site(caller, offset, Capability.EnvironmentProbe, "System.Environment.GetEnvironmentVariable"), args: [T.Str("GITHUB_TOKEN")]);

    // Own.Native.Alloc: a P/Invoke whose entry is VirtualAlloc, asked for 0x40.
    private static SsaSinkFact Memory(string caller, uint offset) =>
        T.Fact(T.Site(caller, offset, Capability.NativeInterop, "Own.Native.Alloc"), args: [Int("0"), Int("4096"), Int("12288"), Int("64")]) with { Import = "VirtualAlloc" };

    private static SsaSinkFact Plain(string caller, uint offset, Capability capability = Capability.FileSystem) =>
        T.Fact(T.Site(caller, offset, capability, "System.IO.File.ReadAllText"), args: [T.Str("x")]);

    private static SsaValue Int(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Int, text));

    private static PackageCapabilityReport ReportWith(ReachabilitySummary reachability) => new(
        new PackageIdentityInfo("Pkg", "1.0.0", "Silvergun Tests", "SSA signals.", []),
        new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero),
        [],
        [],
        [],
        YaraScanStatus: YaraScanStatus.NotRun,
        ScriptScanStatus: ScriptScanStatus.Completed,
        Reachability: reachability);

    private static string Json(object? value) => JsonSerializer.Serialize(value, json);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions json = new() { Converters = { new JsonStringEnumConverter() } };
    #endregion
}
