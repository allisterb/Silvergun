namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet.Graph;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using S = Silvergun.PackageAnalysis.NuGet.Tests.ReachabilitySummaryTests;

/// <summary>
/// SSA facts in the scan report, S5.1 (<c>docs/agent/tasks/ssa-facts-s5.md</c> §2 and §3): <see cref="SsaSummary.Of"/>,
/// <see cref="SsaSummary.Capped"/> and <see cref="FolderSsaSummary.Incomplete"/> over hand-built <see cref="FolderSsa"/>
/// records, and their place in <see cref="ReachabilitySummary.From"/>. Which sites are listed (only Analyzed sites with a
/// constant argument, receiver or reflection target), their order, the caps, a copy's empty list, the value text of §3,
/// targets and candidates, escaping and bounds on crafted input, the incompleteness predicate, that nothing throws, and
/// that SSA never moves <see cref="ReachabilitySummary.Complete"/> nor any byte of the JSON outside <c>Ssa</c>. Hostile
/// characters are built from code points; the source holds none raw, nor any backslash escape of one.
/// </summary>
public sealed class SsaSummaryTests
{
    #region Methods: premises
    [Fact]
    public void Premise_TheBoundsAreTheSpecs()
    {
        Assert.Equal(100, SsaSummary.MaxSitesPerFolder);
        Assert.Equal(1_000, SsaSummary.MaxSites);
        Assert.Equal(1_024, SsaSummary.MaxCallChars);
        Assert.Equal(8, SsaSummary.MaxCandidates);
        Assert.Equal(256, ReachabilitySummary.MaxNameChars);
    }
    #endregion

    #region Methods: SSA not asked for
    [Fact]
    public void Of_Null_IsNull()
    {
        Assert.Null(SsaSummary.Of(null, copy: false));
        Assert.Null(SsaSummary.Of(null, copy: true));
    }

    // Without SSA no folder carries an Ssa key, so the report's JSON is what it was before S5.
    [Fact]
    public void Json_WithoutSsa_HasNoSsaKey_AnywhereInTheReport()
    {
        var json = ReportWith(ReachabilitySummary.From(GraphReport(ssa: null))).ToJson();

        var folders = JsonNode.Parse(json)!["Reachability"]!["Folders"]!.AsArray();
        Assert.Equal(3, folders.Count);
        Assert.All(folders, f => Assert.False(f!.AsObject().ContainsKey("Ssa"), f.ToJsonString()));
        Assert.DoesNotContain("\"Ssa\"", json, StringComparison.Ordinal);
    }

    // With SSA, everything but the Ssa objects is byte for byte the summary without it (acceptance criterion 2).
    [Fact]
    public void Json_WithSsa_IsByteIdentical_OnceTheSsaObjectsAreRemoved()
    {
        var without = ReachabilitySummary.From(GraphReport(ssa: null));
        var with = ReachabilitySummary.From(GraphReport(ssa: AnalyzedSsa(Fact(Site("Own.A()", 4), args: [Str("cmd.exe")]))));
        Assert.All(with.Folders, f => Assert.NotNull(f.Ssa));   // the premise: every folder carries SSA

        var stripped = with with { Folders = [.. with.Folders.Select(f => f with { Ssa = null })] };

        Assert.Equal(ReportWith(without).ToJson(), ReportWith(stripped).ToJson());
        Assert.Equal(without.Complete, with.Complete);
        Assert.Equal(without.StatementsDropped, with.StatementsDropped);
        Assert.NotEqual(ReportWith(without).ToJson(), ReportWith(with).ToJson());
    }

    // The report's JSON with SSA reads back and writes out byte for byte.
    [Fact]
    public void Json_WithSsa_RoundTrips()
    {
        var target = Target(SsaTargetKind.Method, Str("Own.Target"), Str("Run"), candidates: ["Own.Target.Run()"], gap: "the index has a gap");
        var ssa = AnalyzedSsa(
            [
                Fact(Site("Own.A()", 4), args: [Str("cmd.exe"), Param(1), Dyn()], argumentCount: 9, merged: true),
                Fact(Site("Own.B()", 8, Capability.ReflectionInvocation, "System.Reflection.MethodBase.Invoke"), receiver: Dyn(), target: target),
                Fact(Site("Own.C()", 2), SsaSiteStatus.MethodUnknown, failure: SsaFailureKind.UnresolvedFact, reason: "r"),
            ],
            unknown: [new SsaFailureCount(SsaFailureKind.UnresolvedFact, 1)]);
        var json = ReportWith(ReachabilitySummary.From(GraphReport(ssa))).ToJson();

        var back = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(json, back.ToJson());
        Assert.Equal(2, back.Reachability!.Folders[0].Ssa!.Sites.Count);
        Assert.Equal("Analyzed", JsonNode.Parse(json)!["Reachability"]!["Folders"]![0]!["Ssa"]!["Outcome"]!.GetValue<string>());
    }
    #endregion

    #region Methods: which sites are listed
    [Theory]
    [MemberData(nameof(ResolvedValues))]
    public void Of_AnalyzedSiteWithAResolvedArgument_IsListed(string what, SsaValue value)
    {
        var summary = Summary(Fact(Site("Own.A()", 4), args: [Dyn(), value]));

        Assert.True(Assert.Single(summary.Sites) is not null, what);
        Assert.Equal(0, summary.SitesDropped);
    }

    [Theory]
    [MemberData(nameof(ResolvedValues))]
    public void Of_AnalyzedSiteWithAResolvedReceiver_IsListed(string what, SsaValue value)
    {
        var summary = Summary(Fact(Site("Own.A()", 4), receiver: value, args: [Dyn()]));

        Assert.True(Assert.Single(summary.Sites) is not null, what);
    }

    // Parameter, Dynamic of every origin, and a missing value: nothing resolved, nothing listed (but counted).
    [Theory]
    [MemberData(nameof(UnresolvedValues))]
    public void Of_AnalyzedSiteWithOnlyUnresolvedValues_IsNotListed(string what, SsaValue? value)
    {
        var summary = Summary(Fact(Site("Own.A()", 4), receiver: value, args: [value!, Param(0)]));

        Assert.True(summary.Sites.Count == 0, what);
        Assert.Equal(0, summary.SitesDropped);
        Assert.Equal(1, summary.Counts!.Analyzed);
    }

    [Fact]
    public void Of_ConstantTargetType_IsListed_EvenWithEveryArgumentDynamic()
    {
        var summary = Summary(Fact(Site("Own.A()", 4), receiver: Dyn(), args: [Dyn()], target: Target(SsaTargetKind.Type, Str("Own.Target"), null)));

        Assert.NotNull(Assert.Single(summary.Sites).Target);
    }

    [Fact]
    public void Of_ConstantTargetMember_IsListed_EvenWithADynamicType()
    {
        var summary = Summary(Fact(Site("Own.A()", 4), receiver: Dyn(), target: Target(SsaTargetKind.Method, Dyn(SsaDynamicOrigin.FieldLoad), OneOf("Run", "Stop"))));

        Assert.NotNull(Assert.Single(summary.Sites).Target);
    }

    // A target naming nothing constant (here a constant assembly only) is no resolved target.
    [Fact]
    public void Of_TargetWithOnlyDynamicTypeAndMember_IsNotListed()
    {
        var target = Target(SsaTargetKind.Method, Param(1), Dyn(SsaDynamicOrigin.CallResult), assembly: Str("Asm"));

        Assert.Empty(Summary(Fact(Site("Own.A()", 4), receiver: Dyn(), args: [Dyn()], target: target)).Sites);
    }

    // A site that was not analysed says nothing about its values: never listed, even when a crafted fact carries constants.
    [Theory]
    [InlineData(SsaSiteStatus.MethodUnknown)]
    [InlineData(SsaSiteStatus.NotJoined)]
    [InlineData(SsaSiteStatus.NotRun)]
    public void Of_SiteNotAnalysed_IsNeverListed_ButCounted(SsaSiteStatus status)
    {
        var crafted = Fact(Site("Own.A()", 4), status, receiver: Str("r"), args: [Str("cmd.exe")], target: Target(SsaTargetKind.Type, Str("Own.T"), null));

        var summary = Summary(crafted);

        Assert.Empty(summary.Sites);
        Assert.Equal(0, summary.SitesDropped);
        var c = summary.Counts!;
        Assert.Equal(
            (0, status == SsaSiteStatus.MethodUnknown ? 1 : 0, status == SsaSiteStatus.NotJoined ? 1 : 0, status == SsaSiteStatus.NotRun ? 1 : 0),
            (c.Analyzed, c.MethodUnknown, c.NotJoined, c.NotRun));
    }

    [Fact]
    public void Of_Counts_CarryTheFactsCountsAndFlags()
    {
        var facts = new SsaFolderFacts(
            [
                Fact(Site("Own.A()", 1), args: [Str("x")]),
                Fact(Site("Own.A()", 2), args: [Dyn()]),
                Fact(Site("Own.B()", 1), SsaSiteStatus.MethodUnknown, failure: SsaFailureKind.Bounds, reason: "r"),
                Fact(Site("Own.C()", 1), SsaSiteStatus.NotJoined, reason: "r"),
                Fact(Site("Own.C()", 2), SsaSiteStatus.NotJoined, reason: "r"),
                Fact(Site("Own.D()", 1), SsaSiteStatus.NotRun, reason: "r"),
            ],
            SitesTotal: 9, Truncated: true, MethodsLifted: 17, Unknown: [new SsaFailureCount(SsaFailureKind.Bounds, 1)],
            MethodBudget: true, TimeBudget: false, TextBudget: true, AssembliesLost: 0);

        var c = SsaSummary.Of(new FolderSsa(SsaFolderOutcome.Analyzed, facts, null), copy: false)!.Counts!;

        Assert.Equal((2, 1, 2, 1, 9, true, 17), (c.Analyzed, c.MethodUnknown, c.NotJoined, c.NotRun, c.SitesTotal, c.Truncated, c.MethodsLifted));
        Assert.Equal((true, false, true, 0), (c.MethodBudget, c.TimeBudget, c.TextBudget, c.AssembliesLost));
        Assert.Equal((SsaFailureKind.Bounds, 1), (Assert.Single(c.Unknown).Kind, c.Unknown[0].Methods));
    }

    [Fact]
    public void Of_AnalyzedFolder_HasNoReason_EvenWhenTheRecordCarriesOne()
    {
        var summary = SsaSummary.Of(new FolderSsa(SsaFolderOutcome.Analyzed, Facts(), "stray"), copy: false)!;

        Assert.Null(summary.Reason);
        Assert.Equal(SsaFolderOutcome.Analyzed, summary.Outcome);
    }
    #endregion

    #region Methods: order
    // Resolved targets first, then capability in enum order, then caller (ordinal: 'B' < 'a'), offset, callee.
    [Fact]
    public void Of_Sites_AreInTheSpecsOrder()
    {
        var facts = new[]
        {
            Fact(Site("a.M()", 1, Capability.FileSystem, callee: "Z"), args: [Str("1")]),
            Fact(Site("B.M()", 9, Capability.RuntimeControl, callee: "T"), receiver: Dyn(), target: Target(SsaTargetKind.Type, Str("Own.T"), null)),
            Fact(Site("B.M()", 10, Capability.FileSystem, callee: "Y"), args: [Str("2")]),
            Fact(Site("B.M()", 2, Capability.FileSystem, callee: "X"), args: [Str("3")]),
            Fact(Site("B.M()", 2, Capability.FileSystem, callee: "W"), args: [Str("4")]),
            Fact(Site("A.M()", 1, Capability.ProcessExecution, callee: "V"), args: [Str("5")]),
            Fact(Site("Z.M()", 1, Capability.ReflectionInvocation, callee: "U"), target: Target(SsaTargetKind.Method, Dyn(), Str("Run"))),
            Fact(Site("A.M()", 1, Capability.FileSystem, callee: "S"), args: [Str("6")]),
        };

        var sites = Summary(facts).Sites;

        Assert.Equal(
            [
                ("Z.M()", 1u, "U"),   // ReflectionInvocation, resolved target
                ("B.M()", 9u, "T"),   // RuntimeControl, resolved target
                ("A.M()", 1u, "S"),   // FileSystem ...
                ("B.M()", 2u, "W"),
                ("B.M()", 2u, "X"),
                ("B.M()", 10u, "Y"),
                ("a.M()", 1u, "Z"),
                ("A.M()", 1u, "V"),   // ProcessExecution
            ],
            sites.Select(s => (s.Caller, s.Offset, s.Callee)));
    }

    [Fact]
    public void Of_IsDeterministic_WhateverTheFactOrder()
    {
        var facts = Enumerable.Range(0, 40)
            .Select(i => Fact(Site($"N{i % 7}.M()", (uint)(i % 5), (Capability)(i % 11), callee: $"C{i % 3}"), args: [Str($"v{i}")]))
            .ToArray();

        var forward = JsonSerializer.Serialize(Summary(facts), json);
        var backward = JsonSerializer.Serialize(Summary([.. facts.Reverse()]), json);

        Assert.Equal(forward, backward);
        Assert.Equal(40, Summary(facts).Sites.Count);
    }
    #endregion

    #region Methods: caps
    [Fact]
    public void Of_ListsAtMostOneHundredSites_AndCountsTheRest()
    {
        var facts = Enumerable.Range(0, 150).Select(i => Fact(Site($"Own.M{i:000}()", 1), args: [Str("x")])).ToArray();

        var summary = Summary(facts);

        Assert.Equal(100, summary.Sites.Count);
        Assert.Equal(50, summary.SitesDropped);
        Assert.Equal(Enumerable.Range(0, 100).Select(i => $"Own.M{i:000}()"), summary.Sites.Select(s => s.Caller));
        Assert.Equal(150, summary.Counts!.Analyzed);
    }

    // Only resolved sites count against the cap: unresolved ones are neither listed nor dropped.
    [Fact]
    public void Of_UnresolvedSites_AreNotCountedAsDropped()
    {
        var facts = Enumerable.Range(0, 100).Select(i => Fact(Site($"Own.R{i:000}()", 1), args: [Str("x")]))
            .Concat(Enumerable.Range(0, 300).Select(i => Fact(Site($"Own.U{i:000}()", 1), args: [Param(1)])))
            .ToArray();

        var summary = Summary(facts);

        Assert.Equal((100, 0), (summary.Sites.Count, summary.SitesDropped));
    }

    // 10 folders of 95 (950), then one of 150 resolved (100 by its own cap, then 50 by the package's), then one of 5 (none
    // left): the package lists 1,000, in folder order, and each folder's SitesDropped adds what the package cap took.
    [Fact]
    public void From_ListsAtMostOneThousandSitesPerPackage_InFolderOrder()
    {
        var folders = Enumerable.Range(0, 10).Select(i => SsaFolder($"lib/f{i:00}", 95))
            .Append(SsaFolder("lib/f10", 150))
            .Append(SsaFolder("lib/f11", 5))
            .ToArray();

        var summary = ReachabilitySummary.From(new(folders));

        Assert.Equal(1_000, summary.Folders.Sum(f => f.Ssa!.Sites.Count));
        Assert.All(summary.Folders.Take(10), f => Assert.Equal((95, 0), (f.Ssa!.Sites.Count, f.Ssa.SitesDropped)));
        Assert.Equal((50, 100), (summary.Folders[10].Ssa!.Sites.Count, summary.Folders[10].Ssa!.SitesDropped));
        Assert.Equal((0, 5), (summary.Folders[11].Ssa!.Sites.Count, summary.Folders[11].Ssa!.SitesDropped));
        // The package cap keeps each folder's first sites, in the folder's own order.
        Assert.Equal(Enumerable.Range(0, 50).Select(i => $"Own.M{i:000}()"), summary.Folders[10].Ssa!.Sites.Select(s => s.Caller));
        Assert.Equal(10 * 95 + 150 + 5 - 1_000, summary.Folders.Sum(f => f.Ssa!.SitesDropped));
    }

    [Fact]
    public void Capped_UnderTheCap_ReturnsTheFoldersUnchanged()
    {
        var folders = ReachabilitySummary.From(new([SsaFolder("lib/a", 3), SsaFolder("lib/b", 4)])).Folders;

        var capped = SsaSummary.Capped(folders);

        Assert.Equal(JsonSerializer.Serialize(folders, json), JsonSerializer.Serialize(capped, json));
    }

    [Fact]
    public void Capped_FoldersWithoutSsa_PassThrough()
    {
        var folders = ReachabilitySummary.From(new([S.Analyzed("lib/a", S.Report([])), SsaFolder("lib/b", 2)])).Folders;

        var capped = SsaSummary.Capped(folders);

        Assert.Null(capped[0].Ssa);
        Assert.Equal(2, capped[1].Ssa!.Sites.Count);
    }

    [Fact]
    public void Of_Copy_ListsNoSites_ButKeepsTheCounts()
    {
        var ssa = AnalyzedSsa(Fact(Site("Own.A()", 4), args: [Str("x")]), Fact(Site("Own.B()", 4), SsaSiteStatus.NotRun, reason: "r"));

        var primary = SsaSummary.Of(ssa, copy: false)!;
        var copy = SsaSummary.Of(ssa, copy: true)!;

        Assert.Single(primary.Sites);
        Assert.Empty(copy.Sites);
        Assert.Equal(0, copy.SitesDropped);
        Assert.Equal(JsonSerializer.Serialize(primary.Counts, json), JsonSerializer.Serialize(copy.Counts, json));
        Assert.Equal(primary.Incomplete(), copy.Incomplete());
    }

    // Through From: a SameAs folder is a copy, as for statements; a copy whose role changes the triggers is listed in full.
    [Fact]
    public void From_SameAsFolder_ListsNoSites_UnlessItsRoleMakesItNoCopy()
    {
        var ssa = AnalyzedSsa(Fact(Site("Own.A()", 4), args: [Str("x")]));
        var report = S.Report([S.Row(RootClass.Finalizer, Capability.ProcessExecution, 1, 1)]);

        var summary = ReachabilitySummary.From(new(
        [
            S.Analyzed("lib/net8.0", report) with { Ssa = ssa },
            S.Analyzed("lib/net9.0", report, sameAs: "lib/net8.0") with { Ssa = ssa },
            S.Analyzed("tools/net8.0", report, sameAs: "lib/net8.0") with { Ssa = ssa },
        ]));

        Assert.Single(summary.Folders[0].Ssa!.Sites);
        Assert.Equal("lib/net8.0", summary.Folders[1].SameAs);
        Assert.Empty(summary.Folders[1].Ssa!.Sites);
        Assert.Equal(1, summary.Folders[1].Ssa!.Counts!.Analyzed);
        Assert.Null(summary.Folders[2].SameAs);   // the premise: listed in full
        Assert.Single(summary.Folders[2].Ssa!.Sites);
    }
    #endregion

    #region Methods: values (§3)
    [Fact]
    public void Call_IsTheCalleeKeyWithItsArguments()
    {
        Assert.Equal("System.Diagnostics.Process.Start(\"cmd.exe\")", CallOf(Fact(Site("Own.A()", 4), args: [Str("cmd.exe")])));
    }

    [Fact]
    public void Call_StringWithAQuote_EscapesTheQuote()
    {
        Assert.Equal($"K(\"a{Bs}\"b\")", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str("a\"b")])));
    }

    // The worker doubled the backslash, and display escaping leaves it (and a printable escape) as they are.
    [Fact]
    public void Call_AlreadyEscapedText_IsUnchanged()
    {
        var doubled = $"a{Bs}{Bs}b";
        var escape = $"{Bs}x1b{Bs}u202e{Bs}U000E0041";

        Assert.Equal($"K(\"{doubled}\", \"{escape}\")", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str(doubled), Str(escape)])));
    }

    [Fact]
    public void Call_CutString_KeepsItsSuffixOutsideTheQuotes()
    {
        var suffix = Ellipsis + "[+300 chars, sha256:0123abcd]";

        Assert.Equal($"K(\"abc\"{suffix})", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str("abc" + suffix, cut: true)])));
    }

    // Past the folder's text budget a String constant keeps only its hash suffix: shown as `string <suffix>`, never as an
    // empty literal "".
    [Fact]
    public void Call_HashOnlyString_IsTheWordStringAndTheSuffix_WithoutQuotes()
    {
        var suffix = Ellipsis + "[+10240 chars, sha256:0123abcd]";

        var call = CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str(suffix, cut: true), Str("y")]));

        Assert.Equal($"K(string {suffix}, \"y\")", call);
        Assert.DoesNotContain("\"\"", call, StringComparison.Ordinal);
    }

    [Fact]
    public void Call_HashOnlyStringInOneOfAndReceiver_IsRenderedTheSameWay()
    {
        var suffix = Ellipsis + "[+300 chars, sha256:89abcdef]";
        var oneOf = new SsaValue(SsaValueKind.OneOf, [new(SsaConstantKind.String, "a"), new(SsaConstantKind.String, suffix, true)], null, null);

        var call = CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), receiver: Str(suffix, cut: true), args: [oneOf]));

        Assert.Equal($"K(one of \"a\" | string {suffix}) on string {suffix}", call);
    }

    // The worker's own hash-only text (UntrustedText.HashOnly) is recognised as such.
    [Fact]
    public void Call_WorkersHashOnlyText_IsRecognised()
    {
        var hashOnly = UntrustedText.HashOnly(new string('A', 10_240));

        Assert.Equal($"K(string {hashOnly})", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str(hashOnly, cut: true)])));
    }

    // Without Cut, a text that is only a suffix is a string that happens to spell one: quoted whole.
    [Fact]
    public void Call_UncutTextSpellingOnlyASuffix_IsQuotedWhole()
    {
        var suffix = Ellipsis + "[+3 chars, sha256:0123abcd]";

        Assert.Equal($"K(\"{suffix}\")", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str(suffix)])));
    }

    // In a reflection target, too.
    [Fact]
    public void Target_HashOnlyTypeName_IsTheWordStringAndTheSuffix()
    {
        var suffix = Ellipsis + "[+500 chars, sha256:0123abcd]";

        var target = Assert.Single(Summary(Fact(Site("Own.A()", 4), target: Target(SsaTargetKind.Method, Str(suffix, cut: true), Str("Run")))).Sites).Target!;

        Assert.Equal($"Method string {suffix} :: \"Run\"", target.Text);
    }

    // W1: a Type name is attacker-named metadata. Whatever it spells (a closing paren and a second argument, a receiver
    // clause, a member, an assembly, an alternative), it stays inside one quoted literal, in every position a value can
    // take: argument, receiver, OneOf alternative, target type and target member. Stripping the quoted literals leaves
    // only the renderer's own skeleton.
    [Theory]
    [MemberData(nameof(ForgingNames))]
    public void Call_TypeNameForgingAClause_StaysInsideOneLiteral(string payload)
    {
        var name = "Own.T" + payload;
        var e = Escaped(name);
        var typeName = Const(SsaConstantKind.Type, name);
        var oneOf = new SsaValue(SsaValueKind.OneOf, [new(SsaConstantKind.Type, name), new(SsaConstantKind.String, "z")], null, null);

        var argument = CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [typeName]));
        var receiver = CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), receiver: typeName));
        var alternative = CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [oneOf]));
        var target = Assert.Single(Summary(Fact(Site("Own.A()", 4), target: Target(SsaTargetKind.Method, typeName, typeName))).Sites).Target!.Text;

        Assert.Equal($"K(typeof(\"{e}\"))", argument);
        Assert.Equal($"K() on typeof(\"{e}\")", receiver);
        Assert.Equal($"K(one of typeof(\"{e}\") | \"z\")", alternative);
        Assert.Equal($"Method typeof(\"{e}\") :: typeof(\"{e}\")", target);
        Assert.Equal("K(typeof())", StripLiterals(argument));
        Assert.Equal("K() on typeof()", StripLiterals(receiver));
        Assert.Equal("K(one of typeof() | )", StripLiterals(alternative));
        Assert.Equal("Method typeof() :: typeof()", StripLiterals(target));
    }

    // A lone backslash before a quote is NOT held by the summary: it escapes the quote but trusts the worker to have
    // doubled every backslash, so `T\"), typeof("cmd` reads as an escaped backslash, a closing quote and a forged second
    // argument. The protection is the parent's check (GraphWorkerProcess.ValueProblem, review round 2 N1): such a record is
    // a protocol break (GraphWorkerSsaParentTests.WorkerV2_AConstantNotEscapedByTheEscaper_IsAProtocolBreak), so this text
    // never reaches a summary. Pinned so that relying on the parent stays a decision, not an accident.
    [Fact]
    public void Call_LoneBackslashBeforeAQuote_IsTrustedAsTheWorkersEscape_TheParentRejectsIt()
    {
        var forged = "T" + Bs + "\"), typeof(\"cmd";

        var call = CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Const(SsaConstantKind.Type, forged)]));

        Assert.Equal($"K(typeof(\"T{Bs}{Bs}\"), typeof({Bs}\"cmd\"))", call);
        Assert.NotEqual("K(typeof())", StripLiterals(call));   // the literal breaks out here; the parent never lets it in
        // The worker's own escaping of the same raw text doubles the backslash, and then it stays in one literal.
        var escaped = UntrustedText.EscapeBounded(forged, 256);
        Assert.Equal("K(typeof())", StripLiterals(CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Const(SsaConstantKind.Type, escaped)]))));
    }

    // The same names as String constants: the same one literal.
    [Theory]
    [MemberData(nameof(ForgingNames))]
    public void Call_StringForgingAClause_StaysInsideOneLiteral(string payload)
    {
        var text = "Own.T" + payload;

        var call = CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), receiver: Str(text), args: [Str(text), OneOf(text, "z")]));

        Assert.Equal($"K(\"{Escaped(text)}\", one of \"{Escaped(text)}\" | \"z\") on \"{Escaped(text)}\"", call);
        Assert.Equal("K(, one of  | ) on ", StripLiterals(call));
    }

    [Fact]
    public void Call_TypeNameWithAQuote_EscapesIt()
    {
        Assert.Equal($"K(typeof(\"A{Bs}\"B\"))", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Const(SsaConstantKind.Type, "A\"B")])));
    }

    // A cut Type name keeps its suffix outside the quotes; one cut to the suffix alone reads `type <suffix>`.
    [Fact]
    public void Call_CutTypeName_KeepsItsSuffixOutsideTheQuotes()
    {
        var suffix = Ellipsis + "[+700 chars, sha256:0123abcd]";

        Assert.Equal($"K(typeof(\"Own.Lo\"{suffix}))", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Cut(SsaConstantKind.Type, "Own.Lo" + suffix)])));
        Assert.Equal($"K(typeof(type {suffix}))", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Cut(SsaConstantKind.Type, suffix)])));
    }

    // N1: a crafted Cut text whose mark is followed by anything but the exact suffix is quoted whole, String and Type alike:
    // the mark (U+2026, "[+") then `", "x` must not close the literal and open a second argument.
    [Theory]
    [MemberData(nameof(ForgedSuffixes))]
    public void Call_CutTextWithAForgedMark_IsQuotedWhole(string tail)
    {
        var text = "abc" + tail;
        var e = Escaped(text);

        var call = CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str(text, cut: true), Cut(SsaConstantKind.Type, text)]));

        Assert.Equal($"K(\"{e}\", typeof(\"{e}\"))", call);
        Assert.Equal("K(, typeof())", StripLiterals(call));
    }

    // A forged mark earlier in the text does not stop the genuine suffix at the end from splitting.
    [Fact]
    public void Call_ForgedMarkBeforeAGenuineSuffix_SplitsOnlyTheGenuineOne()
    {
        var suffix = Ellipsis + "[+40 chars, sha256:fedcba98]";
        var kept = "a" + Ellipsis + "[+1 chars, sha256:00000000]b" + Ellipsis + "[+\", \"x";

        var call = CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str(kept + suffix, cut: true)]));

        Assert.Equal($"K(\"{Escaped(kept)}\"{suffix})", call);
    }

    // Only Cut says the text is cut: an uncut string that spells a suffix is quoted whole.
    [Fact]
    public void Call_UncutStringSpellingASuffix_IsQuotedWhole()
    {
        var text = "abc" + Ellipsis + "[+3 chars, sha256:0123abcd]";

        Assert.Equal($"K(\"{text}\")", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str(text)])));
    }

    [Fact]
    public void Call_CutStringWithoutTheMark_IsQuotedWhole()
    {
        Assert.Equal("K(\"abc\")", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str("abc", cut: true)])));
    }

    [Fact]
    public void Call_RendersEveryValueKind()
    {
        var fact = Fact(Site("Own.A()", 4, calleeKey: "K"), args:
        [
            Str("s"),
            Const(SsaConstantKind.Int, "-42"),
            Const(SsaConstantKind.Float, "1.5"),
            Const(SsaConstantKind.Null, ""),
            Const(SsaConstantKind.Type, "Own.Target"),
            OneOf("a", "b"),
            Param(2),
            Dyn(SsaDynamicOrigin.CallResult),
        ]);

        Assert.Equal("K(\"s\", -42, 1.5, null, typeof(\"Own.Target\"), one of \"a\" | \"b\", arg 2 of the caller, _)", CallOf(fact));
    }

    [Fact]
    public void Call_OneOfMixedKinds_RendersEachAlternative()
    {
        var value = new SsaValue(SsaValueKind.OneOf, [new(SsaConstantKind.Null, ""), new(SsaConstantKind.Int, "1"), new(SsaConstantKind.String, "x")], null, null);

        Assert.Equal("K(one of null | 1 | \"x\")", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [value])));
    }

    [Fact]
    public void Call_MoreArgumentsThanKept_EndsWithAnEllipsis()
    {
        var fact = Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str("x"), Dyn()], argumentCount: 10);

        Assert.Equal($"K(\"x\", _, {Ellipsis})", CallOf(fact));
    }

    [Fact]
    public void Call_AllArgumentsKept_HasNoEllipsis()
    {
        Assert.Equal("K(\"x\", _)", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str("x"), Dyn()], argumentCount: 2)));
    }

    [Fact]
    public void Call_ConstantReceiver_IsShownAfterTheCall()
    {
        Assert.Equal("K(_) on \"r\"", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), receiver: Str("r"), args: [Dyn()])));
        Assert.Equal("K() on one of \"a\" | \"b\"", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), receiver: OneOf("a", "b"))));
    }

    [Fact]
    public void Call_UnresolvedReceiver_IsNotShown()
    {
        Assert.Equal("K(\"x\")", CallOf(Fact(Site("Own.A()", 4, calleeKey: "K"), receiver: Param(0), args: [Str("x")])));
    }

    [Fact]
    public void Site_CarriesCallerCalleeCapabilityOffsetAndMerged()
    {
        var site = Assert.Single(Summary(Fact(Site("Own.A()", 77, Capability.Network, "K", "Ext.K(System.String)"), args: [Str("x")], merged: true)).Sites);

        Assert.Equal(("Own.A()", "Ext.K(System.String)", Capability.Network, 77u, true), (site.Caller, site.Callee, site.Capability, site.Offset, site.Merged));
        Assert.Null(site.Target);
    }

    [Fact]
    public void Value_EdgeCases_ReadAsUnknown()
    {
        Assert.Equal("_", SsaSummary.Value(null));
        Assert.Equal("_", SsaSummary.Value(Dyn(SsaDynamicOrigin.TooDeep)));
        Assert.Equal("_", SsaSummary.Value(new SsaValue(SsaValueKind.Constant, [], null, null)));   // crafted: no constant
        Assert.Equal("_", SsaSummary.Value(new SsaValue(SsaValueKind.Parameter, [], null, null)));  // crafted: no index
        Assert.Equal("arg 0 of the caller", SsaSummary.Value(Param(0)));
    }
    #endregion

    #region Methods: targets
    [Fact]
    public void Target_Text_IsKindTypeMemberAndAssembly()
    {
        var fact = Fact(Site("Own.A()", 4), target: Target(SsaTargetKind.Method, Str("Own.Target"), Str("Run"), assembly: Str("Asm")));

        var target = Assert.Single(Summary(fact).Sites).Target!;

        Assert.Equal(SsaTargetKind.Method, target.Kind);
        Assert.Equal("Method \"Own.Target\" :: \"Run\" in assembly \"Asm\"", target.Text);
    }

    [Fact]
    public void Target_WithoutMemberOrAssembly_IsKindAndType()
    {
        var target = Assert.Single(Summary(Fact(Site("Own.A()", 4), target: Target(SsaTargetKind.Type, Const(SsaConstantKind.Type, "Own.Target"), null))).Sites).Target!;

        Assert.Equal("Type typeof(\"Own.Target\")", target.Text);
    }

    [Fact]
    public void Target_DynamicMember_ReadsUnknown()
    {
        var target = Assert.Single(Summary(Fact(Site("Own.A()", 4), target: Target(SsaTargetKind.Member, Str("Own.T"), Param(1)))).Sites).Target!;

        Assert.Equal("Member \"Own.T\" :: arg 1 of the caller", target.Text);
    }

    [Fact]
    public void Target_KeepsAtMostEightCandidates_WithTheTotalAndTheGap()
    {
        var names = Enumerable.Range(0, 10).Select(i => $"Own.Target.Run{i}()").ToArray();
        var fact = Fact(Site("Own.A()", 4), target: Target(SsaTargetKind.Method, Str("Own.Target"), Str("Run"), candidates: names, total: 25, gap: "the graph was truncated"));

        var target = Assert.Single(Summary(fact).Sites).Target!;

        Assert.Equal(names.Take(8), target.Candidates);
        Assert.Equal(25, target.CandidatesTotal);
        Assert.Equal("the graph was truncated", target.CandidatesGap);
    }

    [Fact]
    public void Target_WithoutGap_HasNullGap_AndNoCandidates_IsEmpty()
    {
        var target = Assert.Single(Summary(Fact(Site("Own.A()", 4), target: Target(SsaTargetKind.Method, Str("Own.T"), Str("Run")))).Sites).Target!;

        Assert.Null(target.CandidatesGap);
        Assert.Empty(target.Candidates);
        Assert.Equal(0, target.CandidatesTotal);
    }

    // A target is carried on a site listed for its arguments too, even when the target itself resolved nothing.
    [Fact]
    public void Target_Unresolved_IsStillCarried_OnASiteListedForItsArguments()
    {
        var fact = Fact(Site("Own.A()", 4), args: [Str("x")], target: Target(SsaTargetKind.Method, Dyn(), Dyn()));

        var site = Assert.Single(Summary(fact).Sites);

        Assert.Equal("Method _ :: _", site.Target!.Text);
    }
    #endregion

    #region Methods: escaping and bounds (acceptance criterion 3)
    // A crafted report puts raw hostile characters in every string a site can carry: none reaches the summary raw, each
    // reads as its printable escape.
    [Theory]
    [MemberData(nameof(HostileCodePoints))]
    public void Of_EveryString_IsEscaped_ForEachHostileCodePoint(int codePoint)
    {
        var h = Hostile(codePoint);
        var target = Target(SsaTargetKind.Method, Str("T" + h), OneOf("M" + h, "N" + h), assembly: Str("A" + h), candidates: ["C" + h], total: 1, gap: "G" + h);
        var fact = Fact(Site("Own" + h + ".A()", 4, calleeKey: "K" + h, callee: "E" + h), receiver: Str("R" + h), args: [Str("S" + h), Const(SsaConstantKind.Type, "Y" + h)], target: target);

        var summary = Summary(fact);

        var site = Assert.Single(summary.Sites);
        var strings = Strings(summary).ToArray();
        Assert.Equal(6, strings.Length);   // caller, callee, call, target text, candidate, gap
        Assert.All(strings, s => Assert.True(Clean(s), $"U+{codePoint:X} reached the summary raw: {Visible(s)}"));
        var escaped = UntrustedText.Escape(h);
        Assert.NotEqual(h, escaped);   // the premise: the code point is one the escaper escapes
        Assert.Contains("Own" + escaped + ".A()", site.Caller, StringComparison.Ordinal);
        Assert.Contains("\"S" + escaped + "\"", site.Call, StringComparison.Ordinal);
        Assert.Contains("on \"R" + escaped + "\"", site.Call, StringComparison.Ordinal);
        Assert.Contains("\"M" + escaped + "\"", site.Target!.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Of_NonAnalyzedReason_IsEscaped()
    {
        var reason = "worker" + (char)0x202E + "died" + (char)0x1B + "[2J" + (char)0xD800;

        var summary = SsaSummary.Of(new FolderSsa(SsaFolderOutcome.Crashed, null, reason), copy: false)!;

        Assert.True(Clean(summary.Reason!), Visible(summary.Reason!));
        Assert.Equal(UntrustedText.Escape(reason), summary.Reason);
        Assert.StartsWith("worker" + Bs + "u202edied" + Bs + "x1b[2J", summary.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Of_LongNames_AreCutToMaxNameChars_WithTheHashSuffix()
    {
        var caller = "Own." + new string('c', 1_000) + "()";
        var callee = "Ext." + new string('e', 1_000) + "()";
        var candidate = "Own." + new string('d', 1_000) + "()";
        var gap = new string('g', 1_000);
        var fact = Fact(Site(caller, 4, callee: callee), args: [Str("x")], target: Target(SsaTargetKind.Method, Str("T"), Str("M"), candidates: [candidate], total: 1, gap: gap));

        var site = Assert.Single(Summary(fact).Sites);

        Assert.Equal(Reachability.BoundNameTo(caller, 256), site.Caller);
        Assert.Equal(Reachability.BoundNameTo(callee, 256), site.Callee);
        Assert.Equal(Reachability.BoundNameTo(candidate, 256), Assert.Single(site.Target!.Candidates));
        Assert.Equal(Reachability.BoundNameTo(gap, 256), site.Target.CandidatesGap);
        Assert.Matches(@"\[\+\d+ chars, sha256:[0-9a-f]{8}\]$", site.Caller);
    }

    [Fact]
    public void Of_LongCallAndTarget_AreCutToMaxCallChars()
    {
        var big = new string('x', 5_000);
        var fact = Fact(Site("Own.A()", 4, calleeKey: "K"), args: [Str(big)], target: Target(SsaTargetKind.Method, Str(big), Str("M")));

        var site = Assert.Single(Summary(fact).Sites);

        Assert.Equal(Reachability.BoundNameTo($"K(\"{big}\")", SsaSummary.MaxCallChars), site.Call);
        Assert.Equal(Reachability.BoundNameTo($"Method \"{big}\" :: \"M\"", SsaSummary.MaxCallChars), site.Target!.Text);
        Assert.True(site.Call.Length <= SsaSummary.MaxCallChars + 64, $"the call is {site.Call.Length} chars");
        Assert.Matches(@"\[\+\d+ chars, sha256:[0-9a-f]{8}\]$", site.Call);
    }

    [Fact]
    public void Of_LongReason_IsCutToMaxNameChars()
    {
        var reason = new string('r', 4_000);

        Assert.Equal(Reachability.BoundNameTo(reason, 256), SsaSummary.Of(new FolderSsa(SsaFolderOutcome.NotRun, null, reason), copy: false)!.Reason);
    }

    // The escape comes before the cut, so a hostile character never survives at the cut's edge.
    [Fact]
    public void Of_HostileCharacterAtTheCutEdge_IsStillEscaped()
    {
        var caller = new string('c', 255) + (char)0x202E + new string('c', 100);

        var site = Assert.Single(Summary(Fact(Site(caller, 4), args: [Str("x")])).Sites);

        Assert.True(Clean(site.Caller), Visible(site.Caller));
        Assert.Equal(Reachability.BoundNameTo(UntrustedText.Escape(caller), 256), site.Caller);
    }
    #endregion

    #region Methods: Incomplete
    [Fact]
    public void Incomplete_IsFalse_ForAnAnalyzedFolderWithCleanCounts()
    {
        Assert.False(Complete().Incomplete());
    }

    [Theory]
    [InlineData(SsaFolderOutcome.Crashed)]
    [InlineData(SsaFolderOutcome.TimedOut)]
    [InlineData(SsaFolderOutcome.NotRun)]
    public void Incomplete_IsTrue_ForAnOutcomeOtherThanAnalyzed_EvenWithCleanCounts(SsaFolderOutcome outcome)
    {
        Assert.True((Complete() with { Outcome = outcome }).Incomplete());
    }

    [Fact]
    public void Incomplete_IsTrue_WithoutCounts() => Assert.True((Complete() with { Counts = null }).Incomplete());

    [Fact]
    public void Incomplete_IsTrue_WhenTruncated() => Assert.True(With(c => c with { Truncated = true }).Incomplete());

    [Fact]
    public void Incomplete_IsTrue_WhenTheMethodBudgetRanOut() => Assert.True(With(c => c with { MethodBudget = true }).Incomplete());

    [Fact]
    public void Incomplete_IsTrue_WhenTheTimeBudgetRanOut() => Assert.True(With(c => c with { TimeBudget = true }).Incomplete());

    // ssa-facts-s5.md §2: "Analyzed with a flag set" is SSA-incomplete, and Counts' flags include TextBudget: past it,
    // constants keep only their hash and targets keep no candidate names.
    [Fact]
    public void Incomplete_IsTrue_WhenTheTextBudgetRanOut() => Assert.True(With(c => c with { TextBudget = true }).Incomplete());

    [Fact]
    public void Incomplete_IsTrue_WhenAnAssemblyWasLost() => Assert.True(With(c => c with { AssembliesLost = 1 }).Incomplete());

    [Fact]
    public void Incomplete_IsTrue_WithAMethodUnknownSite() => Assert.True(With(c => c with { MethodUnknown = 1 }).Incomplete());

    [Fact]
    public void Incomplete_IsTrue_WithANotJoinedSite() => Assert.True(With(c => c with { NotJoined = 1 }).Incomplete());

    [Fact]
    public void Incomplete_IsTrue_WithANotRunSite() => Assert.True(With(c => c with { NotRun = 1 }).Incomplete());

    [Fact]
    public void Incomplete_ThroughOf_TextBudgetFlag_MakesItIncomplete()
    {
        var facts = Facts(Fact(Site("Own.A()", 4), args: [Str("x")])) with { TextBudget = true };

        var summary = SsaSummary.Of(new FolderSsa(SsaFolderOutcome.Analyzed, facts, null), copy: false)!;

        Assert.True(summary.Counts!.TextBudget);
        Assert.True(summary.Incomplete());
    }

    // Built through Of, a folder with only Analyzed sites is complete, and one MethodUnknown site makes it incomplete.
    [Fact]
    public void Incomplete_ThroughOf_FollowsTheSiteStatuses()
    {
        Assert.False(Summary(Fact(Site("Own.A()", 4), args: [Str("x")])).Incomplete());
        Assert.False(SsaSummary.Of(new FolderSsa(SsaFolderOutcome.Analyzed, Facts(), null), copy: false)!.Incomplete());   // no sink site at all
        Assert.True(Summary(Fact(Site("Own.A()", 4), args: [Str("x")]), Fact(Site("Own.B()", 4), SsaSiteStatus.MethodUnknown, failure: SsaFailureKind.Adapter, reason: "r")).Incomplete());
    }
    #endregion

    #region Methods: outcomes other than Analyzed
    [Theory]
    [InlineData(SsaFolderOutcome.Crashed)]
    [InlineData(SsaFolderOutcome.TimedOut)]
    [InlineData(SsaFolderOutcome.NotRun)]
    public void Of_NonAnalyzedWithoutFacts_CarriesItsOutcomeAndReason(SsaFolderOutcome outcome)
    {
        var summary = SsaSummary.Of(new FolderSsa(outcome, null, "the folder's graph was not built"), copy: false)!;

        Assert.Equal((outcome, "the folder's graph was not built", (SsaCounts?)null, 0, 0), (summary.Outcome, summary.Reason, summary.Counts, summary.Sites.Count, summary.SitesDropped));
        Assert.True(summary.Incomplete());
    }

    [Theory]
    [InlineData(SsaFolderOutcome.Crashed)]
    [InlineData(SsaFolderOutcome.NotRun)]
    public void Of_NonAnalyzedWithoutAReason_SaysNoReasonWasGiven(SsaFolderOutcome outcome)
    {
        Assert.Equal("no reason was given", SsaSummary.Of(new FolderSsa(outcome, null, null), copy: false)!.Reason);
    }

    // Analyzed in name only (a crafted record without facts): no counts, a reason, and incomplete.
    [Fact]
    public void Of_AnalyzedWithoutFacts_IsIncomplete_WithAReason()
    {
        var summary = SsaSummary.Of(new FolderSsa(SsaFolderOutcome.Analyzed, null, null), copy: false)!;

        Assert.Null(summary.Counts);
        Assert.Equal("no reason was given", summary.Reason);
        Assert.True(summary.Incomplete());
    }

    [Fact]
    public void Of_NonAnalyzedCopy_KeepsItsReason()
    {
        var summary = SsaSummary.Of(new FolderSsa(SsaFolderOutcome.TimedOut, null, "8 s ran out"), copy: true)!;

        Assert.Equal((SsaFolderOutcome.TimedOut, "8 s ran out"), (summary.Outcome, summary.Reason));
    }
    #endregion

    #region Methods: never throws (acceptance criterion 4)
    [Theory]
    [MemberData(nameof(BrokenFacts))]
    public void Of_BrokenFacts_GiveCrashed_ForThatFolderOnly(string what, SsaFolderFacts facts)
    {
        var summary = ReachabilitySummary.From(new(
        [
            S.Analyzed("lib/net8.0", S.Report([])) with { Ssa = AnalyzedSsa(Fact(Site("Own.A()", 4), args: [Str("x")])) },
            S.Analyzed("lib/net9.0", S.Report([])) with { Ssa = new FolderSsa(SsaFolderOutcome.Analyzed, facts, null) },
            S.Analyzed("lib/net10.0", S.Report([])) with { Ssa = AnalyzedSsa(Fact(Site("Own.B()", 4), args: [Str("y")])) },
        ]));

        var broken = summary.Folders[1].Ssa!;
        Assert.True(broken.Outcome == SsaFolderOutcome.Crashed, $"{what}: {broken.Outcome}");
        Assert.StartsWith("the folder's SSA summary could not be built: ", broken.Reason, StringComparison.Ordinal);
        Assert.Null(broken.Counts);
        Assert.Empty(broken.Sites);
        Assert.True(broken.Incomplete());
        Assert.Single(summary.Folders[0].Ssa!.Sites);
        Assert.Single(summary.Folders[2].Ssa!.Sites);
        // The graph's half is untouched: every folder is decided, so the summary is still complete (D4).
        Assert.True(summary.Complete, what);
        Assert.All(summary.Folders, f => Assert.Null(f.Reason));
    }

    // The graph summary of a folder failing does not cost its SSA summary: Summarize attaches it outside that try.
    [Fact]
    public void From_AFolderWhoseGraphSummaryFails_StillCarriesItsSsa()
    {
        var broken = new FolderReachability("lib/net9.0", [], null!, FolderOutcome.Analyzed, S.Report([]), null, null, 0, 0,
            AnalyzedSsa(Fact(Site("Own.A()", 4), args: [Str("x")])));

        var folder = Assert.Single(ReachabilitySummary.From(new([broken])).Folders);

        Assert.StartsWith("the folder's reachability summary could not be built: ", folder.Reason, StringComparison.Ordinal);
        Assert.Single(folder.Ssa!.Sites);
    }

    [Fact]
    public void From_ANullFolder_HasNoSsa_AndDoesNotThrow()
    {
        var summary = ReachabilitySummary.From(new([S.Analyzed("lib/net8.0", S.Report([])) with { Ssa = AnalyzedSsa() }, null!]));

        Assert.Equal(2, summary.Folders.Count);
        Assert.NotNull(summary.Folders[0].Ssa);
        Assert.Null(summary.Folders[1].Ssa);
    }
    #endregion

    #region Methods: Complete never reads SSA (D4)
    [Theory]
    [MemberData(nameof(EverySsaShape))]
    public void From_Complete_IsTheSameWithAndWithoutSsa(string what, FolderSsa ssa)
    {
        foreach (var graph in new[] { GraphReport(null), GraphReport(null, incomplete: true) })
        {
            var with = new PackageReachabilityReport([.. graph.Folders.Select(f => f with { Ssa = ssa })]);

            Assert.True(ReachabilitySummary.From(graph).Complete == ReachabilitySummary.From(with).Complete, what);
        }
    }
    #endregion

    #region Methods: helpers
    private static FolderSsaSummary Summary(params SsaSinkFact[] facts) => SsaSummary.Of(AnalyzedSsa(facts), copy: false)!;

    private static string CallOf(SsaSinkFact fact) => Assert.Single(Summary(fact).Sites).Call;

    private static FolderSsa AnalyzedSsa(params SsaSinkFact[] facts) => AnalyzedSsa(facts, []);

    private static FolderSsa AnalyzedSsa(SsaSinkFact[] facts, IReadOnlyList<SsaFailureCount> unknown) =>
        new(SsaFolderOutcome.Analyzed, Facts(facts) with { Unknown = unknown }, null);

    private static SsaFolderFacts Facts(params SsaSinkFact[] facts) => new(facts, facts.Length, false, facts.Length, [], false, false, false, 0);

    // A folder whose `resolved` sites each have a constant argument: callers Own.M000() and on.
    private static FolderReachability SsaFolder(string folder, int resolved) =>
        S.Analyzed(folder, S.Report([])) with { Ssa = AnalyzedSsa([.. Enumerable.Range(0, resolved).Select(i => Fact(Site($"Own.M{i:000}()", 1), args: [Str("x")]))]) };

    // Three folders, the second a copy of the first; every class decided unless `incomplete`, which adds a NotRun folder.
    private static PackageReachabilityReport GraphReport(FolderSsa? ssa, bool incomplete = false)
    {
        var report = S.Report([S.Row(RootClass.NativeEntry, Capability.Network, 1, 1, S.PathOf(true))]);
        var folders = new List<FolderReachability>
        {
            S.Analyzed("lib/net8.0", report) with { Ssa = ssa },
            S.Analyzed("lib/net9.0", report, sameAs: "lib/net8.0") with { Ssa = ssa },
            S.Analyzed("lib/netstandard2.0", S.Report([])) with { Ssa = ssa },
        };
        if (incomplete)
            folders.Add(S.NotAnalyzed("tools/any", FolderOutcome.NotRun, "cap") with { Ssa = ssa is null ? null : new(SsaFolderOutcome.NotRun, null, "no graph") });
        return new(folders);
    }

    private static PackageCapabilityReport ReportWith(ReachabilitySummary reachability) => new(
        new PackageIdentityInfo("Pkg", "1.0.0", "Silvergun Tests", "SSA summary.", []),
        new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero),
        [],
        [],
        [],
        YaraScanStatus: YaraScanStatus.NotRun,
        ScriptScanStatus: ScriptScanStatus.Completed,
        Reachability: reachability);

    private static FolderSsaSummary Complete() =>
        new(SsaFolderOutcome.Analyzed, null, new SsaCounts(3, 0, 0, 0, 3, false, 2, [], false, false, false, 0), [], 0);

    private static FolderSsaSummary With(Func<SsaCounts, SsaCounts> change) => Complete() with { Counts = change(Complete().Counts!) };

    internal static SinkSite Site(string nodeId, uint offset, Capability capability = Capability.ProcessExecution, string calleeKey = "System.Diagnostics.Process.Start", string? callee = null) =>
        new(nodeId, offset, MethodEdgeKind.Call, callee ?? calleeKey + "(System.String)", calleeKey, capability);

    internal static SsaSinkFact Fact(
        SinkSite site, SsaSiteStatus status = SsaSiteStatus.Analyzed, SsaValue? receiver = null, IReadOnlyList<SsaValue>? args = null,
        int? argumentCount = null, bool merged = false, SsaFailureKind? failure = null, string? reason = null, SsaReflectionTarget? target = null) =>
        new(site, status, receiver, args ?? [], argumentCount ?? (args?.Count ?? 0), merged, failure, reason, target);

    internal static SsaReflectionTarget Target(
        SsaTargetKind kind, SsaValue type, SsaValue? member, SsaValue? assembly = null, IReadOnlyList<string>? candidates = null, int? total = null, string? gap = null) =>
        new(kind, assembly, type, member, SsaCandidateMatch.ByName, candidates ?? [], total ?? (candidates?.Count ?? 0), gap);

    internal static SsaValue Str(string text, bool cut = false) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, text, cut));

    private static SsaValue Const(SsaConstantKind kind, string text) => SsaValue.OfConstant(new SsaConstant(kind, text));

    private static SsaValue Cut(SsaConstantKind kind, string text) => SsaValue.OfConstant(new SsaConstant(kind, text, true));

    // `text` as a literal's body: an inner quote escaped (the worker already doubled backslashes; these hold none).
    private static string Escaped(string text) => text.Replace("\"", Bs + "\"", StringComparison.Ordinal);

    // `text` with every quoted literal's body removed (an escaped quote stays inside its literal).
    private static string StripLiterals(string text) => Regex.Replace(text, "\"(?:\\\\.|[^\"\\\\])*\"", string.Empty);

    public static TheoryData<string> ForgingNames() =>
    [
        "\"), \"cmd.exe",
        "\") on \"r",
        " on \"r\"",
        " :: \"Run\"",
        " in assembly \"x\"",
        "\" | \"y",
        "| y",
    ];

    // Tails that start like the suffix but are not exactly it, at the end of the text.
    public static TheoryData<string> ForgedSuffixes() =>
    [
        Ellipsis + "[+\", \"x",
        Ellipsis + "[+3 chars, sha256:0123abcd]\", \"x",
        Ellipsis + "[+3 chars, sha256:0123ABCD]",
        Ellipsis + "[+3 chars, sha256:0123abc]",
        Ellipsis + "[+x chars, sha256:0123abcd]",
        Ellipsis + "[+3 chars, sha256:0123abcd] ",
        "...[+3 chars, sha256:0123abcd]",
    ];

    private static SsaValue OneOf(params string[] texts) => new(SsaValueKind.OneOf, [.. texts.Select(t => new SsaConstant(SsaConstantKind.String, t))], null, null);

    private static SsaValue Param(int index) => SsaValue.OfParameter(index);

    private static SsaValue Dyn(SsaDynamicOrigin origin = SsaDynamicOrigin.Other) => SsaValue.OfDynamic(origin);

    // Every string a folder's summary carries.
    private static IEnumerable<string> Strings(FolderSsaSummary summary)
    {
        if (summary.Reason is { } reason)
            yield return reason;
        foreach (var site in summary.Sites)
        {
            yield return site.Caller;
            yield return site.Callee;
            yield return site.Call;
            if (site.Target is not { } target)
                continue;
            yield return target.Text;
            foreach (var candidate in target.Candidates)
                yield return candidate;
            if (target.CandidatesGap is { } gap)
                yield return gap;
        }
    }

    // The code point as a string: astral ones as their surrogate pair, lone surrogates as themselves.
    private static string Hostile(int codePoint) => codePoint is >= 0xD800 and <= 0xDFFF ? ((char)codePoint).ToString() : char.ConvertFromUtf32(codePoint);

    // No control, bidi, zero-width, separator, soft hyphen, BOM, Tag-block character, and no lone surrogate.
    private static bool Clean(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                var cp = char.ConvertToUtf32(c, text[++i]);
                if (cp is >= 0xE0000 and <= 0xE007F)
                    return false;
                continue;
            }
            if (char.IsSurrogate(c) || Forbidden(c))
                return false;
        }
        return true;
    }

    private static bool Forbidden(char c) =>
        c < 0x20 || c is >= (char)0x7F and <= (char)0x9F || c == 0xAD
        || c is >= (char)0x200B and <= (char)0x200F || c is >= (char)0x2028 and <= (char)0x202E
        || c is >= (char)0x2060 and <= (char)0x2064 || c is >= (char)0x2066 and <= (char)0x2069 || c == 0xFEFF;

    // For a failure message: every non-ASCII or control char as U+XXXX.
    private static string Visible(string text)
    {
        var sb = new StringBuilder();
        foreach (var c in text)
            sb.Append(c is >= ' ' and < (char)0x7F ? c.ToString() : $"<U+{(int)c:X4}>");
        return sb.ToString();
    }

    public static TheoryData<string, SsaValue> ResolvedValues() => new()
    {
        { "String", Str("x") },
        { "Int", Const(SsaConstantKind.Int, "1") },
        { "Float", Const(SsaConstantKind.Float, "0.5") },
        { "Null", Const(SsaConstantKind.Null, "") },
        { "Type", Const(SsaConstantKind.Type, "Own.T") },
        { "OneOf", OneOf("a", "b") },
    };

    public static TheoryData<string, SsaValue?> UnresolvedValues()
    {
        var data = new TheoryData<string, SsaValue?> { { "Parameter", Param(1) }, { "null", null } };
        foreach (var origin in Enum.GetValues<SsaDynamicOrigin>())
            data.Add($"Dynamic {origin}", Dyn(origin));
        return data;
    }

    public static TheoryData<int> HostileCodePoints() =>
    [
        0x00, 0x07, 0x09, 0x0A, 0x0D, 0x1B, 0x7F, 0x85, 0x9B, 0xAD,
        0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029,
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF,
        0xE0001, 0xE0041, 0xE007F, 0xD800, 0xDBFF, 0xDC00, 0xDFFF,
    ];

    public static TheoryData<string, SsaFolderFacts> BrokenFacts() => new()
    {
        { "a null site", Facts(Fact(Site("Own.A()", 4), args: [Str("x")]), null!) },
        { "null sites", new SsaFolderFacts(null!, 0, false, 0, [], false, false, false, 0) },
        { "a fact without a site", Facts(new SsaSinkFact(null!, SsaSiteStatus.Analyzed, null, [Str("x")], 1, false, null, null)) },
        { "null arguments", Facts(new SsaSinkFact(Site("Own.A()", 4), SsaSiteStatus.Analyzed, null, null!, 1, false, null, null)) },
        { "a value without constants", Facts(Fact(Site("Own.A()", 4), args: [new SsaValue(SsaValueKind.OneOf, null!, null, null)])) },
        { "a target with null candidates", Facts(Fact(Site("Own.A()", 4), target: new SsaReflectionTarget(SsaTargetKind.Method, null, Str("T"), Str("M"), SsaCandidateMatch.ByName, null!, 0, null))) },
    };

    public static TheoryData<string, FolderSsa> EverySsaShape() => new()
    {
        { "analysed, clean", AnalyzedSsa(Fact(Site("Own.A()", 4), args: [Str("x")])) },
        { "analysed, a MethodUnknown site", AnalyzedSsa(Fact(Site("Own.A()", 4), SsaSiteStatus.MethodUnknown, failure: SsaFailureKind.Adapter, reason: "r")) },
        { "analysed, broken", new FolderSsa(SsaFolderOutcome.Analyzed, new SsaFolderFacts(null!, 0, false, 0, [], false, false, false, 0), null) },
        { "crashed", new FolderSsa(SsaFolderOutcome.Crashed, null, "exit 35") },
        { "timed out", new FolderSsa(SsaFolderOutcome.TimedOut, null, "8 s") },
        { "not run", new FolderSsa(SsaFolderOutcome.NotRun, null, "budget") },
    };
    #endregion

    #region Fields
    private const char Bs = (char)0x5C;

    private static readonly string Ellipsis = ((char)0x2026).ToString();

    private static readonly JsonSerializerOptions json = new() { Converters = { new JsonStringEnumConverter() } };
    #endregion
}
