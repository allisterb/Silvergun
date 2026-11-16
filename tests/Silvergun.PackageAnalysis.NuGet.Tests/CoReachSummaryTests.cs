namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Graph;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using S = Silvergun.PackageAnalysis.NuGet.Tests.ReachabilitySummaryTests;

/// <summary>
/// The co-reach statements (<c>docs/agent/tasks/recall-levers-1.md</c> §1): per presented class, collection capability
/// (EnvironmentProbe, FileSystem) and label, one statement when some <see cref="ReachProfile"/> of the class holds that
/// capability and Network together; Direct when the profile's Direct set holds both, deferred otherwise. Over hand-built
/// reports: the profiles are the source, so no graph is needed.
/// </summary>
public sealed class CoReachSummaryTests
{
    #region Methods: premises
    [Fact]
    public void Premise_TheProfileCapIsTheSpecs_AndTheCollectionsAreTheTwo()
    {
        Assert.Equal(64, Reachability.MaxProfilesPerClass);
        Assert.Equal([Capability.EnvironmentProbe, Capability.FileSystem], ReachabilityPresentation.CollectionCapabilities);
    }

    // Until the benign measurement (recall-levers-1 §4) names cells that pass, every cell is information, whatever its class.
    [Fact]
    public void CoReachKindOf_EveryCell_IsInformational_UntilMeasured() =>
        Assert.All(Cells(), c => Assert.Equal(ReachStatementKind.Informational, ReachabilityPresentation.CoReachKindOf(c.Class, c.Collection, c.Direct)));

    [Fact]
    public void CoReachText_IsTheSpecsWording()
    {
        Assert.All(Subjects, p =>
        {
            Assert.Equal($"{p.Value} directly reaches both environment reads and the network", ReachabilityPresentation.CoReachText(p.Key, Capability.EnvironmentProbe, true));
            Assert.Equal($"{p.Value} directly reaches both the file system and the network", ReachabilityPresentation.CoReachText(p.Key, Capability.FileSystem, true));
            Assert.Equal($"{p.Value} reaches both environment reads and the network, at least one only through a delegate it creates", ReachabilityPresentation.CoReachText(p.Key, Capability.EnvironmentProbe, false));
            Assert.Equal($"{p.Value} reaches both the file system and the network, at least one only through a delegate it creates", ReachabilityPresentation.CoReachText(p.Key, Capability.FileSystem, false));
        });
    }
    #endregion

    #region Methods: which statements
    [Theory]
    [InlineData(Capability.EnvironmentProbe)]
    [InlineData(Capability.FileSystem)]
    public void Direct_ProfileHoldingBothDirectly_GivesOneDirectStatement(Capability collection)
    {
        var statement = Assert.Single(CoReach(Profile(RootClass.HostContract, [collection, Capability.Network], root: "App.Task.Execute", roots: 3)));

        Assert.Equal((ReachStatementKind.Informational, RootClass.HostContract, collection, Capability.Network, true, 3),
            (statement.Kind, statement.Class, statement.Capability, statement.With, statement.Direct, statement.Roots));
        Assert.Equal(ReachabilityPresentation.CoReachText(RootClass.HostContract, collection, true), statement.Text);
    }

    // The example is the one root, at the weakest evidence: a profile keeps no path.
    [Fact]
    public void Example_IsTheRootAlone_AtChaOnly()
    {
        var statement = Assert.Single(CoReach(Profile(RootClass.TypeInitializer, [Capability.FileSystem, Capability.Network], root: "App.Cctor")));

        Assert.Equal((ReachEvidence.ChaOnly, 0, (string?)null), (statement.Example!.Evidence, statement.Example.HiddenHops, statement.Example.Unseen));
        Assert.Equal(["App.Cctor"], statement.Example.Hops);
    }

    // Network is only deferred: the delegate carries it.
    [Fact]
    public void Deferred_WhenTheDirectSetLacksOneOfThePair()
    {
        var onlyCollection = Assert.Single(CoReach(Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network], direct: [Capability.FileSystem])));
        var onlyNetwork = Assert.Single(CoReach(Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network], direct: [Capability.Network])));
        var neither = Assert.Single(CoReach(Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network], direct: [])));

        Assert.All(new[] { onlyCollection, onlyNetwork, neither }, s => Assert.False(s.Direct));
        Assert.Equal(ReachabilityPresentation.CoReachText(RootClass.HostContract, Capability.FileSystem, false), onlyCollection.Text);
    }

    // Direct and deferred are separate cells: a class with both kinds of profile has both statements, Direct first.
    [Fact]
    public void DirectAndDeferredProfiles_OfOneClassAndCollection_GiveTwoStatements_DirectFirst()
    {
        var statements = CoReach(
            Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network], direct: [Capability.FileSystem], root: "App.B", roots: 2),
            Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network], root: "App.A", roots: 5));

        Assert.Equal([(true, 5, "App.A"), (false, 2, "App.B")], statements.Select(s => (s.Direct, s.Roots, s.Example!.Hops[0])));
    }

    [Fact]
    public void OneProfileWithBothCollections_GivesBothStatements_InCapabilityOrder()
    {
        var statements = CoReach(Profile(RootClass.LoadTime, [Capability.EnvironmentProbe, Capability.FileSystem, Capability.Network]));

        Assert.Equal([Capability.FileSystem, Capability.EnvironmentProbe], statements.Select(s => s.Capability!.Value));
    }

    // Roots sum over the matching profiles; the example is the ordinal-least root of them (ordinal: 'B' < 'a').
    [Fact]
    public void ProfilesOfOneCell_SumTheirRoots_AndNameTheOrdinalLeastRoot()
    {
        var statement = Assert.Single(CoReach(
            Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network], root: "a.Root", roots: 2),
            Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network, Capability.Registry], root: "B.Root", roots: 3),
            Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network, Capability.Cryptography], root: "Z.Root", roots: 10)));

        Assert.Equal(15, statement.Roots);
        Assert.Equal(["B.Root"], statement.Example!.Hops);
    }

    [Fact]
    public void ProfilesOfOtherClassesOrCollections_AreNotSummedIn()
    {
        var statements = CoReach(
            Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network], roots: 2),
            Profile(RootClass.LoadTime, [Capability.FileSystem, Capability.Network], roots: 7),
            Profile(RootClass.HostContract, [Capability.EnvironmentProbe, Capability.Network], roots: 11));

        Assert.Equal(
            [(RootClass.HostContract, Capability.FileSystem, 2), (RootClass.HostContract, Capability.EnvironmentProbe, 11), (RootClass.LoadTime, Capability.FileSystem, 7)],
            statements.Select(s => (s.Class, s.Capability!.Value, s.Roots)));
    }

    [Theory]
    [InlineData(new[] { Capability.Network })]
    [InlineData(new[] { Capability.FileSystem })]
    [InlineData(new[] { Capability.EnvironmentProbe })]
    [InlineData(new[] { Capability.FileSystem, Capability.EnvironmentProbe })]
    [InlineData(new[] { Capability.Registry, Capability.Network })]
    [InlineData(new[] { Capability.ProcessExecution, Capability.Cryptography })]
    [InlineData(new Capability[0])]
    public void ProfilesWithoutACollectionAndNetwork_GiveNoStatement(Capability[] capabilities) =>
        Assert.Empty(CoReach(Profile(RootClass.HostContract, capabilities)));

    // The profile's own Unseen flag says nothing about the pair.
    [Fact]
    public void UnseenProfile_WithNoPair_GivesNoStatement() =>
        Assert.Empty(CoReach(Profile(RootClass.HostContract, [Capability.Network]) with { Unseen = true }));

    [Theory]
    [InlineData(RootClass.PublicApi)]
    [InlineData(RootClass.PublicContract)]
    [InlineData(RootClass.Hidden)]
    [InlineData(RootClass.None)]
    public void ClassesNotPresented_AreIgnored(RootClass cls)
    {
        var report = Report([Profile(cls, [Capability.FileSystem, Capability.Network])], truncated: false);

        Assert.Empty(Only(report).Statements);
    }

    // Every presented class, in the presentation's order whatever the profiles' order.
    [Fact]
    public void Statements_AreInPresentedClassOrder()
    {
        var statements = CoReach([.. S.presented.Reverse().Select(c => Profile(c, [Capability.FileSystem, Capability.Network]))]);

        Assert.Equal(S.presented, statements.Select(s => s.Class));
    }

    // Plain reach statements of a class come before its co-reach ones, and co-reach never displaces them.
    [Fact]
    public void CoReach_FollowsTheClassesPlainStatements()
    {
        var report = Report([Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network])], truncated: false)
            with { Reaches = [S.Row(RootClass.HostContract, Capability.Network, 1, 1, S.PathOf(true))] };

        var statements = Only(report).Statements;

        Assert.Equal([(Capability.Network, (Capability?)null), (Capability.FileSystem, Capability.Network)], statements.Select(s => (s.Capability!.Value, s.With)));
    }

    // Folders that are not analysed say nothing of co-reach; neither does a copy.
    [Fact]
    public void SameAsCopy_CarriesNoStatements()
    {
        var report = Report([Profile(RootClass.NativeEntry, [Capability.FileSystem, Capability.Network])], truncated: false);

        var summary = ReachabilitySummary.From(new([S.Analyzed("lib/net8.0", report), S.Analyzed("lib/net9.0", report, sameAs: "lib/net8.0")]));

        Assert.Single(summary.Folders[0].Statements);
        Assert.Empty(summary.Folders[1].Statements);
        Assert.Empty(summary.Folders[1].Notes);
    }

    [Fact]
    public void NotAnalyzedFolder_HasNoStatements() =>
        Assert.Empty(Assert.Single(ReachabilitySummary.From(new([S.NotAnalyzed("lib/net8.0", FolderOutcome.NotRun, "cap")])).Folders).Statements);

    // Statements say what a root reaches; they never say a folder is incomplete or complete.
    [Fact]
    public void Complete_IsNotMovedByCoReach()
    {
        var without = ReachabilitySummary.From(new([S.Analyzed("lib/net8.0", S.Report([]))]));
        var with = ReachabilitySummary.From(new([S.Analyzed("lib/net8.0", Report([Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network])], truncated: false))]));

        Assert.Equal((without.Complete, without.StatementsDropped), (with.Complete, with.StatementsDropped));
    }
    #endregion

    #region Methods: truncated profiles
    private static string Note(RootClass cls) =>
        $"{cls}: more capability sets than the report keeps, so statements that two capabilities are reached together may be missing";

    // 64 profiles of a class is as many as the report keeps: when it was cut, what it kept may not be all.
    [Fact]
    public void ProfilesTruncated_AddsANote_ForEachPresentedClassAtTheCap()
    {
        var profiles = Many(RootClass.TypeInitializer, 64).Concat(Many(RootClass.HostContract, 64)).Concat(Many(RootClass.LoadTime, 3));

        var folder = Only(Report([.. profiles], truncated: true));

        Assert.Equal([Note(RootClass.TypeInitializer), Note(RootClass.HostContract)], folder.Notes);
    }

    [Fact]
    public void ProfilesNotTruncated_AddsNoNote_EvenAtTheCap() =>
        Assert.Empty(Only(Report([.. Many(RootClass.HostContract, 64)], truncated: false)).Notes);

    [Fact]
    public void ProfilesTruncated_NotePerClassUnderTheCap_IsNotAdded() =>
        Assert.Empty(Only(Report([.. Many(RootClass.HostContract, 63)], truncated: true)).Notes);

    [Fact]
    public void ProfilesTruncated_ForAClassNotPresented_AddsNoNote() =>
        Assert.Empty(Only(Report([.. Many(RootClass.PublicApi, 64)], truncated: true)).Notes);

    // A cut list never turns into a claim: nothing reached, nothing said, but the note.
    [Fact]
    public void ProfilesTruncated_NeverAddsAStatement()
    {
        var folder = Only(Report([.. Many(RootClass.HostContract, 64, [Capability.Registry])], truncated: true));

        Assert.Empty(folder.Statements);
        Assert.Single(folder.Notes);
    }

    // Notes come after the load-time one and before a divergent copy's.
    [Fact]
    public void Notes_KeepTheirOrder_WithOtherNotes()
    {
        var gap = "a.dll: " + GraphFacts.ModuleInitializerGap;
        var classes = S.presented.Select(c => c == RootClass.LoadTime ? S.Status(c, RootClassVerdict.Unknown, 0, gap) : S.Status(c, RootClassVerdict.Reaches)).ToArray();
        var report = Report([.. Many(RootClass.HostContract, 64)], truncated: true) with { Classes = classes };

        var notes = Only(report).Notes;

        Assert.Equal(2, notes.Count);
        Assert.Equal(Note(RootClass.HostContract), notes[1]);
    }
    #endregion

    #region Methods: determinism, bounds, JSON
    [Fact]
    public void Statements_AreDeterministic_WhateverTheProfileOrder()
    {
        var profiles = Enumerable.Range(0, 30)
            .Select(i => Profile(S.presented[i % 5], i % 3 == 0 ? [Capability.FileSystem, Capability.Network] : [Capability.EnvironmentProbe, Capability.FileSystem, Capability.Network],
                direct: i % 2 == 0 ? null : [Capability.Network], root: $"App.R{i:00}", roots: i + 1))
            .ToArray();

        var forward = JsonSerializer.Serialize(Only(Report(profiles, truncated: false)).Statements, json);
        var backward = JsonSerializer.Serialize(Only(Report([.. profiles.Reverse()], truncated: false)).Statements, json);

        Assert.Equal(forward, backward);
    }

    // The root is the package's own text: escaped and cut like every name of the summary.
    [Fact]
    public void ExampleRoot_IsEscapedAndBounded()
    {
        var hostile = "App." + (char)0x202E + "Root" + (char)0x0A + new string('x', 400);

        var statement = Assert.Single(CoReach(Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network], root: hostile)));

        var hop = Assert.Single(statement.Example!.Hops);
        Assert.StartsWith("App.", hop, StringComparison.Ordinal);
        Assert.DoesNotContain((char)0x202E, hop);
        Assert.DoesNotContain('\n', hop);
        Assert.True(hop.Length <= 256 + 48, $"{hop.Length} chars");
        Assert.Contains("[+", hop, StringComparison.Ordinal);
    }

    [Fact]
    public void Json_OrdinaryStatements_HaveNoWithKey()
    {
        var report = S.Report([S.Row(RootClass.NativeEntry, Capability.Network, 1, 1, S.PathOf(true))]);

        var json = ReportWith(ReachabilitySummary.From(new([S.Analyzed("lib/net8.0", report)]))).ToJson();

        Assert.Contains("\"Statements\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"With\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Json_CoReachStatement_HasWithNetwork_AndRoundTrips()
    {
        var report = Report([Profile(RootClass.HostContract, [Capability.EnvironmentProbe, Capability.Network])], truncated: false);
        var json = ReportWith(ReachabilitySummary.From(new([S.Analyzed("lib/net8.0", report)]))).ToJson();

        var statement = JsonNode.Parse(json)!["Reachability"]!["Folders"]![0]!["Statements"]![0]!;

        Assert.Equal("Network", statement["With"]!.GetValue<string>());
        Assert.Equal("EnvironmentProbe", statement["Capability"]!.GetValue<string>());
        Assert.Equal(json, PackageCapabilityReport.FromJson(json)!.ToJson());
        Assert.Equal(Capability.Network, PackageCapabilityReport.FromJson(json)!.Reachability!.Folders[0].Statements[0].With);
    }

    // A report written before co-reach: no With anywhere, and it reads.
    [Fact]
    public void Json_FromBeforeCoReach_StillReads_WithNoWith()
    {
        var report = S.Report([S.Row(RootClass.NativeEntry, Capability.Network, 2, 1, S.PathOf(true))]);
        var node = JsonNode.Parse(ReportWith(ReachabilitySummary.From(new([S.Analyzed("lib/net8.0", report)]))).ToJson())!;
        foreach (var statement in node["Reachability"]!["Folders"]![0]!["Statements"]!.AsArray())
            Assert.False(statement!.AsObject().ContainsKey("With"));

        var back = PackageCapabilityReport.FromJson(node.ToJsonString())!;

        Assert.All(back.Reachability!.Folders[0].Statements, s => Assert.Null(s.With));
        Assert.Equal(2, back.Reachability.Folders[0].Statements.Count);
    }

    [Fact]
    public void Json_StatementAlone_WritesWithOnlyWhenSet()
    {
        var plain = new ReachStatement(ReachStatementKind.Informational, RootClass.NativeEntry, Capability.Network, true, 1, "t", null);
        var co = plain with { With = Capability.Network };

        Assert.DoesNotContain("With", JsonSerializer.Serialize(plain, json), StringComparison.Ordinal);
        Assert.Contains("\"With\":\"Network\"", JsonSerializer.Serialize(co, json), StringComparison.Ordinal);
        Assert.Null(JsonSerializer.Deserialize<ReachStatement>(JsonSerializer.Serialize(plain, json), json)!.With);
    }
    #endregion

    #region Methods: helpers
    private static ReachProfile Profile(RootClass cls, Capability[] capabilities, Capability[]? direct = null, string root = "App.Root", int roots = 1) =>
        new(cls, capabilities, false, direct ?? capabilities, false, roots, root);

    private static IEnumerable<ReachProfile> Many(RootClass cls, int count, Capability[]? capabilities = null) =>
        Enumerable.Range(0, count).Select(i => Profile(cls, capabilities ?? [Capability.FileSystem, Capability.Network, (Capability)(i % 11)], root: $"App.R{i:00}"));

    private static ReachabilityReport Report(IReadOnlyList<ReachProfile> profiles, bool truncated) =>
        S.Report([]) with { Profiles = profiles, ProfilesTruncated = truncated };

    private static FolderReachSummary Only(ReachabilityReport report) =>
        Assert.Single(ReachabilitySummary.From(new([S.Analyzed("lib/net8.0", report)])).Folders);

    private static IReadOnlyList<ReachStatement> CoReach(params ReachProfile[] profiles) => Only(Report(profiles, truncated: false)).Statements;

    private static IEnumerable<(RootClass Class, Capability Collection, bool Direct)> Cells() =>
        from cls in Enum.GetValues<RootClass>()
        from collection in ReachabilityPresentation.CollectionCapabilities
        from direct in new[] { true, false }
        select (cls, collection, direct);

    private static PackageCapabilityReport ReportWith(ReachabilitySummary reachability) => new(
        new PackageIdentityInfo("Pkg", "1.0.0", "Silvergun Tests", "Co-reach.", []),
        new DateTimeOffset(2026, 11, 15, 12, 0, 0, TimeSpan.Zero),
        [],
        [],
        [],
        YaraScanStatus: YaraScanStatus.NotRun,
        ScriptScanStatus: ScriptScanStatus.Completed,
        Reachability: reachability);
    #endregion

    #region Fields
    private static readonly Dictionary<RootClass, string> Subjects = new()
    {
        [RootClass.NativeEntry] = "a native entry point",
        [RootClass.Finalizer] = "a finalizer",
        [RootClass.TypeInitializer] = "a type initializer",
        [RootClass.HostContract] = "a build-host entry point (MSBuild task, analyzer, generator)",
        [RootClass.LoadTime] = "a module initializer",
    };

    private static readonly JsonSerializerOptions json = new() { Converters = { new JsonStringEnumConverter() } };
    #endregion
}
