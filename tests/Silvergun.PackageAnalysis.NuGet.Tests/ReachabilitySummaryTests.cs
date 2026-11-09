namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// Reachability R3, S0 (<c>docs/agent/tasks/reachability-r3.md</c>, acceptance criteria 1-4): <see cref="ReachabilitySummary.From"/>
/// over hand-built <see cref="PackageReachabilityReport"/>s. The table's cells (trigger or information, and their wording),
/// the folds that keep an unseen or failed folder from reading clean, the unseen sink's naming, the LoadTime notes, the
/// example paths, the bounds on hostile names and on the statement count, <c>SameAs</c>, order, role, determinism and
/// that it never throws. Hostile characters are built from escapes; the source holds none raw.
/// </summary>
public sealed class ReachabilitySummaryTests
{
    #region Methods: premises
    [Fact]
    public void Premise_TheBoundsAreTheSpecs()
    {
        Assert.Equal(2000, ReachabilitySummary.MaxStatements);
        Assert.Equal(8, ReachabilitySummary.MaxHops);
        Assert.Equal(256, ReachabilitySummary.MaxNameChars);
        Assert.Equal(8, ReachabilitySummary.MaxReasons);
    }

    [Fact]
    public void Presentation_Classes_AreTheFivePresented_InTableOrder()
    {
        Assert.Equal(presented, ReachabilityPresentation.Classes);
    }

    [Fact]
    public void Presentation_SignalCapabilities_AreR2bsFive()
    {
        Assert.Equal(signal.OrderBy(c => c), ReachabilityPresentation.SignalCapabilities.OrderBy(c => c));
    }

    // Acceptance criterion 1, "and only for it": over every single root class, every sink and both labels, a trigger is
    // exactly NativeEntry (either label) or Finalizer (Direct) on a signal capability.
    [Fact]
    public void Presentation_KindOf_IsATrigger_OnlyForNativeEntryAndFinalizerDirect_OnASignalCapability()
    {
        foreach (var cls in Enum.GetValues<RootClass>().Where(c => c != RootClass.None))
            foreach (var sink in allSinks)
                foreach (var direct in new[] { true, false })
                    Assert.True(Expected(cls, sink, direct) == ReachabilityPresentation.KindOf(cls, sink, direct), $"{cls} {sink?.ToString() ?? "unseen"} direct={direct}");
    }
    #endregion

    #region Methods: the table's cells
    [Theory]
    [MemberData(nameof(SignalCapabilities))]
    public void Summary_NativeEntryDirect_IsATrigger(Capability capability)
    {
        var statement = Assert.Single(StatementsOf(Row(RootClass.NativeEntry, capability, 1, 1, PathOf(true))));

        Assert.Equal(ReachStatementKind.Trigger, statement.Kind);
        Assert.True(statement.Direct);
        Assert.Equal(1, statement.Roots);
        Assert.Equal($"a native entry point directly reaches {capability}", statement.Text);
    }

    [Theory]
    [MemberData(nameof(SignalCapabilities))]
    public void Summary_NativeEntryDeferred_IsATrigger(Capability capability)
    {
        var statement = Assert.Single(StatementsOf(Row(RootClass.NativeEntry, capability, 1, 0, PathOf(false))));

        Assert.Equal(ReachStatementKind.Trigger, statement.Kind);
        Assert.False(statement.Direct);
        Assert.Equal($"a native entry point creates a delegate that reaches {capability}", statement.Text);
    }

    [Theory]
    [MemberData(nameof(SignalCapabilities))]
    public void Summary_FinalizerDirect_IsATrigger_FinalizerDeferred_IsInformational(Capability capability)
    {
        var statements = StatementsOf(Row(RootClass.Finalizer, capability, 3, 1));

        Assert.Equal(
            [
                (ReachStatementKind.Trigger, true, 1, $"a finalizer directly reaches {capability}"),
                (ReachStatementKind.Informational, false, 2, $"a finalizer creates a delegate that reaches {capability}"),
            ],
            statements.Select(s => (s.Kind, s.Direct, s.Roots, s.Text)));
    }

    [Theory]
    [MemberData(nameof(InformationalClassesOnSignalCapabilities))]
    public void Summary_TypeInitializerHostContractLoadTime_AreInformational_AtBothLabels(RootClass cls, string subject, Capability capability)
    {
        var statements = StatementsOf(Row(cls, capability, 2, 1));

        Assert.Equal(
            [
                (ReachStatementKind.Informational, true, $"{subject} directly reaches {capability}"),
                (ReachStatementKind.Informational, false, $"{subject} creates a delegate that reaches {capability}"),
            ],
            statements.Select(s => (s.Kind, s.Direct, s.Text)));
    }

    [Theory]
    [MemberData(nameof(NonSignalCapabilities))]
    public void Summary_NonSignalCapability_IsInformational_EvenForNativeEntry(Capability capability)
    {
        var statements = StatementsOf(Row(RootClass.NativeEntry, capability, 2, 1), Row(RootClass.Finalizer, capability, 2, 1));

        Assert.Equal(4, statements.Count);
        Assert.All(statements, s => Assert.Equal(ReachStatementKind.Informational, s.Kind));
        Assert.Contains(statements, s => s.Text == $"a native entry point directly reaches {capability}");
    }

    [Theory]
    [MemberData(nameof(PresentedClasses))]
    public void Summary_UnseenSink_IsInformational_ForEveryPresentedClass(RootClass cls)
    {
        var statements = StatementsOf(Row(cls, null, 2, 1));

        Assert.Equal(2, statements.Count);
        Assert.All(statements, s => Assert.Equal(ReachStatementKind.Informational, s.Kind));
        Assert.All(statements, s => Assert.Null(s.Capability));
    }

    // Acceptance criterion 1 end to end: every presented class at every sink and both labels, in one folder, carries the
    // table's kind, and each cell gives exactly its two statements.
    [Fact]
    public void Summary_EveryPresentedCell_HasTheTablesKind()
    {
        var rows = presented.SelectMany(cls => allSinks.Select(sink => Row(cls, sink, 2, 1))).ToArray();

        var statements = StatementsOf(rows);

        Assert.Equal(rows.Length * 2, statements.Count);
        Assert.All(statements, s => Assert.Equal(Expected(s.Class, s.Capability, s.Direct), s.Kind));
        Assert.Equal(5 * 2 + 5, statements.Count(s => s.Kind == ReachStatementKind.Trigger));
    }

    [Theory]
    [MemberData(nameof(ClassSubjects))]
    public void Summary_EachPresentedClass_IsWordedByItsSubject(RootClass cls, string subject)
    {
        var statements = StatementsOf(Row(cls, Capability.Network, 2, 1));

        Assert.Equal([$"{subject} directly reaches Network", $"{subject} creates a delegate that reaches Network"], statements.Select(s => s.Text));
    }
    #endregion

    #region Methods: counts per label
    [Fact]
    public void Summary_RowWithFiveRootsTwoDirect_GivesADirectStatementOfTwo_AndADeferredStatementOfThree()
    {
        var statements = StatementsOf(Row(RootClass.TypeInitializer, Capability.FileSystem, 5, 2));

        Assert.Equal(
            [
                (true, 2, "a type initializer directly reaches FileSystem"),
                (false, 3, "a type initializer creates a delegate that reaches FileSystem"),
            ],
            statements.Select(s => (s.Direct, s.Roots, s.Text)));
        Assert.All(statements, s => Assert.Equal((RootClass.TypeInitializer, (Capability?)Capability.FileSystem), (s.Class, s.Capability)));
    }

    [Fact]
    public void Summary_RowWhoseRootsAreAllDirect_GivesOnlyTheDirectStatement()
    {
        var statement = Assert.Single(StatementsOf(Row(RootClass.NativeEntry, Capability.Network, 4, 4)));

        Assert.Equal((true, 4, "a native entry point directly reaches Network"), (statement.Direct, statement.Roots, statement.Text));
    }

    [Fact]
    public void Summary_RowWithNoDirectRoot_GivesOnlyTheDeferredStatement()
    {
        var statement = Assert.Single(StatementsOf(Row(RootClass.NativeEntry, Capability.Network, 4, 0)));

        Assert.Equal((false, 4, "a native entry point creates a delegate that reaches Network"), (statement.Direct, statement.Roots, statement.Text));
    }
    #endregion

    #region Methods: classes not presented
    [Theory]
    [InlineData(RootClass.PublicApi)]
    [InlineData(RootClass.PublicContract)]
    [InlineData(RootClass.Hidden)]
    public void Summary_PublicApiPublicContractHidden_YieldNoStatementsAndNoClassVerdicts(RootClass cls)
    {
        var report = Report(
            [Row(cls, Capability.ProcessExecution, 3, 1, PathOf(true)), Row(cls, null, 2, 2)],
            [.. presented.Select(c => Status(c, RootClassVerdict.None, 0)), Status(cls, RootClassVerdict.Unknown, 5, "why")]);

        var folder = Only(report);

        Assert.Empty(folder.Statements);
        Assert.Equal(presented, folder.Classes.Select(c => c.Class));
        Assert.DoesNotContain(folder.Classes, c => c.Class == cls);
    }
    #endregion

    #region Methods: class verdicts
    [Fact]
    public void Summary_Classes_AreTheFivePresented_InTableOrder_WithTheReportsRootsAndVerdicts()
    {
        var report = Report([], [
            Status(RootClass.LoadTime, RootClassVerdict.None, 7),
            Status(RootClass.Hidden, RootClassVerdict.Reaches, 9),
            Status(RootClass.Finalizer, RootClassVerdict.Reaches, 2),
            Status(RootClass.HostContract, RootClassVerdict.Unknown, 3, "a gap"),
            Status(RootClass.NativeEntry, RootClassVerdict.None, 0),
            Status(RootClass.TypeInitializer, RootClassVerdict.Reaches, 4),
        ]);

        var folder = Only(report);

        Assert.Equal(
            [
                (RootClass.NativeEntry, 0, RootClassVerdict.None),
                (RootClass.Finalizer, 2, RootClassVerdict.Reaches),
                (RootClass.TypeInitializer, 4, RootClassVerdict.Reaches),
                (RootClass.HostContract, 3, RootClassVerdict.Unknown),
                (RootClass.LoadTime, 7, RootClassVerdict.None),
            ],
            folder.Classes.Select(c => (c.Class, c.Roots, c.Verdict)));
        Assert.Equal(["a gap"], folder.Classes[3].Reasons);
        Assert.All(folder.Classes.Where(c => c.Class != RootClass.HostContract), c => Assert.Empty(c.Reasons));
    }

    [Fact]
    public void Summary_AClassMissingFromTheReport_IsUnknown_WithAReason()
    {
        var report = Report([], presented.Where(c => c != RootClass.Finalizer).Select(c => Status(c, RootClassVerdict.None, 0)));

        var summary = Summarize(Analyzed(Lib, report));

        var finalizer = Assert.Single(summary.Folders).Classes.Single(c => c.Class == RootClass.Finalizer);
        Assert.Equal((0, RootClassVerdict.Unknown), (finalizer.Roots, finalizer.Verdict));
        Assert.Equal(["the report has no verdict for this class"], finalizer.Reasons);
        Assert.False(summary.Complete);
    }

    [Fact]
    public void Summary_ANoneVerdict_StaysNone_WhenNothingFolds_AndTheSummaryIsComplete()
    {
        var summary = Summarize(Analyzed(Lib, Report([], presented.Select(c => Status(c, RootClassVerdict.None, 0)))));

        Assert.All(Assert.Single(summary.Folders).Classes, c => Assert.Equal(RootClassVerdict.None, c.Verdict));
        Assert.True(summary.Complete);
        Assert.Equal(ReachabilityScanStatus.Completed, summary.Status());
    }

    [Fact]
    public void Summary_AnUnknownVerdictFromTheReport_StaysUnknown_AndTheSummaryIsIncomplete()
    {
        var report = Report([], presented.Select(c => c == RootClass.TypeInitializer ? Status(c, RootClassVerdict.Unknown, 1, "1 root(s) reach code the graph cannot see") : Status(c, RootClassVerdict.Reaches)));

        var summary = Summarize(Analyzed(Lib, report));

        Assert.Equal(RootClassVerdict.Unknown, summary.Folders[0].Classes.Single(c => c.Class == RootClass.TypeInitializer).Verdict);
        Assert.False(summary.Complete);
        Assert.Equal(ReachabilityScanStatus.Incomplete, summary.Status());
    }

    // Complete needs every presented verdict to be None or Reaches: a verdict outside the enum is not decided.
    [Fact]
    public void Summary_AnOutOfRangeVerdictFromTheReport_IsNotComplete()
    {
        var report = Report([], presented.Select(c => Status(c, c == RootClass.TypeInitializer ? (RootClassVerdict)99 : RootClassVerdict.Reaches)));

        var summary = Summarize(Analyzed(Lib, report));

        Assert.False(summary.Complete);
        Assert.Equal(ReachabilityScanStatus.Incomplete, summary.Status());
    }

    [Theory]
    [InlineData(true, ReachabilityScanStatus.Completed)]
    [InlineData(false, ReachabilityScanStatus.Incomplete)]
    public void Status_IsCompleted_ExactlyWhenComplete(bool complete, ReachabilityScanStatus expected)
    {
        Assert.Equal(expected, new ReachabilitySummary([], 0, complete).Status());
    }
    #endregion

    #region Methods: folds (acceptance criterion 2)
    [Fact]
    public void Summary_LoadFailure_MakesEveryClassUnknown()
    {
        var failures = new[] { "a", "b", "c", "d", "e" }.Select(n => new PackageGraphLoadFailure($"lib/net8.0/{n}.dll", "not managed")).ToArray();
        var report = Report([Row(RootClass.NativeEntry, Capability.Network, 1, 1)], presented.Select(c => Status(c, c == RootClass.NativeEntry ? RootClassVerdict.Reaches : RootClassVerdict.None, 1)));

        var summary = Summarize(Analyzed(Lib, report, failures));

        const string reason = "5 assembly(ies) did not load: lib/net8.0/a.dll, lib/net8.0/b.dll, lib/net8.0/c.dll, and 2 more";
        var folder = Assert.Single(summary.Folders);
        Assert.All(folder.Classes, c => Assert.Equal(RootClassVerdict.Unknown, c.Verdict));
        Assert.All(folder.Classes, c => Assert.Equal([reason], c.Reasons));
        Assert.Single(folder.Statements);   // what was seen is still said
        Assert.False(summary.Complete);
        Assert.Equal(ReachabilityScanStatus.Incomplete, summary.Status());
    }

    [Fact]
    public void Summary_LoadFailureOfThreeOrFewer_ListsEveryOne_WithoutAMoreClause()
    {
        var failures = new[] { new PackageGraphLoadFailure("lib/net8.0/a.dll", "x"), new PackageGraphLoadFailure("lib/net8.0/b.dll", "y"), new PackageGraphLoadFailure("lib/net8.0/c.dll", "z") };

        var folder = Assert.Single(Summarize(Analyzed(Lib, Report([]), failures)).Folders);

        Assert.All(folder.Classes, c => Assert.Equal(["3 assembly(ies) did not load: lib/net8.0/a.dll, lib/net8.0/b.dll, lib/net8.0/c.dll"], c.Reasons));
    }

    [Fact]
    public void Summary_LoadFailure_LeadsTheClassesOwnReasons()
    {
        var report = Report([], presented.Select(c => Status(c, RootClassVerdict.Unknown, 1, "own reason")));

        var folder = Assert.Single(Summarize(Analyzed(Lib, report, [new PackageGraphLoadFailure("lib/net8.0/a.dll", "x")])).Folders);

        Assert.All(folder.Classes, c => Assert.Equal(["1 assembly(ies) did not load: lib/net8.0/a.dll", "own reason"], c.Reasons));
    }

    // The folder-level causes come first, so the 8-reason cap never hides them behind a class's own gaps.
    [Fact]
    public void Summary_FoldReasons_SurviveTheReasonCap()
    {
        var reasons = Enumerable.Range(0, 10).Select(i => $"gap {i}").ToArray();
        var report = Report([], presented.Select(c => Status(c, RootClassVerdict.Unknown, 1, reasons)), partial: true, partialReason: "the graph was truncated");

        var folder = Assert.Single(Summarize(Analyzed(Lib, report, [new PackageGraphLoadFailure("lib/net8.0/a.dll", "x")])).Folders);

        Assert.All(folder.Classes, c => Assert.Equal(
            ["1 assembly(ies) did not load: lib/net8.0/a.dll", "the report is partial: the graph was truncated", .. reasons.Take(6), "and 4 more reason(s)"],
            c.Reasons));
    }

    [Fact]
    public void Summary_PartialReport_MakesEveryClassUnknown_KeepsStatements()
    {
        ReachabilityReport Of(bool partial) => Report(
            [Row(RootClass.NativeEntry, Capability.Network, 2, 1), Row(RootClass.LoadTime, null, 1, 1)],
            presented.Select(c => Status(c, RootClassVerdict.None, 0)),
            partial, partial ? "the graph was truncated: node budget" : null);

        var whole = Only(Of(false));
        var summary = Summarize(Analyzed(Lib, Of(true)));

        var folder = Assert.Single(summary.Folders);
        Assert.Equal(whole.Statements, folder.Statements);
        Assert.Equal(3, folder.Statements.Count);
        Assert.All(folder.Classes, c => Assert.Equal(RootClassVerdict.Unknown, c.Verdict));
        Assert.All(folder.Classes, c => Assert.Equal(["the report is partial: the graph was truncated: node budget"], c.Reasons));
        Assert.False(summary.Complete);
    }

    [Fact]
    public void Summary_PartialReportWithoutAReason_SaysNoReasonWasGiven()
    {
        var folder = Only(Report([], partial: true));

        Assert.All(folder.Classes, c => Assert.Contains("the report is partial: no reason was given", c.Reasons));
    }

    [Fact]
    public void Summary_PartialReportWithALoadFailure_GivesBothReasons_LoadFailureFirst()
    {
        var report = Report([], presented.Select(c => Status(c, RootClassVerdict.None, 0)), partial: true, partialReason: "p");

        var folder = Assert.Single(Summarize(Analyzed(Lib, report, [new PackageGraphLoadFailure("lib/net8.0/a.dll", "x")])).Folders);

        Assert.All(folder.Classes, c => Assert.Equal(["1 assembly(ies) did not load: lib/net8.0/a.dll", "the report is partial: p"], c.Reasons));
    }

    [Theory]
    [InlineData(FolderOutcome.Crashed)]
    [InlineData(FolderOutcome.TimedOut)]
    [InlineData(FolderOutcome.NotRun)]
    [InlineData(FolderOutcome.NothingLoaded)]
    public void Summary_CrashedTimedOutNotRunNothingLoaded_HaveNoStatements_AndAReason(FolderOutcome outcome)
    {
        var failures = outcome == FolderOutcome.NothingLoaded ? new[] { new PackageGraphLoadFailure("lib/net8.0/a.dll", "x") } : [];

        var summary = Summarize(NotAnalyzed(Lib, outcome, outcome == FolderOutcome.NothingLoaded ? null : "the worker exited with code 35", failures));

        var folder = Assert.Single(summary.Folders);
        Assert.Equal((Lib, PackageItemRole.Lib, outcome), (folder.Folder, folder.Role, folder.Outcome));
        Assert.False(string.IsNullOrEmpty(folder.Reason));
        Assert.Null(folder.SameAs);
        Assert.Empty(folder.Classes);
        Assert.Empty(folder.Notes);
        Assert.Empty(folder.Statements);
        Assert.False(summary.Complete);
        Assert.Equal(ReachabilityScanStatus.Incomplete, summary.Status());
    }

    [Fact]
    public void Summary_Crashed_ReasonSaysUnanalysableAndSuspect()
    {
        var folder = Assert.Single(Summarize(NotAnalyzed(Lib, FolderOutcome.Crashed, "the worker exited with code 35")).Folders);

        Assert.Equal("the graph worker failed on this folder, so it is unanalysable, and suspect: the worker exited with code 35", folder.Reason);
    }

    [Fact]
    public void Summary_CrashedWithoutAReason_SaysNoReasonWasGiven()
    {
        var folder = Assert.Single(Summarize(NotAnalyzed(Lib, FolderOutcome.Crashed, null)).Folders);

        Assert.Equal("the graph worker failed on this folder, so it is unanalysable, and suspect: no reason was given", folder.Reason);
    }

    [Theory]
    [InlineData(FolderOutcome.TimedOut)]
    [InlineData(FolderOutcome.NotRun)]
    public void Summary_TimedOutAndNotRun_CarryTheirReason(FolderOutcome outcome)
    {
        Assert.Equal("the package budget of 600 s was spent", Assert.Single(Summarize(NotAnalyzed(Lib, outcome, "the package budget of 600 s was spent")).Folders).Reason);
        Assert.Equal("no reason was given", Assert.Single(Summarize(NotAnalyzed(Lib, outcome, null)).Folders).Reason);
    }

    [Fact]
    public void Summary_NothingLoaded_ReasonListsTheLoadFailures()
    {
        var failures = new[] { "a", "b", "c", "d" }.Select(n => new PackageGraphLoadFailure($"lib/net8.0/{n}.dll", "x")).ToArray();

        var folder = Assert.Single(Summarize(NotAnalyzed(Lib, FolderOutcome.NothingLoaded, null, failures)).Folders);

        Assert.Equal("4 assembly(ies) did not load: lib/net8.0/a.dll, lib/net8.0/b.dll, lib/net8.0/c.dll, and 1 more", folder.Reason);
    }

    [Fact]
    public void Summary_NothingLoadedWithoutLoadFailures_SaysNoAssemblyLoaded()
    {
        Assert.Equal("no assembly of the folder loaded", Assert.Single(Summarize(NotAnalyzed(Lib, FolderOutcome.NothingLoaded, null)).Folders).Reason);
    }

    // A folder whose outcome is not Analyzed is not read from its report even if one is present.
    [Fact]
    public void Summary_ANonAnalyzedFolderWithAReport_IsStillNotAnalysed()
    {
        var folder = new FolderReachability(Lib, [], [], FolderOutcome.Crashed, Report([Row(RootClass.NativeEntry, Capability.Network, 1, 1)]), "exit 35", null, 0, 0);

        var summary = Summarize(folder);

        Assert.Empty(summary.Folders[0].Statements);
        Assert.Empty(summary.Folders[0].Classes);
        Assert.False(summary.Complete);
    }

    [Fact]
    public void Summary_IsComplete_OnlyWhenEveryFolderIsDecided()
    {
        var good = Report([Row(RootClass.NativeEntry, Capability.Network, 1, 1)]);

        Assert.True(Summarize(Analyzed("lib/net8.0", good), Analyzed("lib/net9.0", good)).Complete);
        Assert.False(Summarize(Analyzed("lib/net8.0", good), Analyzed("lib/net9.0", good), NotAnalyzed("lib/net10.0", FolderOutcome.NotRun, "cap")).Complete);
        Assert.False(Summarize(Analyzed("lib/net8.0", good), Analyzed("lib/net9.0", good, [new PackageGraphLoadFailure("lib/net9.0/a.dll", "x")])).Complete);
        Assert.False(Summarize(Analyzed("lib/net8.0", good), Analyzed("lib/net9.0", Report([], partial: true, partialReason: "p"))).Complete);
    }
    #endregion

    #region Methods: the unseen sink
    [Fact]
    public void Summary_UnseenSink_NamesOpacityAndInternalCallApart()
    {
        var row = Row(RootClass.NativeEntry, null, 3, 3,
            PathOf(true, opacity: OpacityKind.IndirectCall),
            PathOf(true, ownSink: true),
            PathOf(true, ownSink: false));

        var statement = Assert.Single(StatementsOf(row));

        Assert.Equal("a native entry point directly reaches code the graph cannot see (an indirect call (calli), an internal call, an API the map marks unanalyzed)", statement.Text);
        Assert.Equal("an indirect call (calli)", statement.Example!.Unseen);
    }

    [Theory]
    [InlineData(OpacityKind.IndirectCall, "an indirect call (calli)")]
    [InlineData(OpacityKind.Unresolved, "an unresolved call")]
    [InlineData(OpacityKind.Ambiguous, "an ambiguous call")]
    [InlineData(OpacityKind.BodyUnreadable, "an unreadable method body")]
    [InlineData(OpacityKind.NameShadowed, "an opacity site (NameShadowed)")]
    public void Summary_UnseenSink_NamesEachOpacityKind(OpacityKind kind, string phrase)
    {
        var statement = Assert.Single(StatementsOf(Row(RootClass.TypeInitializer, null, 1, 1, PathOf(true, opacity: kind))));

        Assert.Equal($"a type initializer directly reaches code the graph cannot see ({phrase})", statement.Text);
        Assert.Equal(phrase, statement.Example!.Unseen);
    }

    [Fact]
    public void Summary_UnseenSink_ListsEachKindOnce_InExampleOrder()
    {
        var row = Row(RootClass.NativeEntry, null, 3, 3,
            PathOf(true, opacity: OpacityKind.Unresolved),
            PathOf(true, opacity: OpacityKind.IndirectCall),
            PathOf(true, opacity: OpacityKind.Unresolved));

        Assert.Equal("a native entry point directly reaches code the graph cannot see (an unresolved call, an indirect call (calli))", Assert.Single(StatementsOf(row)).Text);
    }

    [Fact]
    public void Summary_UnseenSink_NamesFromTheExamplesWithItsLabel()
    {
        var row = Row(RootClass.TypeInitializer, null, 2, 1, PathOf(true, opacity: OpacityKind.IndirectCall), PathOf(false, opacity: OpacityKind.Unresolved));

        var statements = StatementsOf(row);

        Assert.Equal(
            [
                "a type initializer directly reaches code the graph cannot see (an indirect call (calli))",
                "a type initializer creates a delegate that reaches code the graph cannot see (an unresolved call)",
            ],
            statements.Select(s => s.Text));
        Assert.Equal(["an indirect call (calli)", "an unresolved call"], statements.Select(s => s.Example!.Unseen));
    }

    // When no example has the label, another label's paths are no evidence for this one: no kinds are named, and there is
    // no example to show. The Direct statement still names its own.
    [Fact]
    public void Summary_UnseenSink_NamesNoKinds_WhenNoExampleHasItsLabel()
    {
        var row = Row(RootClass.TypeInitializer, null, 2, 1, PathOf(true, opacity: OpacityKind.IndirectCall), PathOf(true, ownSink: true));

        var statements = StatementsOf(row);

        var deferred = statements.Single(s => !s.Direct);
        Assert.Equal("a type initializer creates a delegate that reaches code the graph cannot see", deferred.Text);
        Assert.Null(deferred.Example);
        Assert.Equal("a type initializer directly reaches code the graph cannot see (an indirect call (calli), an internal call)", statements.Single(s => s.Direct).Text);
    }

    [Fact]
    public void Summary_UnseenSinkWithoutExamples_SaysCodeTheGraphCannotSee()
    {
        var statement = Assert.Single(StatementsOf(Row(RootClass.LoadTime, null, 1, 1)));

        Assert.Equal("a module initializer directly reaches code the graph cannot see", statement.Text);
        Assert.Null(statement.Example);
    }

    [Fact]
    public void Summary_ExampleUnseen_IsSetOnlyForUnseenStatements()
    {
        var statements = StatementsOf(Row(RootClass.NativeEntry, Capability.Network, 1, 1, PathOf(true)), Row(RootClass.NativeEntry, null, 1, 1, PathOf(true)));

        Assert.Null(statements.Single(s => s.Capability is not null).Example!.Unseen);
        Assert.Equal("an API the map marks unanalyzed", statements.Single(s => s.Capability is null).Example!.Unseen);
    }
    #endregion

    #region Methods: LoadTime notes
    [Fact]
    public void Summary_LoadTimeGap_ShowsLoadTimeCodeNotVisible()
    {
        var report = Report([], presented.Select(c => c == RootClass.LoadTime
            ? Status(c, RootClassVerdict.Unknown, 0, "lib/net8.0/a.dll: " + GraphFacts.ModuleInitializerGap, "lib/net8.0/b.dll: " + GraphFacts.ModuleInitializerGap)
            : Status(c, RootClassVerdict.None, 0)));

        var folder = Only(report);

        Assert.Equal(["load-time code present, not visible to the model (2 assembly(ies) with a module initializer)"], folder.Notes);
        var loadTime = folder.Classes.Single(c => c.Class == RootClass.LoadTime);
        Assert.Equal(RootClassVerdict.Unknown, loadTime.Verdict);
        Assert.Equal(["lib/net8.0/a.dll: " + GraphFacts.ModuleInitializerGap, "lib/net8.0/b.dll: " + GraphFacts.ModuleInitializerGap], loadTime.Reasons);
        Assert.Empty(folder.Statements);   // a note, not a statement: the unseen sink keeps one meaning
    }

    [Fact]
    public void Summary_LoadTimeUnreadableModule_SaysWhetherLoadTimeCodeIsPresentIsUnknown()
    {
        var report = Report([], presented.Select(c => c == RootClass.LoadTime
            ? Status(c, RootClassVerdict.Unknown, 0, "lib/net8.0/a.dll: " + GraphFacts.ModuleUnreadableGap)
            : Status(c, RootClassVerdict.None, 0)));

        Assert.Equal(["whether load-time code is present is unknown (1 assembly(ies) with unreadable module metadata)"], Only(report).Notes);
    }

    [Fact]
    public void Summary_LoadTimeBothGaps_GiveBothNotes_InitializerFirst()
    {
        var report = Report([], presented.Select(c => c == RootClass.LoadTime
            ? Status(c, RootClassVerdict.Unknown, 0, "b.dll: " + GraphFacts.ModuleUnreadableGap, "a.dll: " + GraphFacts.ModuleInitializerGap)
            : Status(c, RootClassVerdict.None, 0)));

        Assert.Equal(
            [
                "load-time code present, not visible to the model (1 assembly(ies) with a module initializer)",
                "whether load-time code is present is unknown (1 assembly(ies) with unreadable module metadata)",
            ],
            Only(report).Notes);
    }

    [Fact]
    public void Summary_WithoutALoadTimeGap_HasNoNotes()
    {
        var report = Report([], presented.Select(c => c switch
        {
            RootClass.LoadTime => Status(c, RootClassVerdict.Unknown, 1, "1 root(s) reach code the graph cannot see"),
            // A gap reason on another class is not LoadTime's.
            RootClass.TypeInitializer => Status(c, RootClassVerdict.Unknown, 1, "a.dll: " + GraphFacts.ModuleInitializerGap),
            _ => Status(c, RootClassVerdict.None, 0),
        }));

        Assert.Empty(Only(report).Notes);
    }

    [Fact]
    public void Premise_TheGapConstants_KeepTheirText()
    {
        Assert.Equal("<Module>..cctor runs at load and is invisible to the model", GraphFacts.ModuleInitializerGap);
        Assert.Equal("module metadata unreadable: whether a module initializer runs at load is unknown", GraphFacts.ModuleUnreadableGap);
    }
    #endregion

    #region Methods: examples
    [Fact]
    public void Summary_Example_IsTheFirstWithTheStatementsLabel()
    {
        var row = Row(RootClass.NativeEntry, Capability.Network, 3, 2,
            PathOf(false, prefix: "App.A"), PathOf(true, prefix: "App.B"), PathOf(true, prefix: "App.C"), PathOf(false, prefix: "App.D"));

        var statements = StatementsOf(row);

        Assert.Equal(["App.B0", "App.B1"], statements.Single(s => s.Direct).Example!.Hops);
        Assert.Equal(["App.A0", "App.A1"], statements.Single(s => !s.Direct).Example!.Hops);
    }

    [Fact]
    public void Summary_Example_IsNull_WhenNoExampleHasTheStatementsLabel()
    {
        var statements = StatementsOf(Row(RootClass.NativeEntry, Capability.Network, 3, 2, PathOf(true)));

        Assert.NotNull(statements.Single(s => s.Direct).Example);
        Assert.Null(statements.Single(s => !s.Direct).Example);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(8)]
    public void Summary_PathOfEightOrFewerHops_IsKeptWhole(int hops)
    {
        var example = Assert.Single(StatementsOf(Row(RootClass.NativeEntry, Capability.Network, 1, 1, PathOf(true, hops)))).Example!;

        Assert.Equal(Enumerable.Range(0, hops).Select(i => $"App.H{i}"), example.Hops);
        Assert.Equal(0, example.HiddenHops);
    }

    [Theory]
    [InlineData(9)]
    [InlineData(20)]
    [InlineData(64)]
    public void Summary_LongPath_KeepsFirstSixAndLastTwoHops(int hops)
    {
        var example = Assert.Single(StatementsOf(Row(RootClass.NativeEntry, Capability.Network, 1, 1, PathOf(true, hops)))).Example!;

        Assert.Equal([.. Enumerable.Range(0, 6).Select(i => $"App.H{i}"), $"App.H{hops - 2}", $"App.H{hops - 1}"], example.Hops);
        Assert.Equal(hops - 8, example.HiddenHops);
    }

    // A raw path already truncated at Reachability.MaxPathHops keeps its first 62 hops and its last two; the summary keeps
    // the real path's first six and last two, and counts the rest of its whole length.
    [Fact]
    public void Summary_RawPathTruncatedAt64Hops_CountsHiddenHopsFromItsWholeLength()
    {
        var hops = Enumerable.Range(0, 62).Select(i => Hop($"App.H{i}")).Concat([Hop("App.H98"), Hop("Ext.Sink", null)]).ToArray();
        var path = new ReachPath("App.H0", ReachEvidence.Bound, true, hops, 100, true, null);

        var example = Assert.Single(StatementsOf(Row(RootClass.NativeEntry, Capability.Network, 1, 1, path))).Example!;

        Assert.Equal(["App.H0", "App.H1", "App.H2", "App.H3", "App.H4", "App.H5", "App.H98", "Ext.Sink"], example.Hops);
        Assert.Equal(92, example.HiddenHops);
    }

    [Theory]
    [InlineData(ReachEvidence.Bound)]
    [InlineData(ReachEvidence.Instantiated)]
    [InlineData(ReachEvidence.ChaOnly)]
    public void Summary_Example_CopiesTheEvidence(ReachEvidence evidence)
    {
        var example = Assert.Single(StatementsOf(Row(RootClass.NativeEntry, Capability.Network, 1, 1, PathOf(true, evidence: evidence)))).Example!;

        Assert.Equal(evidence, example.Evidence);
    }
    #endregion

    #region Methods: bounds on hostile names (acceptance criterion 3)
    [Fact]
    public void Summary_Names_AreEscapedAndCut()
    {
        var longFolder = "lib/net8.0/" + new string('f', 300);
        var longNode = "App." + new string('n', 400);
        var longReason = "reason " + new string('r', 500);
        var longSameAs = "lib/net9.0/" + new string('s', 300);
        var report = Report(
            [Row(RootClass.NativeEntry, Capability.Network, 1, 1, new ReachPath(longNode, ReachEvidence.Bound, true, [Hop(longNode), Hop("Ext.Sink", null)], 2, false, null))],
            presented.Select(c => Status(c, RootClassVerdict.Unknown, 1, longReason)));

        var summary = Summarize(
            Analyzed(longFolder, report),
            NotAnalyzed("lib/net10.0", FolderOutcome.TimedOut, longReason),
            Analyzed("lib/net11.0", report, sameAs: longSameAs));

        var (folder, timedOut, copy) = (summary.Folders[0], summary.Folders[1], summary.Folders[2]);
        Assert.Equal(Cut(longFolder), folder.Folder);
        Assert.Equal(Cut(longNode), folder.Statements[0].Example!.Hops[0]);
        Assert.All(folder.Classes, c => Assert.Equal([Cut(longReason)], c.Reasons));
        Assert.Equal(Cut(longReason), timedOut.Reason);
        Assert.Equal(Cut(longSameAs), copy.SameAs);
        Assert.StartsWith(longFolder[..256] + "…[+55 chars, sha256:", folder.Folder, StringComparison.Ordinal);
        Assert.Matches(@"…\[\+\d+ chars, sha256:[0-9a-f]{8}\]$", folder.Folder);
    }

    // Two names sharing their first 256 chars still differ once cut.
    [Fact]
    public void Summary_TwoLongNamesSharingTheirFirst256Chars_StayDistinct()
    {
        var prefix = "lib/net8.0/" + new string('x', 300);

        var summary = Summarize(Analyzed(prefix + "A", Report([])), Analyzed(prefix + "B", Report([])));

        Assert.NotEqual(summary.Folders[0].Folder, summary.Folders[1].Folder);
    }

    [Theory]
    [InlineData(0x202E, "\\u202e")]       // RIGHT-TO-LEFT OVERRIDE
    [InlineData(0x200B, "\\u200b")]       // ZERO WIDTH SPACE
    [InlineData(0xE0041, "\\U000E0041")]  // TAG LATIN CAPITAL LETTER A
    public void Summary_InvisibleCharacters_ComeOutAsVisibleEscapes(int codePoint, string escape)
    {
        var raw = char.ConvertFromUtf32(codePoint);
        string Hostile(string name) => name + raw + "x";
        string Shown(string name) => name + escape + "x";
        var report = Report(
            [Row(RootClass.NativeEntry, Capability.Network, 1, 1, new ReachPath(Hostile("App.R"), ReachEvidence.Bound, true, [Hop(Hostile("App.R")), Hop("Ext.Sink", null)], 2, false, null))],
            presented.Select(c => Status(c, RootClassVerdict.Unknown, 1, Hostile("why"))),
            partial: true, partialReason: Hostile("partial"));

        var summary = Summarize(
            Analyzed(Hostile("lib/net8.0/a"), report, [new PackageGraphLoadFailure(Hostile("lib/net8.0/a/b.dll"), "x")]),
            NotAnalyzed(Hostile("lib/net9.0/a"), FolderOutcome.Crashed, Hostile("exit")),
            Analyzed("lib/net10.0", report, sameAs: Hostile("lib/net8.0/a")));

        var (folder, crashed, copy) = (summary.Folders[0], summary.Folders[1], summary.Folders[2]);
        Assert.Equal(Shown("lib/net8.0/a"), folder.Folder);
        Assert.Equal(Shown("App.R"), folder.Statements[0].Example!.Hops[0]);
        Assert.All(folder.Classes, c => Assert.Equal(
            [$"1 assembly(ies) did not load: {Shown("lib/net8.0/a/b.dll")}", $"the report is partial: {Shown("partial")}", Shown("why")], c.Reasons));
        Assert.Equal(Shown("lib/net9.0/a"), crashed.Folder);
        Assert.EndsWith(Shown("exit"), crashed.Reason, StringComparison.Ordinal);
        Assert.Equal(Shown("lib/net8.0/a"), copy.SameAs);
        Assert.DoesNotContain(raw, JsonSerializer.Serialize(summary, new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }), StringComparison.Ordinal);
    }

    // Escaping comes before the cut: a 252-char name with two bidi overrides is 262 chars escaped, so it is cut; were it
    // cut first, it would pass whole and be escaped to 262.
    [Fact]
    public void Summary_EscapingHappensBeforeTheCut()
    {
        var name = new string('a', 250) + "\u202E\u202E";
        var escaped = new string('a', 250) + "\\u202e\\u202e";

        var folder = Assert.Single(Summarize(Analyzed(name, Report([]))).Folders);

        Assert.Equal(Reachability.BoundNameTo(escaped, 256), folder.Folder);
        Assert.StartsWith(new string('a', 250) + "\\u202e…[+6 chars, sha256:", folder.Folder, StringComparison.Ordinal);
    }

    [Fact]
    public void Summary_ClassReasons_AreCappedAtEight_ThenSayHowManyMore()
    {
        var reasons = Enumerable.Range(0, 12).Select(i => $"reason {i}").ToArray();
        var report = Report([], presented.Select(c => Status(c, RootClassVerdict.Unknown, 1, reasons)));

        var folder = Only(report);

        Assert.All(folder.Classes, c => Assert.Equal([.. reasons.Take(8), "and 4 more reason(s)"], c.Reasons));
    }

    [Fact]
    public void Summary_ClassReasons_AreDeduplicatedBeforeTheCap()
    {
        var reasons = Enumerable.Range(0, 8).Select(i => $"reason {i}").Concat(["reason 0", "reason 3"]).ToArray();
        var report = Report([], presented.Select(c => Status(c, RootClassVerdict.Unknown, 1, reasons)));

        Assert.All(Only(report).Classes, c => Assert.Equal(reasons.Take(8), c.Reasons));
    }

    [Fact]
    public void Summary_ClassReasonsThatOnlyDifferPastTheCut_StayDistinct()
    {
        var prefix = new string('r', 300);
        var report = Report([], presented.Select(c => Status(c, RootClassVerdict.Unknown, 1, prefix + "A", prefix + "B")));

        Assert.All(Only(report).Classes, c => Assert.Equal([Cut(prefix + "A"), Cut(prefix + "B")], c.Reasons));
    }

    [Fact]
    public void Summary_ManySameAsFolders_CarryNothingOfTheirOwn()
    {
        var report = Report([Row(RootClass.NativeEntry, Capability.Network, 2, 1, PathOf(true), PathOf(false))]);
        var copies = Enumerable.Range(0, 500).Select(i => Analyzed($"lib/copy{i}", report, sameAs: "lib/net8.0"));

        var summary = Summarize([Analyzed("lib/net8.0", report), .. copies]);

        Assert.Equal(501, summary.Folders.Count);
        Assert.Equal(2, summary.Folders.Sum(f => f.Statements.Count));
        Assert.All(summary.Folders.Skip(1), f => Assert.True(f.Statements.Count == 0 && f.Classes.Count == 0 && f.Notes.Count == 0 && f.SameAs == "lib/net8.0"));
        Assert.Equal(0, summary.StatementsDropped);
        Assert.True(summary.Complete);
    }
    #endregion

    #region Methods: the statement cap
    [Fact]
    public void Summary_StatementCap_DropsInformationalBeforeTriggers_AndCounts()
    {
        // 56 informational folders of 36 statements (2,016), then one trigger folder of 15: 2,031 statements.
        var folders = Enumerable.Range(0, 56).Select(i => InformationalFolder($"lib/i{i:00}", 36)).Append(TriggerFolder("lib/zz-triggers")).ToArray();

        var summary = Summarize(folders);

        Assert.Equal(2000, summary.Folders.Sum(f => f.Statements.Count));
        Assert.Equal(31, summary.StatementsDropped);
        var triggers = summary.Folders[^1].Statements;
        Assert.Equal(15, triggers.Count);   // the late folder's triggers all survive
        Assert.All(triggers, s => Assert.Equal(ReachStatementKind.Trigger, s.Kind));
        Assert.All(summary.Folders.Take(55), f => Assert.Equal(36, f.Statements.Count));   // information fills in folder order
        Assert.Equal(Only(folders[55].Report!).Statements.Take(5), summary.Folders[55].Statements);   // the folder at the edge keeps a prefix
    }

    // Triggers take the cap first, across folders: a late folder's triggers survive while an early folder's information is
    // all dropped.
    [Fact]
    public void Summary_StatementCap_ATriggerInALateFolderSurvives_WhileAnEarlyFoldersInformationIsDropped()
    {
        // One informational folder (36), then 133 trigger folders of 15 and a last one of 5 Finalizer triggers: 2,000 triggers.
        var finalizersOnly = Analyzed("lib/zz-last", Report(signal.Select(c => Row(RootClass.Finalizer, c, 1, 1))));
        var folders = new[] { InformationalFolder("lib/a-info", 36) }
            .Concat(Enumerable.Range(0, 133).Select(i => TriggerFolder($"lib/t{i:000}")))
            .Append(finalizersOnly)
            .ToArray();

        var summary = Summarize(folders);

        Assert.Empty(summary.Folders[0].Statements);
        Assert.Equal(5, summary.Folders[^1].Statements.Count);
        Assert.Equal(2000, summary.Folders.Sum(f => f.Statements.Count));
        Assert.All(summary.Folders.SelectMany(f => f.Statements), s => Assert.Equal(ReachStatementKind.Trigger, s.Kind));
        Assert.Equal(36, summary.StatementsDropped);
    }

    [Fact]
    public void Summary_StatementCap_OverTriggers_KeepsTheFirstTwoThousandInFolderOrder()
    {
        // 134 trigger folders of 15: 2,010 triggers, 10 over.
        var summary = Summarize([.. Enumerable.Range(0, 134).Select(i => TriggerFolder($"lib/t{i:000}"))]);

        Assert.All(summary.Folders.Take(133), f => Assert.Equal(15, f.Statements.Count));
        Assert.Equal(5, summary.Folders[133].Statements.Count);
        Assert.Equal(10, summary.StatementsDropped);
    }

    [Fact]
    public void Summary_AtExactlyTheCap_DropsNothing()
    {
        // 55 folders of 36 and one of 20: 2,000.
        var folders = Enumerable.Range(0, 55).Select(i => InformationalFolder($"lib/i{i:00}", 36)).Append(InformationalFolder("lib/last", 20)).ToArray();

        var summary = Summarize(folders);

        Assert.Equal(2000, summary.Folders.Sum(f => f.Statements.Count));
        Assert.Equal(0, summary.StatementsDropped);
    }

    // The cap drops statements, not verdicts: dropping is not incompleteness.
    [Fact]
    public void Summary_StatementCap_DoesNotChangeComplete()
    {
        var summary = Summarize([.. Enumerable.Range(0, 60).Select(i => InformationalFolder($"lib/i{i:00}", 36))]);

        Assert.True(summary.StatementsDropped > 0);
        Assert.True(summary.Complete);
    }
    #endregion

    #region Methods: SameAs
    [Fact]
    public void Summary_SameAsFolder_RefersToItsPrimary()
    {
        var report = Report(
            [Row(RootClass.NativeEntry, Capability.Network, 2, 1, PathOf(true))],
            presented.Select(c => c == RootClass.LoadTime ? Status(c, RootClassVerdict.Unknown, 0, "a.dll: " + GraphFacts.ModuleInitializerGap) : Status(c, RootClassVerdict.Reaches)));

        var summary = Summarize(Analyzed("lib/net8.0", report), Analyzed("lib/net9.0", report, sameAs: "lib/net8.0"));

        var copy = summary.Folders[1];
        Assert.Equal(("lib/net9.0", PackageItemRole.Lib, FolderOutcome.Analyzed, (string?)null, (string?)"lib/net8.0"), (copy.Folder, copy.Role, copy.Outcome, copy.Reason, copy.SameAs));
        Assert.Empty(copy.Classes);
        Assert.Empty(copy.Notes);
        Assert.Empty(copy.Statements);
        Assert.NotEmpty(summary.Folders[0].Statements);
        Assert.NotEmpty(summary.Folders[0].Notes);
    }

    [Fact]
    public void Summary_SameAsFolder_StillCountsTowardComplete()
    {
        var good = Report([Row(RootClass.NativeEntry, Capability.Network, 1, 1)]);

        Assert.True(Summarize(Analyzed("lib/net8.0", good), Analyzed("lib/net9.0", good, sameAs: "lib/net8.0")).Complete);
        Assert.False(Summarize(Analyzed("lib/net8.0", good), Analyzed("lib/net9.0", good, [new PackageGraphLoadFailure("lib/net9.0/a.dll", "x")], sameAs: "lib/net8.0")).Complete);
        Assert.False(Summarize(Analyzed("lib/net8.0", good), Analyzed("lib/net9.0", Report([], partial: true, partialReason: "p"), sameAs: "lib/net8.0")).Complete);
        Assert.False(Summarize(Analyzed("lib/net8.0", good), Analyzed("lib/net9.0", Report([], [Status(RootClass.NativeEntry, RootClassVerdict.Unknown, 1, "u")]), sameAs: "lib/net8.0")).Complete);
    }

    [Fact]
    public void Summary_ANonAnalyzedSameAsFolder_KeepsItsReasonAndItsPrimary()
    {
        var copy = new FolderReachability("lib/net9.0", [], [], FolderOutcome.Crashed, null, "exit 35", "lib/net8.0", 0, 0);

        var summary = Summarize(Analyzed("lib/net8.0", Report([])), copy);

        Assert.Equal("lib/net8.0", summary.Folders[1].SameAs);
        Assert.Contains("unanalysable, and suspect", summary.Folders[1].Reason, StringComparison.Ordinal);
        Assert.False(summary.Complete);
    }
    #endregion

    #region Methods: order and role
    [Fact]
    public void Summary_StatementsInAFolder_AreOrdered_TriggerFirst_ThenClass_ThenCapabilityUnseenLast_ThenDirectFirst()
    {
        var statements = StatementsOf(
            Row(RootClass.LoadTime, null, 2, 1),
            Row(RootClass.TypeInitializer, Capability.Network, 2, 1),
            Row(RootClass.NativeEntry, Capability.Network, 1, 0),
            Row(RootClass.Finalizer, Capability.Network, 2, 1),
            Row(RootClass.NativeEntry, null, 1, 1),
            Row(RootClass.NativeEntry, Capability.Cryptography, 1, 1),
            Row(RootClass.HostContract, Capability.FileSystem, 1, 0),
            Row(RootClass.TypeInitializer, Capability.FileSystem, 1, 1),
            Row(RootClass.NativeEntry, Capability.FileSystem, 2, 1));

        Assert.Equal(
            [
                (ReachStatementKind.Trigger, RootClass.NativeEntry, (Capability?)Capability.FileSystem, true),
                (ReachStatementKind.Trigger, RootClass.NativeEntry, Capability.FileSystem, false),
                (ReachStatementKind.Trigger, RootClass.NativeEntry, Capability.Network, false),
                (ReachStatementKind.Trigger, RootClass.Finalizer, Capability.Network, true),
                (ReachStatementKind.Informational, RootClass.NativeEntry, Capability.Cryptography, true),
                (ReachStatementKind.Informational, RootClass.NativeEntry, null, true),
                (ReachStatementKind.Informational, RootClass.Finalizer, Capability.Network, false),
                (ReachStatementKind.Informational, RootClass.TypeInitializer, Capability.FileSystem, true),
                (ReachStatementKind.Informational, RootClass.TypeInitializer, Capability.Network, true),
                (ReachStatementKind.Informational, RootClass.TypeInitializer, Capability.Network, false),
                (ReachStatementKind.Informational, RootClass.HostContract, Capability.FileSystem, false),
                (ReachStatementKind.Informational, RootClass.LoadTime, null, true),
                (ReachStatementKind.Informational, RootClass.LoadTime, null, false),
            ],
            statements.Select(s => (s.Kind, s.Class, s.Capability, s.Direct)));
    }

    [Fact]
    public void Summary_Folders_KeepTheReportsOrder()
    {
        string[] names = ["tools/net8.0/any", "lib/net8.0", "build", "analyzers/dotnet/cs"];

        var summary = Summarize([.. names.Select(n => Analyzed(n, Report([])))]);

        Assert.Equal(names, summary.Folders.Select(f => f.Folder));
    }

    [Theory]
    [InlineData("lib/net8.0", PackageItemRole.Lib)]
    [InlineData("analyzers/dotnet/cs", PackageItemRole.Analyzers)]
    [InlineData("build", PackageItemRole.Build)]
    [InlineData("buildTransitive/net8.0", PackageItemRole.BuildTransitive)]
    [InlineData("tools/net8.0/any", PackageItemRole.Tools)]
    [InlineData("runtimes/win-x64/lib/net8.0", PackageItemRole.Runtimes)]
    [InlineData("", PackageItemRole.Other)]
    public void Summary_Role_ComesFromTheFolderPath(string folder, PackageItemRole role)
    {
        Assert.Equal(role, Assert.Single(Summarize(Analyzed(folder, Report([]))).Folders).Role);
        Assert.Equal(role, Assert.Single(Summarize(NotAnalyzed(folder, FolderOutcome.NotRun, "r")).Folders).Role);
    }
    #endregion

    #region Methods: determinism (acceptance criterion 4)
    [Fact]
    public void Summary_IsDeterministic()
    {
        var report = new PackageReachabilityReport(
        [
            Analyzed("lib/net8.0", Report(
                [
                    Row(RootClass.NativeEntry, Capability.Network, 3, 1, PathOf(true, 12), PathOf(false, 3, prefix: "App.D")),
                    Row(RootClass.TypeInitializer, null, 2, 2, PathOf(true, opacity: OpacityKind.IndirectCall), PathOf(true, ownSink: true)),
                    Row(RootClass.Finalizer, Capability.FileSystem, 1, 1, PathOf(true, evidence: ReachEvidence.ChaOnly)),
                ],
                presented.Select(c => c == RootClass.LoadTime ? Status(c, RootClassVerdict.Unknown, 0, "a.dll: " + GraphFacts.ModuleInitializerGap, "b\u202Ec") : Status(c, RootClassVerdict.Reaches)))),
            Analyzed("lib/net9.0", Report([]), sameAs: "lib/net8.0"),
            NotAnalyzed("tools/net8.0/any", FolderOutcome.Crashed, "exit 35"),
            NotAnalyzed("build", FolderOutcome.NothingLoaded, null, [new PackageGraphLoadFailure("build/x.dll", "not managed")]),
        ]);

        var first = JsonSerializer.SerializeToUtf8Bytes(ReachabilitySummary.From(report), json);
        var second = JsonSerializer.SerializeToUtf8Bytes(ReachabilitySummary.From(report), json);

        Assert.Equal(first, second);
        Assert.True(first.Length > 1000);   // not vacuous: the summary carries statements, examples, notes and reasons
    }
    #endregion

    #region Methods: never throws
    // Analyzed in name only: every presented class reads Unknown for the folder's reason, so the folder never reads clean
    // by its outcome alone.
    [Fact]
    public void Summary_AnAnalyzedFolderWithoutAReport_ReadsNoReport_AndIsNotComplete()
    {
        var summary = Summarize(new FolderReachability(Lib, [], [], FolderOutcome.Analyzed, null, null, null, 0, 0));

        var folder = Assert.Single(summary.Folders);
        Assert.Equal((FolderOutcome.Analyzed, "the folder has no reachability report"), (folder.Outcome, folder.Reason));
        AssertEveryClassUnknownFor(folder, folder.Reason!);
        Assert.Empty(folder.Notes);
        Assert.Empty(folder.Statements);
        Assert.False(summary.Complete);
    }

    [Fact]
    public void Summary_AnAnalyzedFolderWithoutAReport_AndLoadFailures_NamesBoth()
    {
        var failures = new[] { "a", "b", "c", "d" }.Select(n => new PackageGraphLoadFailure($"lib/net8.0/{n}.dll", "x")).ToArray();

        var summary = Summarize(new FolderReachability(Lib, [], failures, FolderOutcome.Analyzed, null, null, null, 0, 0));

        var folder = Assert.Single(summary.Folders);
        Assert.Equal("the folder has no reachability report; 4 assembly(ies) did not load: lib/net8.0/a.dll, lib/net8.0/b.dll, lib/net8.0/c.dll, and 1 more", folder.Reason);
        AssertEveryClassUnknownFor(folder, folder.Reason!);
        Assert.Empty(folder.Statements);
        Assert.False(summary.Complete);
    }

    // A folder that cannot be summarized (here, a null load-failure list) costs only itself: it keeps its outcome, every
    // presented class reads Unknown for the failure, and the folders around it are kept.
    [Fact]
    public void Summary_AFolderThatCannotBeSummarized_ReadsAsSuch_AndTheOthersAreKept()
    {
        var good = Report([Row(RootClass.NativeEntry, Capability.Network, 1, 1)]);
        var broken = new FolderReachability("lib/net9.0", [], null!, FolderOutcome.Analyzed, good, null, null, 0, 0);

        var summary = Summarize(Analyzed("lib/net8.0", good), broken, Analyzed("lib/net10.0", good));

        Assert.Equal(3, summary.Folders.Count);
        var failed = summary.Folders[1];
        Assert.Equal(("lib/net9.0", PackageItemRole.Other, FolderOutcome.Analyzed), (failed.Folder, failed.Role, failed.Outcome));
        Assert.StartsWith("the folder's reachability summary could not be built: ", failed.Reason, StringComparison.Ordinal);
        AssertEveryClassUnknownFor(failed, failed.Reason!);
        Assert.Empty(failed.Statements);
        Assert.Single(summary.Folders[0].Statements);
        Assert.Single(summary.Folders[2].Statements);
        Assert.False(summary.Complete);
    }

    [Fact]
    public void Summary_FromANullReport_DoesNotThrow_AndIsIncomplete()
    {
        var summary = ReachabilitySummary.From(null!);

        var folder = Assert.Single(summary.Folders);
        Assert.Equal(FolderOutcome.NotRun, folder.Outcome);
        Assert.StartsWith("the reachability summary could not be built: ", folder.Reason, StringComparison.Ordinal);
        Assert.False(summary.Complete);
    }

    // A null folder costs only itself: it reads NotRun, unnamed, with every class Unknown, and the good folder is intact.
    [Fact]
    public void Summary_ANullFolderInTheReport_DoesNotThrow_AndIsIncomplete()
    {
        var good = Analyzed(Lib, Report([Row(RootClass.NativeEntry, Capability.Network, 2, 1, PathOf(true), PathOf(false))]));

        var summary = ReachabilitySummary.From(new PackageReachabilityReport([good, null!]));

        Assert.Equal(2, summary.Folders.Count);
        Assert.Equal(JsonSerializer.Serialize(Assert.Single(Summarize(good).Folders), json), JsonSerializer.Serialize(summary.Folders[0], json));
        var unnamed = summary.Folders[1];
        Assert.Equal((string.Empty, FolderOutcome.NotRun), (unnamed.Folder, unnamed.Outcome));
        Assert.StartsWith("the folder's reachability summary could not be built: ", unnamed.Reason, StringComparison.Ordinal);
        AssertEveryClassUnknownFor(unnamed, unnamed.Reason!);
        Assert.Empty(unnamed.Statements);
        Assert.False(summary.Complete);
    }

    [Fact]
    public void Summary_AReportWithNullLists_DoesNotThrow_AndIsIncomplete()
    {
        var report = new ReachabilityReport(null!, null!, false, null!, 0, null!, 0, coverage, false, null);

        var summary = Summarize(Analyzed(Lib, report));

        Assert.NotNull(Assert.Single(summary.Folders).Reason);
        Assert.False(summary.Complete);
    }
    #endregion

    #region Methods: helpers
    // The five presented classes, in table order, each Unknown with no roots and exactly `reason`.
    private static void AssertEveryClassUnknownFor(FolderReachSummary folder, string reason)
    {
        Assert.Equal(presented, folder.Classes.Select(c => c.Class));
        Assert.All(folder.Classes, c => Assert.Equal((0, RootClassVerdict.Unknown), (c.Roots, c.Verdict)));
        Assert.All(folder.Classes, c => Assert.Equal([reason], c.Reasons));
    }

    private static ReachStatementKind Expected(RootClass cls, Capability? sink, bool direct) =>
        sink is { } c && signal.Contains(c) && (cls == RootClass.NativeEntry || (cls == RootClass.Finalizer && direct))
            ? ReachStatementKind.Trigger
            : ReachStatementKind.Informational;

    private static string Cut(string name) => Reachability.BoundNameTo(name, 256);

    private static ReachHop Hop(string nodeId, string? assembly = "App") => new(nodeId, assembly, null, 0);

    // A path of `hops` hops, prefix0 .. prefix{hops-1}; the last one is the sink, an external API unless ownSink.
    private static ReachPath PathOf(bool direct, int hops = 2, string prefix = "App.H", ReachEvidence evidence = ReachEvidence.Bound, OpacityKind? opacity = null, bool ownSink = false) =>
        new(prefix + "0", evidence, direct, [.. Enumerable.Range(0, hops).Select(i => Hop(prefix + i, i < hops - 1 || ownSink ? "App" : null))], hops, false, opacity);

    private static CapabilityReach Row(RootClass cls, Capability? capability, int roots, int direct, params ReachPath[] examples) =>
        new(cls, capability, roots, roots, roots, direct, examples);

    private static RootClassStatus Status(RootClass cls, RootClassVerdict verdict, int roots = 1, params string[] reasons) => new(cls, roots, verdict, reasons);

    // A report with these rows; every presented class Reaches unless `classes` says otherwise.
    private static ReachabilityReport Report(IEnumerable<CapabilityReach> rows, IEnumerable<RootClassStatus>? classes = null, bool partial = false, string? partialReason = null) =>
        new([.. rows], [], false, [.. classes ?? presented.Select(c => Status(c, RootClassVerdict.Reaches))], 0, [], 0, coverage, partial, partialReason);

    private static FolderReachability Analyzed(string folder, ReachabilityReport report, IReadOnlyList<PackageGraphLoadFailure>? failures = null, string? sameAs = null) =>
        new(folder, [$"{folder}/a.dll"], failures ?? [], FolderOutcome.Analyzed, report, null, sameAs, 10, 10);

    private static FolderReachability NotAnalyzed(string folder, FolderOutcome outcome, string? reason, IReadOnlyList<PackageGraphLoadFailure>? failures = null) =>
        new(folder, [$"{folder}/a.dll"], failures ?? [], outcome, null, reason, null, 0, 0);

    // `count` (at most 36) informational statements: one Direct row per (TypeInitializer, HostContract, LoadTime) x sink.
    private static FolderReachability InformationalFolder(string folder, int count) =>
        Analyzed(folder, Report(new[] { RootClass.TypeInitializer, RootClass.HostContract, RootClass.LoadTime }
            .SelectMany(cls => allSinks.Select(sink => Row(cls, sink, 1, 1)))
            .Take(count)));

    // 15 triggers: NativeEntry at both labels and Finalizer at Direct, on each signal capability.
    private static FolderReachability TriggerFolder(string folder) =>
        Analyzed(folder, Report(signal.SelectMany(c => new[] { Row(RootClass.NativeEntry, c, 2, 1), Row(RootClass.Finalizer, c, 1, 1) })));

    private static ReachabilitySummary Summarize(params FolderReachability[] folders) => ReachabilitySummary.From(new(folders));

    private static FolderReachSummary Only(ReachabilityReport report) => Assert.Single(Summarize(Analyzed(Lib, report)).Folders);

    private static IReadOnlyList<ReachStatement> StatementsOf(params CapabilityReach[] rows) => Only(Report(rows)).Statements;

    public static TheoryData<Capability> SignalCapabilities() => [.. signal];

    public static TheoryData<Capability> NonSignalCapabilities() => [.. Enum.GetValues<Capability>().Except(signal)];

    public static TheoryData<RootClass> PresentedClasses() => [.. presented];

    public static TheoryData<RootClass, string> ClassSubjects() => new()
    {
        { RootClass.NativeEntry, "a native entry point" },
        { RootClass.Finalizer, "a finalizer" },
        { RootClass.TypeInitializer, "a type initializer" },
        { RootClass.HostContract, "a build-host entry point (MSBuild task, analyzer, generator)" },
        { RootClass.LoadTime, "a module initializer" },
    };

    public static TheoryData<RootClass, string, Capability> InformationalClassesOnSignalCapabilities()
    {
        var data = new TheoryData<RootClass, string, Capability>();
        foreach (var (cls, subject) in new[] { (RootClass.TypeInitializer, "a type initializer"), (RootClass.HostContract, "a build-host entry point (MSBuild task, analyzer, generator)"), (RootClass.LoadTime, "a module initializer") })
            foreach (var capability in signal)
                data.Add(cls, subject, capability);
        return data;
    }
    #endregion

    #region Fields
    private const string Lib = "lib/net8.0";

    private static readonly RootClass[] presented =
        [RootClass.NativeEntry, RootClass.Finalizer, RootClass.TypeInitializer, RootClass.HostContract, RootClass.LoadTime];

    private static readonly Capability[] signal =
        [Capability.ProcessExecution, Capability.Registry, Capability.Network, Capability.NativeInterop, Capability.FileSystem];

    private static readonly Capability?[] allSinks = [.. Enum.GetValues<Capability>().Select(c => (Capability?)c), null];

    private static readonly GraphCoverage coverage =
        new(new IndexCoverage(0, 0, 0), 0, 0, 0, 0, ResolutionCounts.None, 0, 0, 0, 0, 0, 0, 0, false, null);

    private static readonly JsonSerializerOptions json = new() { Converters = { new JsonStringEnumConverter() } };
    #endregion
}
