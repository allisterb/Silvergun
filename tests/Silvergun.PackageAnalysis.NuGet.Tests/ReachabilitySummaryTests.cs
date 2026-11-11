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
/// example paths, the bounds on hostile names and on the statement count, <c>SameAs</c> (a copy whose folder role makes
/// other cells triggers than its primary's is listed in full, review C1), order, role (a folder is judged by its own role
/// or a loaded member's, review W1), determinism and that it never throws. Hostile characters are built from escapes; the
/// source holds none raw.
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

    // The role axis below is checked over every role by name: a new role must be placed on the table, not defaulted.
    [Fact]
    public void Premise_PackageItemRole_IsTheEightRoles()
    {
        Assert.Equal(
            [PackageItemRole.Lib, PackageItemRole.Runtimes, PackageItemRole.Tools, PackageItemRole.Build, PackageItemRole.BuildTransitive, PackageItemRole.Analyzers, PackageItemRole.Content, PackageItemRole.Other],
            Enum.GetValues<PackageItemRole>());
    }

    // The folder data below names a folder of every role, so the summary-level role tests cover them all.
    [Fact]
    public void Premise_TheRoleFolders_CoverEveryRole()
    {
        var roles = FinalizerTriggerFolders().Concat(FinalizerInformationalFolders()).Select(row => (PackageItemRole)row[1]).Distinct();

        Assert.Equal(Enum.GetValues<PackageItemRole>(), roles.OrderBy(r => r));
    }

    // Acceptance criterion 1, "and only for it": over every single root class, every sink, both labels and every folder
    // role, a trigger is exactly NativeEntry (either label, any role) or Finalizer (Direct, in a lib or runtimes folder) on
    // a signal capability (user's ruling, 2026-11-11).
    [Fact]
    public void Presentation_KindOf_IsATrigger_OnlyForNativeEntry_AndFinalizerDirectInLibOrRuntimes_OnASignalCapability()
    {
        var triggers = 0;
        foreach (var cls in Enum.GetValues<RootClass>().Where(c => c != RootClass.None))
            foreach (var sink in allSinks)
                foreach (var direct in new[] { true, false })
                    foreach (var role in Enum.GetValues<PackageItemRole>())
                    {
                        var kind = ReachabilityPresentation.KindOf(cls, sink, direct, role);
                        Assert.True(Expected(cls, sink, direct, role) == kind, $"{cls} {sink?.ToString() ?? "unseen"} direct={direct} role={role}");
                        triggers += kind == ReachStatementKind.Trigger ? 1 : 0;
                    }

        // NativeEntry: 5 signal capabilities x 2 labels x 8 roles; Finalizer: 5 x Direct x {Lib, Runtimes}.
        Assert.Equal(5 * 2 * 8 + 5 * 2, triggers);
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
        Assert.All(statements, s => Assert.Equal(Expected(s.Class, s.Capability, s.Direct, PackageItemRole.Lib), s.Kind));
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

    #region Methods: the folder role (user's ruling, 2026-11-11)
    // Finalizer at Direct triggers only where R2b measured it: lib and runtimes folders, by the folder's first segment.
    [Theory]
    [MemberData(nameof(FinalizerTriggerFolders))]
    public void Summary_FinalizerDirect_IsATrigger_InALibOrRuntimesFolder(string folder, PackageItemRole role)
    {
        var summary = Assert.Single(Summarize(Analyzed(folder, Report(signal.Select(c => Row(RootClass.Finalizer, c, 1, 1, PathOf(true)))))).Folders);

        Assert.Equal(role, summary.Role);
        Assert.Equal(
            signal.OrderBy(c => c).Select(c => (ReachStatementKind.Trigger, (Capability?)c, true, $"a finalizer directly reaches {c}")),
            summary.Statements.Select(s => (s.Kind, s.Capability, s.Direct, s.Text)));
    }

    [Theory]
    [MemberData(nameof(FinalizerInformationalFolders))]
    public void Summary_FinalizerDirect_IsInformational_OutsideLibAndRuntimes(string folder, PackageItemRole role)
    {
        var summary = Assert.Single(Summarize(Analyzed(folder, Report(signal.Select(c => Row(RootClass.Finalizer, c, 1, 1, PathOf(true)))))).Folders);

        Assert.Equal(role, summary.Role);
        Assert.Equal(
            signal.OrderBy(c => c).Select(c => (ReachStatementKind.Informational, (Capability?)c, true, $"a finalizer directly reaches {c}")),
            summary.Statements.Select(s => (s.Kind, s.Capability, s.Direct, s.Text)));
    }

    // The role changes only the Kind: the same reach in a folder of every role gives the same statement otherwise.
    [Fact]
    public void Summary_FinalizerDirect_IsTheSameStatementInEveryRole_ButForItsKind()
    {
        var folders = AllRoleFolders();
        var report = Report([Row(RootClass.Finalizer, Capability.ProcessExecution, 1, 1, PathOf(true, 3, evidence: ReachEvidence.ChaOnly))]);

        var summary = Summarize([.. folders.Select(f => Analyzed(f.Folder, report))]);

        var statements = summary.Folders.Select(f => Assert.Single(f.Statements)).ToArray();
        Assert.Equal(
            folders.Select(f => f.Role is PackageItemRole.Lib or PackageItemRole.Runtimes ? ReachStatementKind.Trigger : ReachStatementKind.Informational),
            statements.Select(s => s.Kind));
        Assert.Single(statements
            .Select(s => (s.Class, s.Capability, s.Direct, s.Roots, s.Text, s.Example!.Evidence, string.Join("|", s.Example!.Hops), s.Example!.HiddenHops, s.Example!.Unseen))
            .Distinct());
        Assert.Equal("a finalizer directly reaches ProcessExecution", statements[0].Text);
    }

    [Theory]
    [MemberData(nameof(AllRoleFolderData))]
    public void Summary_FinalizerDeferred_IsInformational_InEveryRole(string folder, PackageItemRole role)
    {
        var summary = Assert.Single(Summarize(Analyzed(folder, Report(signal.Select(c => Row(RootClass.Finalizer, c, 1, 0, PathOf(false)))))).Folders);

        Assert.Equal(role, summary.Role);
        Assert.Equal(
            signal.OrderBy(c => c).Select(c => (ReachStatementKind.Informational, (Capability?)c, false, $"a finalizer creates a delegate that reaches {c}")),
            summary.Statements.Select(s => (s.Kind, s.Capability, s.Direct, s.Text)));
    }

    // NativeEntry, at both labels, still triggers in every role: tasks/ and tools/ included.
    [Theory]
    [MemberData(nameof(AllRoleFolderData))]
    public void Summary_NativeEntry_IsATrigger_AtBothLabels_InEveryRole(string folder, PackageItemRole role)
    {
        var summary = Assert.Single(Summarize(Analyzed(folder, Report(signal.Select(c => Row(RootClass.NativeEntry, c, 2, 1, PathOf(true), PathOf(false)))))).Folders);

        Assert.Equal(role, summary.Role);
        Assert.Equal(
            signal.SelectMany(c => new[]
            {
                (ReachStatementKind.Trigger, (Capability?)c, true, $"a native entry point directly reaches {c}"),
                (ReachStatementKind.Trigger, (Capability?)c, false, $"a native entry point creates a delegate that reaches {c}"),
            }).OrderBy(t => (int)t.Item2!.Value).ThenBy(t => !t.Item3),
            summary.Statements.Select(s => (s.Kind, s.Capability, s.Direct, s.Text)));
    }

    // Every presented cell in a folder of each role carries the table's kind for that role: 10 NativeEntry triggers
    // everywhere, plus Finalizer's 5 in lib and runtimes.
    [Theory]
    [MemberData(nameof(AllRoleFolderData))]
    public void Summary_EveryPresentedCell_HasTheTablesKind_InEveryRole(string folder, PackageItemRole role)
    {
        var rows = presented.SelectMany(cls => allSinks.Select(sink => Row(cls, sink, 2, 1))).ToArray();

        var summary = Assert.Single(Summarize(Analyzed(folder, Report(rows))).Folders);

        Assert.Equal(role, summary.Role);
        Assert.Equal(rows.Length * 2, summary.Statements.Count);
        Assert.All(summary.Statements, s => Assert.Equal(Expected(s.Class, s.Capability, s.Direct, role), s.Kind));
        Assert.Equal(5 * 2 + (role is PackageItemRole.Lib or PackageItemRole.Runtimes ? 5 : 0), summary.Statements.Count(s => s.Kind == ReachStatementKind.Trigger));
    }

    // Statements sort by Kind first, so outside lib and runtimes the Finalizer/Direct statement sorts with the
    // informational ones, by class, ahead of its deferred twin; in lib it stays among the triggers (the order test above).
    [Theory]
    [MemberData(nameof(FinalizerInformationalFolders))]
    public void Summary_FinalizerDirect_OutsideLibAndRuntimes_SortsWithTheInformationalStatements(string folder, PackageItemRole role)
    {
        var report = Report(
        [
            Row(RootClass.LoadTime, null, 2, 1),
            Row(RootClass.TypeInitializer, Capability.Network, 2, 1),
            Row(RootClass.NativeEntry, Capability.Network, 1, 0),
            Row(RootClass.Finalizer, Capability.Network, 2, 1),
            Row(RootClass.NativeEntry, null, 1, 1),
            Row(RootClass.NativeEntry, Capability.Cryptography, 1, 1),
            Row(RootClass.HostContract, Capability.FileSystem, 1, 0),
            Row(RootClass.TypeInitializer, Capability.FileSystem, 1, 1),
            Row(RootClass.NativeEntry, Capability.FileSystem, 2, 1),
        ]);

        var summary = Assert.Single(Summarize(Analyzed(folder, report)).Folders);

        Assert.Equal(role, summary.Role);
        Assert.Equal(
            [
                (ReachStatementKind.Trigger, RootClass.NativeEntry, (Capability?)Capability.FileSystem, true),
                (ReachStatementKind.Trigger, RootClass.NativeEntry, Capability.FileSystem, false),
                (ReachStatementKind.Trigger, RootClass.NativeEntry, Capability.Network, false),
                (ReachStatementKind.Informational, RootClass.NativeEntry, Capability.Cryptography, true),
                (ReachStatementKind.Informational, RootClass.NativeEntry, null, true),
                (ReachStatementKind.Informational, RootClass.Finalizer, Capability.Network, true),
                (ReachStatementKind.Informational, RootClass.Finalizer, Capability.Network, false),
                (ReachStatementKind.Informational, RootClass.TypeInitializer, Capability.FileSystem, true),
                (ReachStatementKind.Informational, RootClass.TypeInitializer, Capability.Network, true),
                (ReachStatementKind.Informational, RootClass.TypeInitializer, Capability.Network, false),
                (ReachStatementKind.Informational, RootClass.HostContract, Capability.FileSystem, false),
                (ReachStatementKind.Informational, RootClass.LoadTime, null, true),
                (ReachStatementKind.Informational, RootClass.LoadTime, null, false),
            ],
            summary.Statements.Select(s => (s.Kind, s.Class, s.Capability, s.Direct)));
    }

    // The package-wide cap keeps triggers first, and only what is a trigger in its folder's role counts as one: 56
    // informational lib folders of 36 (2,016), then a folder of 15 reaches (10 NativeEntry, 5 Finalizer/Direct). In lib or
    // runtimes all 15 are triggers and survive; elsewhere the 5 Finalizer/Direct are informational, come last in folder
    // order, and are the ones dropped. 2,031 statements, 31 dropped either way.
    [Theory]
    [InlineData("lib/zz-triggers", 15)]
    [InlineData("runtimes/win/lib/net8.0", 15)]
    [InlineData("tools/net8.0", 10)]
    [InlineData("tasks/net461", 10)]
    [InlineData("tools/net8.0/runtimes/browser/lib/net8.0", 10)]
    public void Summary_StatementCap_KeepsTriggersFirst_ByTheirFoldersRole(string last, int keptInLast)
    {
        var folders = Enumerable.Range(0, 56).Select(i => InformationalFolder($"lib/i{i:00}", 36)).Append(TriggerFolder(last)).ToArray();

        var summary = Summarize(folders);

        Assert.Equal(2000, summary.Folders.Sum(f => f.Statements.Count));
        Assert.Equal(31, summary.StatementsDropped);
        var lastStatements = summary.Folders[^1].Statements;
        Assert.Equal(keptInLast, lastStatements.Count);
        Assert.All(lastStatements, s => Assert.Equal(ReachStatementKind.Trigger, s.Kind));
        Assert.Equal(10, lastStatements.Count(s => s.Class == RootClass.NativeEntry));
        Assert.Equal(keptInLast - 10, lastStatements.Count(s => s.Class == RootClass.Finalizer));
        Assert.All(summary.Folders.Take(55), f => Assert.Equal(36, f.Statements.Count));
        Assert.Equal(20 - keptInLast, summary.Folders[55].Statements.Count);   // the information at the edge gets what the triggers leave
    }

    // A tool may ship a runtimes/.../lib tree of its own: the role is the first segment's, so it is still Tools.
    [Fact]
    public void Summary_NestedRuntimesLibUnderTools_IsTools_SoFinalizerDirectIsInformational()
    {
        const string folder = "tools/net8.0/runtimes/browser/lib/net8.0";

        var summary = Assert.Single(Summarize(Analyzed(folder, Report([Row(RootClass.Finalizer, Capability.FileSystem, 1, 1, PathOf(true)), Row(RootClass.NativeEntry, Capability.FileSystem, 1, 1, PathOf(true))]))).Folders);

        Assert.Equal(PackageItemRole.Tools, summary.Role);
        Assert.Equal(
            [
                (ReachStatementKind.Trigger, RootClass.NativeEntry, "a native entry point directly reaches FileSystem"),
                (ReachStatementKind.Informational, RootClass.Finalizer, "a finalizer directly reaches FileSystem"),
            ],
            summary.Statements.Select(s => (s.Kind, s.Class, s.Text)));
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

        // The copy's primary is in the report (last; the lookup is by name), so the copy keeps its SameAs (review C1).
        var summary = Summarize(
            Analyzed(longFolder, report),
            NotAnalyzed("lib/net10.0", FolderOutcome.TimedOut, longReason),
            Analyzed("lib/net11.0", report, sameAs: longSameAs),
            Analyzed(longSameAs, report));

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

    #region Methods: SameAs across folder roles (review C1)
    // Deduplication ignores paths and folders sort ordinally, so build/net8.0 is the primary and lib/net8.0 its copy. The
    // copy is listed in full under its own role: the lib Finalizer/Direct trigger survives the build primary's information.
    [Fact]
    public void Summary_SameAsLibCopy_OfABuildPrimary_KeepsItsFinalizerDirectTriggers()
    {
        var report = CrossRoleReport();

        var summary = Summarize(Analyzed("build/net8.0", report), Analyzed("lib/net8.0", report, sameAs: "build/net8.0"));

        var (primary, copy) = (summary.Folders[0], summary.Folders[1]);
        Assert.Equal((PackageItemRole.Build, (string?)null), (primary.Role, primary.SameAs));
        Assert.Equal([(ReachStatementKind.Trigger, RootClass.NativeEntry), (ReachStatementKind.Informational, RootClass.Finalizer)], KindsOf(primary));
        Assert.Empty(primary.Notes);
        Assert.Equal(("lib/net8.0", PackageItemRole.Lib, FolderOutcome.Analyzed, (string?)null, (string?)null), (copy.Folder, copy.Role, copy.Outcome, copy.Reason, copy.SameAs));
        Assert.Equal([(ReachStatementKind.Trigger, RootClass.NativeEntry), (ReachStatementKind.Trigger, RootClass.Finalizer)], KindsOf(copy));
        Assert.Equal([ListedInFull("build/net8.0")], copy.Notes);
        AssertIsTheFolderAlone(copy, Analyzed("lib/net8.0", report));
        Assert.Equal(presented, copy.Classes.Select(c => c.Class));
        Assert.Equal(0, summary.StatementsDropped);
        Assert.True(summary.Complete);
    }

    // The copy's own notes come first, then the one that says why it is listed.
    [Fact]
    public void Summary_ADivergentCopy_KeepsItsLoadTimeNote_BeforeTheListedInFullNote()
    {
        var report = CrossRoleReport(loadTimeGap: true);

        var summary = Summarize(Analyzed("build/net8.0", report), Analyzed("lib/net8.0", report, sameAs: "build/net8.0"));

        Assert.Equal([LoadTimeNote], summary.Folders[0].Notes);
        Assert.Equal([LoadTimeNote, ListedInFull("build/net8.0")], summary.Folders[1].Notes);
        Assert.False(summary.Complete);   // LoadTime is Unknown in both
    }

    [Fact]
    public void Summary_ADivergentCopy_StillCountsTowardComplete()
    {
        var good = CrossRoleReport();
        var failure = new PackageGraphLoadFailure("lib/net8.0/a.dll", "x");

        Assert.True(Summarize(Analyzed("build/net8.0", good), Analyzed("lib/net8.0", good, sameAs: "build/net8.0")).Complete);
        var failed = Summarize(Analyzed("build/net8.0", good), Analyzed("lib/net8.0", good, [failure], sameAs: "build/net8.0"));
        Assert.False(failed.Complete);
        Assert.All(failed.Folders[1].Classes, c => Assert.Equal(RootClassVerdict.Unknown, c.Verdict));
        Assert.All(failed.Folders[0].Classes, c => Assert.Equal(RootClassVerdict.Reaches, c.Verdict));
        Assert.False(Summarize(Analyzed("build/net8.0", good), Analyzed("lib/net8.0", Report([], partial: true, partialReason: "p"), sameAs: "build/net8.0")).Complete);
    }

    // 55 informational lib folders of 36 (1,980), then build/zz (10 NativeEntry triggers, 5 Finalizer/Direct informational
    // in build) and its lib/zz copy (all 15 triggers): 2,010 statements, 25 triggers. Every trigger survives; the build
    // primary's 5 informational come last and are dropped, and the information at the edge gives up 5 more.
    [Fact]
    public void Summary_StatementCap_CountsADivergentCopysTriggers_AsTriggers()
    {
        var folders = Enumerable.Range(0, 55).Select(i => InformationalFolder($"lib/i{i:00}", 36))
            .Append(TriggerFolder("build/zz"))
            .Append(TriggerFolder("lib/zz") with { SameAs = "build/zz" })
            .ToArray();

        var summary = Summarize(folders);

        Assert.Equal(2000, summary.Folders.Sum(f => f.Statements.Count));
        Assert.Equal(10, summary.StatementsDropped);
        var (primary, copy) = (summary.Folders[^2], summary.Folders[^1]);
        Assert.Equal(10, primary.Statements.Count);
        Assert.All(primary.Statements, s => Assert.Equal((ReachStatementKind.Trigger, RootClass.NativeEntry), (s.Kind, s.Class)));
        Assert.Null(copy.SameAs);
        Assert.Equal(15, copy.Statements.Count);
        Assert.All(copy.Statements, s => Assert.Equal(ReachStatementKind.Trigger, s.Kind));
        Assert.All(summary.Folders.Take(54), f => Assert.Equal(36, f.Statements.Count));
        Assert.Equal(31, summary.Folders[54].Statements.Count);
    }

    // The reverse: a lib primary and its tools copy also differ, so the copy is listed in full, its Finalizer/Direct
    // informational as tools makes it.
    [Fact]
    public void Summary_SameAsToolsCopy_OfALibPrimary_IsListedInFull_WithFinalizerDirectInformational()
    {
        var report = CrossRoleReport();

        var summary = Summarize(Analyzed("lib/net8.0", report), Analyzed("tools/net8.0", report, sameAs: "lib/net8.0"));

        var (primary, copy) = (summary.Folders[0], summary.Folders[1]);
        Assert.Equal([(ReachStatementKind.Trigger, RootClass.NativeEntry), (ReachStatementKind.Trigger, RootClass.Finalizer)], KindsOf(primary));
        Assert.Empty(primary.Notes);
        Assert.Equal((PackageItemRole.Tools, (string?)null), (copy.Role, copy.SameAs));
        Assert.Equal([(ReachStatementKind.Trigger, RootClass.NativeEntry), (ReachStatementKind.Informational, RootClass.Finalizer)], KindsOf(copy));
        Assert.Equal([ListedInFull("lib/net8.0")], copy.Notes);
        AssertIsTheFolderAlone(copy, Analyzed("tools/net8.0", report));
    }

    // Any pair whose roles make different cells triggers: the copy is its own folder summarized alone, plus the note.
    [Theory]
    [InlineData("build/net8.0", "lib/net8.0")]
    [InlineData("buildTransitive/net8.0", "runtimes/win/lib/net8.0")]
    [InlineData("tools/net8.0", "Lib/net8.0")]
    [InlineData("analyzers/dotnet/cs", "runtimes/win-x64/native")]
    [InlineData("lib/net8.0", "tasks/net461")]
    [InlineData("runtimes/win/lib/net8.0", "build/net8.0")]
    [InlineData("lib/net8.0", "tools/net8.0/runtimes/browser/lib/net8.0")]
    public void Summary_SameAsCopy_WhoseRoleTriggersOtherwise_IsListedInFull(string primaryFolder, string copyFolder)
    {
        var report = CrossRoleReport();

        var summary = Summarize(Analyzed(primaryFolder, report), Analyzed(copyFolder, report, sameAs: primaryFolder));

        var copy = summary.Folders[1];
        Assert.Null(copy.SameAs);
        Assert.Equal([ListedInFull(primaryFolder)], copy.Notes);
        AssertIsTheFolderAlone(copy, Analyzed(copyFolder, report));
        AssertIsTheFolderAlone(summary.Folders[0], Analyzed(primaryFolder, report));
        Assert.Empty(summary.Folders[0].Notes);
    }

    // Lib with runtimes, and any two roles where only NativeEntry triggers, make the same cells triggers: the copy stays a
    // reference to its primary, with nothing of its own.
    [Theory]
    [InlineData("lib/net8.0", "runtimes/win/lib/net8.0")]
    [InlineData("runtimes/win/lib/net8.0", "lib/net8.0")]
    [InlineData("lib/net8.0", "Lib/net9.0")]
    [InlineData("tools/a", "tasks/b")]
    [InlineData("build/net8.0", "tools/net8.0")]
    [InlineData("analyzers/dotnet/cs", "content/any")]
    [InlineData("buildTransitive/net8.0", "contentFiles/any/net8.0")]
    [InlineData("tools/net8.0", "tools/net8.0/runtimes/browser/lib/net8.0")]
    public void Summary_SameAsCopy_WhoseRoleTriggersAlike_StaysSuppressed(string primaryFolder, string copyFolder)
    {
        var report = CrossRoleReport();

        var summary = Summarize(Analyzed(primaryFolder, report), Analyzed(copyFolder, report, sameAs: primaryFolder));

        var copy = summary.Folders[1];
        Assert.Equal((copyFolder, FolderOutcome.Analyzed, (string?)null, (string?)primaryFolder), (copy.Folder, copy.Outcome, copy.Reason, copy.SameAs));
        Assert.Empty(copy.Classes);
        Assert.Empty(copy.Notes);
        Assert.Empty(copy.Statements);
        Assert.Equal(2, summary.Folders[0].Statements.Count);
        Assert.True(summary.Complete);
    }

    // A crafted SameAs naming a folder the report does not hold: there is no primary to defer to, so the copy is listed in
    // full, even in a role that would have matched.
    [Theory]
    [InlineData("lib/net9.0", "lib/gone")]
    [InlineData("tools/net9.0", "tools/gone")]
    [InlineData("lib/net9.0", "")]
    public void Summary_SameAsCopy_WhosePrimaryIsNotInTheReport_IsListedInFull(string copyFolder, string missing)
    {
        var report = CrossRoleReport();

        var summary = Summarize(Analyzed("lib/net8.0", report), Analyzed(copyFolder, report, sameAs: missing));

        var copy = summary.Folders[1];
        Assert.Null(copy.SameAs);
        Assert.Equal([ListedInFull(missing)], copy.Notes);
        AssertIsTheFolderAlone(copy, Analyzed(copyFolder, report));
    }

    // The missing primary's name is attacker-shaped: the note escapes it, and the cut bounds the whole note. The
    // explanation comes first, so a long name loses only its own end to the cut.
    [Fact]
    public void Summary_TheListedInFullNote_EscapesThePrimarysName_AndTheCutTakesOnlyItsEnd()
    {
        var rlo = char.ConvertFromUtf32(0x202E);
        var tail = new string('g', 300);
        const string explanation = "listed in full because its folder role changes which statements are triggers; same files as ";

        var summary = Summarize(Analyzed("lib/net8.0", CrossRoleReport(), sameAs: "lib/" + rlo + tail));

        var note = Assert.Single(Assert.Single(summary.Folders).Notes);
        Assert.Equal(Cut(ListedInFull("lib/" + @"\" + "u202e" + tail)), note);
        Assert.StartsWith(explanation + "lib/" + @"\" + "u202e" + "ggg", note, StringComparison.Ordinal);
        Assert.StartsWith((explanation + "lib/" + @"\" + "u202e" + tail)[..256] + (char)0x2026 + "[+", note, StringComparison.Ordinal);   // cut inside the name
        Assert.True(explanation.Length + "lib/".Length < 256);
        Assert.DoesNotContain(rlo, note, StringComparison.Ordinal);
    }

    // What PackageReachability.Copy gives the copy of a primary that was not analysed: the primary's outcome and reason,
    // remapped to the copy's own paths, and SameAs the primary (GraphWorkerParentTests pins that end to end). Only an
    // analysed copy has statements for its role to change, so a not-analysed one is never divergent: whatever the two
    // roles, it keeps its outcome, its reason and its SameAs, and gets no note.
    [Theory]
    [MemberData(nameof(NotAnalyzedCopyCases))]
    public void Summary_ACrashedTimedOutOrNotRunCopy_KeepsItsOutcomeReasonAndSameAs_WhateverTheRoles(FolderOutcome outcome, string primaryFolder, string copyFolder)
    {
        var primary = new FolderReachability(primaryFolder, [$"{primaryFolder}/a.dll"], [], outcome, null, $"exit 9 on {primaryFolder}/a.dll", null, 0, 0);
        var copy = primary with { Folder = copyFolder, Assemblies = [$"{copyFolder}/a.dll"], Reason = $"exit 9 on {copyFolder}/a.dll", SameAs = primaryFolder };

        var summary = Summarize(primary, copy);

        var shown = summary.Folders[1];
        var reason = outcome == FolderOutcome.Crashed
            ? $"the graph worker failed on this folder, so it is unanalysable, and suspect: exit 9 on {copyFolder}/a.dll"
            : $"exit 9 on {copyFolder}/a.dll";
        Assert.Equal((copyFolder, outcome, (string?)reason, (string?)primaryFolder), (shown.Folder, shown.Outcome, shown.Reason, shown.SameAs));
        Assert.Empty(shown.Classes);
        Assert.Empty(shown.Notes);
        Assert.Empty(shown.Statements);
        Assert.False(summary.Complete);
    }

    // A NothingLoaded copy's reason names its own failures; it keeps its SameAs whatever the roles.
    [Theory]
    [InlineData("build/net8.0", "lib/net8.0")]
    [InlineData("lib/net8.0", "tools/net8.0")]
    [InlineData("lib/net8.0", "lib/net9.0")]
    public void Summary_ANothingLoadedCopy_NamesItsOwnFailures_AndKeepsItsSameAs_WhateverTheRoles(string primaryFolder, string copyFolder)
    {
        var primary = new FolderReachability(primaryFolder, [], [new($"{primaryFolder}/a.dll", "not managed")], FolderOutcome.NothingLoaded, null, null, null, 0, 0);
        var copy = primary with { Folder = copyFolder, LoadFailures = [new($"{copyFolder}/a.dll", "not managed")], SameAs = primaryFolder };

        var summary = Summarize(primary, copy);

        var shown = summary.Folders[1];
        Assert.Equal((FolderOutcome.NothingLoaded, (string?)$"1 assembly(ies) did not load: {copyFolder}/a.dll", (string?)primaryFolder), (shown.Outcome, shown.Reason, shown.SameAs));
        Assert.Empty(shown.Notes);
        Assert.Empty(shown.Statements);
        Assert.False(summary.Complete);
    }

    // Analyzed in name only (no report): nothing to list in full, so it keeps its SameAs, every class Unknown, no note.
    [Theory]
    [InlineData("build/net8.0", "lib/net8.0")]
    [InlineData("lib/net8.0", "lib/net9.0")]
    public void Summary_AnAnalyzedCopyWithoutAReport_KeepsItsSameAs_WhateverTheRoles(string primaryFolder, string copyFolder)
    {
        var copy = new FolderReachability(copyFolder, [$"{copyFolder}/a.dll"], [], FolderOutcome.Analyzed, null, null, primaryFolder, 0, 0);

        var summary = Summarize(Analyzed(primaryFolder, CrossRoleReport()), copy);

        var shown = summary.Folders[1];
        Assert.Equal(((string?)"the folder has no reachability report", (string?)primaryFolder), (shown.Reason, shown.SameAs));
        AssertEveryClassUnknownFor(shown, shown.Reason!);
        Assert.Empty(shown.Notes);
        Assert.Empty(shown.Statements);
        Assert.False(summary.Complete);
    }

    // Even with its primary missing from the report, a not-analysed copy is no divergent one: its SameAs is kept, escaped.
    [Fact]
    public void Summary_ACrashedCopy_WhosePrimaryIsNotInTheReport_KeepsItsSameAs()
    {
        var copy = new FolderReachability("lib/net9.0", ["lib/net9.0/a.dll"], [], FolderOutcome.Crashed, null, "exit 9", "build/gone", 0, 0);

        var shown = Assert.Single(Summarize(copy).Folders);

        Assert.Equal((FolderOutcome.Crashed, (string?)"build/gone"), (shown.Outcome, shown.SameAs));
        Assert.Empty(shown.Notes);
    }

    public static TheoryData<FolderOutcome, string, string> NotAnalyzedCopyCases()
    {
        var data = new TheoryData<FolderOutcome, string, string>();
        foreach (var outcome in new[] { FolderOutcome.Crashed, FolderOutcome.TimedOut, FolderOutcome.NotRun })
            foreach (var (primary, copy) in new[] { ("build/net8.0", "lib/net8.0"), ("lib/net8.0", "tools/net8.0"), ("lib/net8.0", "lib/net9.0"), ("build/net8.0", "tools/net8.0") })
                data.Add(outcome, primary, copy);
        return data;
    }
    #endregion

    #region Methods: a folder judged by its members' roles (review W1)
    // NuGet unescapes entry names, so an entry named lib%2Fnet8.0%2FA.dll is extracted at the package root (folder "",
    // role Other) but installed into lib/. Its folder is judged as lib; the role shown is still the folder's own.
    [Theory]
    [InlineData("lib%2Fnet8.0%2FA.dll")]
    [InlineData("runtimes%2Fwin%2Flib%2Fnet8.0%2FA.dll")]
    [InlineData("%6Cib%2Fnet8.0%2FA.dll")]
    [InlineData("LIB%2fnet8.0%2fA.dll")]
    public void Summary_TheRootFolder_WithAnEscapedLibMember_JudgesFinalizerDirectAsATrigger_ButShowsRoleOther(string member)
    {
        var summary = Assert.Single(Summarize(Analyzed("", CrossRoleReport(), assemblies: [member])).Folders);

        Assert.Equal((string.Empty, PackageItemRole.Other), (summary.Folder, summary.Role));
        Assert.Equal([(ReachStatementKind.Trigger, RootClass.NativeEntry), (ReachStatementKind.Trigger, RootClass.Finalizer)], KindsOf(summary));
    }

    [Fact]
    public void Summary_TheRootFolder_WithAPlainMember_KeepsFinalizerDirectInformational()
    {
        var summary = Assert.Single(Summarize(Analyzed("", CrossRoleReport(), assemblies: ["A.dll"])).Folders);

        Assert.Equal(PackageItemRole.Other, summary.Role);
        Assert.Equal([(ReachStatementKind.Trigger, RootClass.NativeEntry), (ReachStatementKind.Informational, RootClass.Finalizer)], KindsOf(summary));
    }

    [Fact]
    public void Summary_AToolsFolder_WithItsOwnMember_KeepsFinalizerDirectInformational()
    {
        var summary = Assert.Single(Summarize(Analyzed("tools/x", CrossRoleReport(), assemblies: ["tools/x/A.dll"])).Folders);

        Assert.Equal(PackageItemRole.Tools, summary.Role);
        Assert.Equal([(ReachStatementKind.Trigger, RootClass.NativeEntry), (ReachStatementKind.Informational, RootClass.Finalizer)], KindsOf(summary));
    }

    // One lib member among others is enough: the folder is judged by the role that triggers most.
    [Fact]
    public void Summary_ATasksFolder_WithOneEscapedLibMember_JudgesFinalizerDirectAsATrigger()
    {
        var summary = Assert.Single(Summarize(Analyzed("tasks/net461", CrossRoleReport(), assemblies: ["tasks/net461/A.dll", "lib%2Fnet8.0%2FB.dll", "tasks/net461/C.dll"])).Folders);

        Assert.Equal(PackageItemRole.Other, summary.Role);
        Assert.Equal([(ReachStatementKind.Trigger, RootClass.NativeEntry), (ReachStatementKind.Trigger, RootClass.Finalizer)], KindsOf(summary));
    }

    // An escaped "lib" deeper in a member's path is not its first segment: tasks/net461/lib%2F... is still tasks.
    [Fact]
    public void Summary_ATasksFolder_WhoseMemberEscapesLibPastItsFirstSegment_KeepsFinalizerDirectInformational()
    {
        var summary = Assert.Single(Summarize(Analyzed("tasks/net461", CrossRoleReport(), assemblies: ["tasks/net461/lib%2Fnet8.0%2FA.dll"])).Folders);

        Assert.Equal([(ReachStatementKind.Trigger, RootClass.NativeEntry), (ReachStatementKind.Informational, RootClass.Finalizer)], KindsOf(summary));
    }

    // The trigger role decides SameAs too: a root folder holding an escaped lib member triggers as its lib primary does, so
    // it stays a reference; with a plain member it does not, and is listed in full.
    [Theory]
    [InlineData("lib%2Fnet8.0%2FA.dll", true)]
    [InlineData("A.dll", false)]
    public void Summary_ACopysTriggerRole_ComesFromItsMembers_Too(string member, bool suppressed)
    {
        var report = CrossRoleReport();

        var summary = Summarize(Analyzed("lib/net8.0", report, assemblies: ["lib/net8.0/A.dll"]), Analyzed("", report, sameAs: "lib/net8.0", assemblies: [member]));

        var copy = summary.Folders[1];
        string[] notes = suppressed ? [] : [ListedInFull("lib/net8.0")];
        Assert.Equal(suppressed ? "lib/net8.0" : null, copy.SameAs);
        Assert.Equal(suppressed ? 0 : 2, copy.Statements.Count);
        Assert.Equal(notes, copy.Notes);
    }
    #endregion

    #region Methods: TriggerRole and SameKinds
    [Theory]
    [MemberData(nameof(Roles))]
    public void Presentation_TriggerRole_WithNoMembers_IsTheFolderRole(PackageItemRole role)
    {
        Assert.Equal(role, ReachabilityPresentation.TriggerRole(role, []));
    }

    // Over all 64 (folder, member) pairs: the member's role only when more cells trigger in it (lib or runtimes over any
    // other), checked against KindOf's own trigger count too.
    [Fact]
    public void Presentation_TriggerRole_OfAFolderAndOneMember_IsTheMembers_OnlyWhenMoreCellsTriggerInIt()
    {
        foreach (var folder in Enum.GetValues<PackageItemRole>())
            foreach (var member in Enum.GetValues<PackageItemRole>())
            {
                var expected = LibOrRuntimes(member) && !LibOrRuntimes(folder) ? member : folder;
                var byCount = TriggerCells(member) > TriggerCells(folder) ? member : folder;

                var actual = ReachabilityPresentation.TriggerRole(folder, [member]);

                Assert.True(expected == actual, $"folder {folder}, member {member}: {actual}");
                Assert.Equal(byCount, actual);
            }
    }

    [Fact]
    public void Presentation_TriggerRole_OnATie_KeepsTheFolderRole_ThenTheFirstBestMember()
    {
        Assert.Equal(PackageItemRole.Lib, ReachabilityPresentation.TriggerRole(PackageItemRole.Lib, [PackageItemRole.Runtimes]));
        Assert.Equal(PackageItemRole.Runtimes, ReachabilityPresentation.TriggerRole(PackageItemRole.Runtimes, [PackageItemRole.Lib]));
        Assert.Equal(PackageItemRole.Tools, ReachabilityPresentation.TriggerRole(PackageItemRole.Tools, [PackageItemRole.Build, PackageItemRole.Other, PackageItemRole.Content]));
        Assert.Equal(PackageItemRole.Runtimes, ReachabilityPresentation.TriggerRole(PackageItemRole.Other, [PackageItemRole.Tools, PackageItemRole.Runtimes, PackageItemRole.Lib]));
        Assert.Equal(PackageItemRole.Lib, ReachabilityPresentation.TriggerRole(PackageItemRole.Other, [PackageItemRole.Build, PackageItemRole.Lib, PackageItemRole.Runtimes]));
        Assert.Equal(PackageItemRole.Lib, ReachabilityPresentation.TriggerRole(PackageItemRole.Lib, [PackageItemRole.Tools, PackageItemRole.Other]));
    }

    [Fact]
    public void Presentation_SameKinds_HoldsWithinLibAndRuntimes_AndWithinTheOtherRoles_Only()
    {
        Assert.True(ReachabilityPresentation.SameKinds(PackageItemRole.Lib, PackageItemRole.Runtimes));
        Assert.True(ReachabilityPresentation.SameKinds(PackageItemRole.Tools, PackageItemRole.Other));
        Assert.True(ReachabilityPresentation.SameKinds(PackageItemRole.Build, PackageItemRole.Analyzers));
        Assert.False(ReachabilityPresentation.SameKinds(PackageItemRole.Lib, PackageItemRole.Tools));
        Assert.False(ReachabilityPresentation.SameKinds(PackageItemRole.Build, PackageItemRole.Runtimes));
        foreach (var a in Enum.GetValues<PackageItemRole>())
            foreach (var b in Enum.GetValues<PackageItemRole>())
                Assert.True((LibOrRuntimes(a) == LibOrRuntimes(b)) == ReachabilityPresentation.SameKinds(a, b), $"{a} {b}");
    }

    // SameKinds is what its name says: two roles give every cell the same kind under KindOf exactly when it holds.
    [Fact]
    public void Presentation_SameKinds_IsKindOfAgreeingOnEveryCell()
    {
        foreach (var a in Enum.GetValues<PackageItemRole>())
            foreach (var b in Enum.GetValues<PackageItemRole>())
            {
                var agree = Cells().All(c => ReachabilityPresentation.KindOf(c.Class, c.Sink, c.Direct, a) == ReachabilityPresentation.KindOf(c.Class, c.Sink, c.Direct, b));
                Assert.True(agree == ReachabilityPresentation.SameKinds(a, b), $"{a} {b}");
            }
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
    [InlineData("content/net8.0", PackageItemRole.Content)]
    [InlineData("contentFiles/any/net8.0", PackageItemRole.Content)]
    [InlineData("tasks/net461", PackageItemRole.Other)]
    [InlineData("tools/net8.0/runtimes/browser/lib/net8.0", PackageItemRole.Tools)]
    [InlineData("", PackageItemRole.Other)]
    [InlineData("%6Cib/net8.0", PackageItemRole.Lib)]     // NuGet unescapes entry names (review W1)
    [InlineData("lib%2Fnet8.0", PackageItemRole.Lib)]
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

    // The whole-pass failure: one NotRun folder named "" (the package), role Other, nothing else, Incomplete; its reason is
    // escaped, then cut. The hostile character sits early, so the cut keeps its escape.
    [Fact]
    public void Failed_IsOneUnnamedNotRunFolder_WithItsReasonEscapedAndCut_AndIsIncomplete()
    {
        var rlo = char.ConvertFromUtf32(0x202E);
        var tail = new string('m', 400);
        var escaped = "evil" + @"\" + "u202e" + "txt" + tail;

        var summary = ReachabilitySummary.Failed("evil" + rlo + "txt" + tail);

        Assert.Equal(ReachabilityScanStatus.Incomplete, summary.Status());
        Assert.False(summary.Complete);
        Assert.Equal(0, summary.StatementsDropped);
        var folder = Assert.Single(summary.Folders);
        Assert.Equal((string.Empty, PackageItemRole.Other, FolderOutcome.NotRun, (string?)null), (folder.Folder, folder.Role, folder.Outcome, folder.SameAs));
        Assert.Empty(folder.Classes);
        Assert.Empty(folder.Notes);
        Assert.Empty(folder.Statements);
        Assert.Equal(Cut(escaped), folder.Reason);
        Assert.StartsWith(escaped[..256] + (char)0x2026 + $"[+{escaped.Length - 256} chars, sha256:", folder.Reason, StringComparison.Ordinal);
        Assert.Matches(@"\[\+\d+ chars, sha256:[0-9a-f]{8}\]$", folder.Reason);
        Assert.DoesNotContain(rlo, folder.Reason!, StringComparison.Ordinal);
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

    // The table, spelled out independently of ReachabilityPresentation: NativeEntry at either label in any role, Finalizer
    // at Direct only in a lib or runtimes folder, each on a signal capability.
    private static ReachStatementKind Expected(RootClass cls, Capability? sink, bool direct, PackageItemRole role) =>
        sink is { } c && signal.Contains(c)
        && (cls == RootClass.NativeEntry || (cls == RootClass.Finalizer && direct && role is PackageItemRole.Lib or PackageItemRole.Runtimes))
            ? ReachStatementKind.Trigger
            : ReachStatementKind.Informational;

    private static string Cut(string name) => Reachability.BoundNameTo(name, 256);

    // A Finalizer/Direct reach (a trigger only in lib and runtimes) and a NativeEntry one (a trigger anywhere); every class
    // decided unless `loadTimeGap`, which leaves LoadTime Unknown for a module initializer (one note).
    private static ReachabilityReport CrossRoleReport(bool loadTimeGap = false) =>
        Report(
            [Row(RootClass.Finalizer, Capability.ProcessExecution, 1, 1, PathOf(true)), Row(RootClass.NativeEntry, Capability.Network, 1, 1, PathOf(true))],
            loadTimeGap
                ? presented.Select(c => c == RootClass.LoadTime ? Status(c, RootClassVerdict.Unknown, 0, "a.dll: " + GraphFacts.ModuleInitializerGap) : Status(c, RootClassVerdict.Reaches))
                : null);

    private static (ReachStatementKind Kind, RootClass Class)[] KindsOf(FolderReachSummary folder) => [.. folder.Statements.Select(s => (s.Kind, s.Class))];

    // The note a divergent SameAs copy carries, spelled out independently of ReachabilitySummary (review C1).
    private static string ListedInFull(string primary) =>
        $"listed in full because its folder role changes which statements are triggers; same files as {primary}";

    // `shown` carries exactly what `folder`, without its SameAs, summarized alone does, but for its notes.
    private static void AssertIsTheFolderAlone(FolderReachSummary shown, FolderReachability folder)
    {
        var alone = Assert.Single(Summarize(folder with { SameAs = null }).Folders);
        Assert.Equal((alone.Folder, alone.Role, alone.Outcome, alone.Reason), (shown.Folder, shown.Role, shown.Outcome, shown.Reason));
        Assert.Equal(JsonSerializer.Serialize(alone.Classes, json), JsonSerializer.Serialize(shown.Classes, json));
        Assert.Equal(JsonSerializer.Serialize(alone.Statements, json), JsonSerializer.Serialize(shown.Statements, json));
        Assert.NotEmpty(shown.Statements);
    }

    private static bool LibOrRuntimes(PackageItemRole role) => role is PackageItemRole.Lib or PackageItemRole.Runtimes;

    // Every (class, sink, label) cell, the classes not presented included.
    private static IEnumerable<(RootClass Class, Capability? Sink, bool Direct)> Cells() =>
        from cls in Enum.GetValues<RootClass>().Where(c => c != RootClass.None)
        from sink in allSinks
        from direct in new[] { true, false }
        select (cls, sink, direct);

    // How many cells KindOf makes triggers in a folder of `role`.
    private static int TriggerCells(PackageItemRole role) =>
        Cells().Count(c => ReachabilityPresentation.KindOf(c.Class, c.Sink, c.Direct, role) == ReachStatementKind.Trigger);

    // The report builders below are internal so the scan-wiring tests (ReachabilityScanWiringTests) build their reports
    // the same way.
    internal static ReachHop Hop(string nodeId, string? assembly = "App") => new(nodeId, assembly, null, 0);

    // A path of `hops` hops, prefix0 .. prefix{hops-1}; the last one is the sink, an external API unless ownSink.
    internal static ReachPath PathOf(bool direct, int hops = 2, string prefix = "App.H", ReachEvidence evidence = ReachEvidence.Bound, OpacityKind? opacity = null, bool ownSink = false) =>
        new(prefix + "0", evidence, direct, [.. Enumerable.Range(0, hops).Select(i => Hop(prefix + i, i < hops - 1 || ownSink ? "App" : null))], hops, false, opacity);

    internal static CapabilityReach Row(RootClass cls, Capability? capability, int roots, int direct, params ReachPath[] examples) =>
        new(cls, capability, roots, roots, roots, direct, examples);

    internal static RootClassStatus Status(RootClass cls, RootClassVerdict verdict, int roots = 1, params string[] reasons) => new(cls, roots, verdict, reasons);

    // A report with these rows; every presented class Reaches unless `classes` says otherwise.
    internal static ReachabilityReport Report(IEnumerable<CapabilityReach> rows, IEnumerable<RootClassStatus>? classes = null, bool partial = false, string? partialReason = null) =>
        new([.. rows], [], false, [.. classes ?? presented.Select(c => Status(c, RootClassVerdict.Reaches))], 0, [], 0, coverage, partial, partialReason);

    // Its one loaded assembly is <folder>/a.dll unless `assemblies` names them.
    internal static FolderReachability Analyzed(string folder, ReachabilityReport report, IReadOnlyList<PackageGraphLoadFailure>? failures = null, string? sameAs = null, IReadOnlyList<string>? assemblies = null) =>
        new(folder, assemblies ?? [$"{folder}/a.dll"], failures ?? [], FolderOutcome.Analyzed, report, null, sameAs, 10, 10);

    internal static FolderReachability NotAnalyzed(string folder, FolderOutcome outcome, string? reason, IReadOnlyList<PackageGraphLoadFailure>? failures = null) =>
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

    public static TheoryData<PackageItemRole> Roles() => [.. Enum.GetValues<PackageItemRole>()];

    // Folders whose role (NuGetPackage.RoleOf, by first segment of the unescaped name, case-insensitive) is Lib or Runtimes.
    public static TheoryData<string, PackageItemRole> FinalizerTriggerFolders() => new()
    {
        { "lib/net8.0", PackageItemRole.Lib },
        { "Lib/net8.0", PackageItemRole.Lib },
        { "%6Cib/net8.0", PackageItemRole.Lib },
        { "lib%2Fnet8.0", PackageItemRole.Lib },
        { "runtimes/win/lib/net8.0", PackageItemRole.Runtimes },
        { "runtimes/win-x64/native", PackageItemRole.Runtimes },
    };

    // A folder of every other role, the S3 packages' build-time folders among them, and lookalikes of lib and runtimes.
    public static TheoryData<string, PackageItemRole> FinalizerInformationalFolders() => new()
    {
        { "tasks/net461", PackageItemRole.Other },
        { "tools/net8.0", PackageItemRole.Tools },
        { "tools", PackageItemRole.Tools },
        { "build/net8.0", PackageItemRole.Build },
        { "buildTransitive/net8.0", PackageItemRole.BuildTransitive },
        { "analyzers/dotnet/cs", PackageItemRole.Analyzers },
        { "content/net8.0", PackageItemRole.Content },
        { "contentFiles/any/net8.0", PackageItemRole.Content },
        { "tools/net8.0/runtimes/browser/lib/net8.0", PackageItemRole.Tools },
        { "libs/net8.0", PackageItemRole.Other },
        { "build/runtimes/win/lib/net8.0", PackageItemRole.Build },
    };

    public static TheoryData<string, PackageItemRole> AllRoleFolderData()
    {
        var data = new TheoryData<string, PackageItemRole>();
        foreach (var (folder, role) in AllRoleFolders())
            data.Add(folder, role);
        return data;
    }

    private static (string Folder, PackageItemRole Role)[] AllRoleFolders() =>
        [.. FinalizerTriggerFolders().Concat(FinalizerInformationalFolders()).Select(row => ((string)row[0], (PackageItemRole)row[1]))];

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

    private const string LoadTimeNote = "load-time code present, not visible to the model (1 assembly(ies) with a module initializer)";

    internal static readonly RootClass[] presented =
        [RootClass.NativeEntry, RootClass.Finalizer, RootClass.TypeInitializer, RootClass.HostContract, RootClass.LoadTime];

    private static readonly Capability[] signal =
        [Capability.ProcessExecution, Capability.Registry, Capability.Network, Capability.NativeInterop, Capability.FileSystem];

    private static readonly Capability?[] allSinks = [.. Enum.GetValues<Capability>().Select(c => (Capability?)c), null];

    private static readonly GraphCoverage coverage =
        new(new IndexCoverage(0, 0, 0), 0, 0, 0, 0, ResolutionCounts.None, 0, 0, 0, 0, 0, 0, 0, false, null);

    private static readonly JsonSerializerOptions json = new() { Converters = { new JsonStringEnumConverter() } };
    #endregion
}
