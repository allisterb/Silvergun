namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// The <c>scan-package --reachability</c> human section (<c>docs/agent/tasks/reachability-r3.md</c>, "The human section
/// (S2)"), pinned in-process over hand-built <see cref="ReachabilitySummary"/> records, where the console width is ours
/// to set and exact lines can be asserted. Every test runs in both modes: ASCII (the default) and rich (the glyphs and
/// arrow of <c>--rich</c>). The rich console here has no ANSI so a line compares whole; the markup-injection tests also
/// run on an ANSI console. The end-to-end wiring is <see cref="ReachabilityScanPackageCliTests"/>.
/// <para>Non-ASCII glyphs are built from code points (<see cref="char.ConvertFromUtf32"/>), never typed.</para>
/// </summary>
public sealed class ReachabilitySectionRendererTests
{
    #region Methods: the title and the count line
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_Title_SaysInformationalAndNotTheExitCode(bool rich)
    {
        var lines = Write(rich, Summary(Quiet("lib/net8.0")));

        Assert.Contains(lines, l => l.Contains("Reachability (informational; does not affect the exit code)", StringComparison.Ordinal));
    }

    // Two triggers and one informational statement in one folder, a NotRun folder, a quiet one and an Analyzed folder
    // with a Reason (no report): four folders, two not analysed (Reason != null, whatever the outcome).
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_CountLine_CountsTriggersInformationalFoldersAndNotAnalysed(bool rich)
    {
        var summary = Summary(
            Analyzed("lib/net8.0", statements: [Trigger("t1"), Trigger("t2"), Info("i1")]),
            NotAnalysedFolder("lib/net9.0", FolderOutcome.NotRun, "the package budget was spent"),
            Quiet("lib/netstandard2.0"),
            Analyzed("tools/any", reason: "the folder has no reachability report", classes: [Unknown(RootClass.NativeEntry, "the folder has no reachability report")]));

        var lines = Write(rich, summary);

        Assert.Contains("2 trigger(s), 1 informational statement(s) in 4 folder(s); 2 folder(s) not analysed", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_EmptySummary_CountsZeroAndListsNothing(bool rich)
    {
        var lines = Write(rich, new ReachabilitySummary([], 0, true));

        Assert.Contains("0 trigger(s), 0 informational statement(s) in 0 folder(s); 0 folder(s) not analysed", lines);
        Assert.Equal(2, lines.Count);   // the title rule and the count line
    }
    #endregion

    #region Methods: statements
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_FolderHeader_IsTheFolderAndItsRole(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", statements: [Info("x")])));

        Assert.Contains("lib/net8.0 (Lib)", lines);
    }

    // A trigger carries the alert glyph ("[!]" in ASCII); an informational statement the bullet and no alert glyph.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_Trigger_HasTheAlertGlyph_Informational_HasTheBulletOnly(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", statements: [Trigger("native code can reach Network", roots: 3), Info("type initializers can reach Cryptography", roots: 1)])));

        Assert.Contains($"  {Alert(rich)} native code can reach Network (3 root(s))", lines);
        var info = Assert.Single(lines, l => l.Contains("type initializers can reach Cryptography", StringComparison.Ordinal));
        Assert.Equal($"  {Bullet(rich)} type initializers can reach Cryptography (1 root(s))", info);
        Assert.DoesNotContain(Alert(rich), info, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_StatementWithoutExample_HasNoPathLine(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", statements: [Trigger("t")])));

        var at = lines.IndexOf($"  {Alert(rich)} t (1 root(s))");
        Assert.True(at >= 0, string.Join("\n", lines));
        Assert.Equal(at + 1, lines.Count);   // nothing after it: no path line, no dropped line
    }

    // The example sits on the next line, indented under its statement, hops joined by the mode's arrow.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_Example_IsTheNextLine_HopsJoinedByTheModesArrow(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", statements: [Trigger("t", example: Example(["A.Root()", "A.Mid()", "Sink.Call()"]))])));

        var at = lines.IndexOf($"  {Alert(rich)} t (1 root(s))");
        Assert.True(at >= 0, string.Join("\n", lines));
        Assert.Equal($"      A.Root(){Arrow(rich)}A.Mid(){Arrow(rich)}Sink.Call()", lines[at + 1]);
    }

    // HiddenHops > 0: "...N more..." (with U+2026 ellipses when rich) between the first hops and the last two.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_HiddenHops_MarkerSitsBeforeTheLastTwoHops(bool rich)
    {
        var hops = new[] { "H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8" };
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", statements: [Trigger("t", example: Example(hops, hidden: 5))])));

        var a = Arrow(rich);
        Assert.Contains($"      H1{a}H2{a}H3{a}H4{a}H5{a}H6{a}{More(rich, 5)}{a}H7{a}H8", lines);
    }

    // Degenerate input a crafted report could carry: fewer than two hops with hidden ones. The marker still shows.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_HiddenHopsWithOneHop_StillShowsTheMarker(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", statements: [Trigger("t", example: Example(["Only()"], hidden: 3))])));

        Assert.Contains($"      {More(rich, 3)}{Arrow(rich)}Only()", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_NoHiddenHops_HasNoMarker(bool rich)
    {
        var output = string.Join("\n", Write(rich, Summary(Analyzed("lib/net8.0", statements: [Trigger("t", example: Example(["A()", "B()"]))]))));

        Assert.DoesNotContain(" more", output, StringComparison.Ordinal);
    }

    // An unseen reach names what it ended in, after the path.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_UnseenExample_EndsWithTheUnseenSuffix(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", statements: [Info("t", capability: null, example: Example(["A()", "B()"], unseen: "an indirect call (calli)"))])));

        Assert.Contains($"      A(){Arrow(rich)}B() (ends in an indirect call (calli))", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_UnseenExampleWithHiddenHops_HasTheMarkerAndTheSuffix(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", statements: [Trigger("t", example: Example(["A()", "B()", "C()"], hidden: 2, unseen: "an unresolved call"))])));

        var a = Arrow(rich);
        Assert.Contains($"      A(){a}{More(rich, 2)}{a}B(){a}C() (ends in an unresolved call)", lines);
    }

    // Statements, then notes, then Unknown classes, in that order under the folder header.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_Folder_ListsStatementsThenNotesThenUnknownClasses(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0",
            statements: [Info("i")],
            notes: ["load-time code is not visible"],
            classes: [Unknown(RootClass.LoadTime, "r")])));

        var header = lines.IndexOf("lib/net8.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal(
            new[] { $"  {Bullet(rich)} i (1 root(s))", $"  {Bullet(rich)} load-time code is not visible", "  LoadTime: Unknown", "      r" },
            lines.Skip(header + 1).ToArray());
    }
    #endregion

    #region Methods: class verdicts
    // Only Unknown verdicts are listed, each with every reason indented beneath it; None and Reaches are not.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_UnknownVerdicts_AreListedWithTheirReasons_DecidedOnesAreNot(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", classes:
        [
            Decided(RootClass.Finalizer, RootClassVerdict.None),
            Unknown(RootClass.HostContract, "1 root(s) reach code the graph cannot see", "another reason"),
            Decided(RootClass.NativeEntry, RootClassVerdict.Reaches),
        ])));

        var at = lines.IndexOf("  HostContract: Unknown");
        Assert.True(at >= 0, string.Join("\n", lines));
        Assert.Equal("      1 root(s) reach code the graph cannot see", lines[at + 1]);
        Assert.Equal("      another reason", lines[at + 2]);
        Assert.DoesNotContain(lines, l => l.Contains("Finalizer", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.Contains("NativeEntry", StringComparison.Ordinal));
    }

    // A folder whose only news is an Unknown verdict is listed: a quiet folder must not be mistaken for a clean one.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_FolderWithOnlyAnUnknownVerdict_IsListed(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", classes: [Unknown(RootClass.TypeInitializer)])));

        Assert.Contains("lib/net8.0 (Lib)", lines);
        Assert.Contains("  TypeInitializer: Unknown", lines);
    }

    // Only the analysed folders' Unknown verdicts count, the ones the section lists (S2 review N1): "a" adds 1; "b" is
    // Analyzed with a Reason, so not analysed, and its two Unknown classes add 0; "c" has no classes.
    [Fact]
    public void UnknownVerdicts_CountsUnknownClassesOfAnalysedFoldersOnly()
    {
        var summary = Summary(
            Analyzed("a", classes: [Unknown(RootClass.LoadTime), Decided(RootClass.Finalizer, RootClassVerdict.None)]),
            Analyzed("b", reason: "the folder has no reachability report", classes: [Unknown(RootClass.LoadTime), Unknown(RootClass.HostContract)]),
            NotAnalysedFolder("c", FolderOutcome.Crashed, "exit 35"));

        Assert.Equal(1, ReachabilitySectionRenderer.UnknownVerdicts(summary));
        Assert.Equal(2, ReachabilitySectionRenderer.NotAnalysed(summary));
    }

    // Unknown classes in a non-Analyzed folder without a Reason (crafted) are not counted either: it is not analysed.
    [Fact]
    public void UnknownVerdicts_IgnoresCraftedNonAnalyzedFolderWithoutAReason()
    {
        var summary = Summary(
            Crafted("lib/net8.0", FolderOutcome.Crashed, reason: null, classes: [Unknown(RootClass.LoadTime), Unknown(RootClass.HostContract)]),
            Analyzed("lib/net9.0", classes: [Unknown(RootClass.Finalizer)]));

        Assert.Equal(1, ReachabilitySectionRenderer.UnknownVerdicts(summary));
        Assert.Equal(1, ReachabilitySectionRenderer.NotAnalysed(summary));
    }
    #endregion

    #region Methods: IncompleteNote
    [Fact]
    public void IncompleteNote_CompleteAndAllDecided_IsNull()
    {
        var summary = new ReachabilitySummary([Quiet("lib/net8.0"), Analyzed("lib/net9.0", statements: [Trigger("t")])], 0, true);

        Assert.Null(ReachabilitySectionRenderer.IncompleteNote(summary));
    }

    [Fact]
    public void IncompleteNote_EmptyCompleteSummary_IsNull() =>
        Assert.Null(ReachabilitySectionRenderer.IncompleteNote(new ReachabilitySummary([], 0, true)));

    // Two not analysed (a NotRun folder, an Analyzed folder with a Reason whose Unknown classes do not count), and two
    // Unknown verdicts in the analysed folder.
    [Fact]
    public void IncompleteNote_IncompleteSummary_GivesTheCounts()
    {
        var summary = new ReachabilitySummary(
        [
            Analyzed("lib/net8.0", classes: [Unknown(RootClass.LoadTime), Unknown(RootClass.HostContract), Decided(RootClass.Finalizer, RootClassVerdict.None)]),
            NotAnalysedFolder("lib/net9.0", FolderOutcome.NotRun, "the package budget was spent"),
            Analyzed("tools/any", reason: "the folder has no reachability report", classes: [Unknown(RootClass.NativeEntry)]),
        ], 0, false);

        Assert.Equal(Note(2, 2), ReachabilitySectionRenderer.IncompleteNote(summary));
    }

    // A crafted report claims Complete but carries a NotRun folder: the note is decided from the folders too.
    [Fact]
    public void IncompleteNote_ForgedCompleteWithANotRunFolder_StillGivesTheNote()
    {
        var summary = new ReachabilitySummary([Quiet("lib/net8.0"), NotAnalysedFolder("lib/net9.0", FolderOutcome.NotRun, "the package budget was spent")], 0, true);

        Assert.Equal(Note(1, 0), ReachabilitySectionRenderer.IncompleteNote(summary));
    }

    // A crafted report claims Complete but carries a Crashed folder with no Reason (N2): still not analysed.
    [Fact]
    public void IncompleteNote_ForgedCompleteWithACrashedFolderWithoutAReason_StillGivesTheNote()
    {
        var summary = new ReachabilitySummary([Quiet("lib/net8.0"), Crafted("lib/net9.0", FolderOutcome.Crashed, reason: null)], 0, true);

        Assert.Equal(Note(1, 0), ReachabilitySectionRenderer.IncompleteNote(summary));
    }

    // The reverse: the stored Complete is false though every folder is decided. The stored flag is honoured: a note,
    // with both counts 0.
    [Fact]
    public void IncompleteNote_StoredIncompleteWithZeroCounts_StillGivesTheNote()
    {
        var summary = new ReachabilitySummary([Analyzed("lib/net8.0", classes: [Decided(RootClass.NativeEntry, RootClassVerdict.None), Decided(RootClass.LoadTime, RootClassVerdict.None)])], 0, false);

        Assert.Equal(Note(0, 0), ReachabilitySectionRenderer.IncompleteNote(summary));
        Assert.Equal("scan-package: reachability INCOMPLETE (0 folder(s) not analysed, 0 class verdict(s) Unknown); see the report.",
            ReachabilitySectionRenderer.IncompleteNote(summary));
    }

    [Fact]
    public void IncompleteNote_StoredIncompleteEmptySummary_GivesTheNoteWithZeroCounts() =>
        Assert.Equal(Note(0, 0), ReachabilitySectionRenderer.IncompleteNote(new ReachabilitySummary([], 0, false)));
    #endregion

    #region Methods: folders not analysed, SameAs, the package
    // A non-Analyzed folder names its outcome, then the reason.
    [Theory]
    [InlineData(false, FolderOutcome.NothingLoaded)]
    [InlineData(false, FolderOutcome.Crashed)]
    [InlineData(false, FolderOutcome.TimedOut)]
    [InlineData(false, FolderOutcome.NotRun)]
    [InlineData(true, FolderOutcome.NothingLoaded)]
    [InlineData(true, FolderOutcome.Crashed)]
    [InlineData(true, FolderOutcome.TimedOut)]
    [InlineData(true, FolderOutcome.NotRun)]
    public void Write_NotAnalysedFolder_NamesItsOutcomeAndReason(bool rich, FolderOutcome outcome)
    {
        var lines = Write(rich, Summary(NotAnalysedFolder("tools/net8.0/any", outcome, "the folder timeout of 120 s ran out")));

        var header = lines.IndexOf("tools/net8.0/any (Tools)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal($"  {Alert(rich)} not analysed: {outcome}: the folder timeout of 120 s ran out", lines[header + 1]);
    }

    // An Analyzed folder that has a Reason (no report, or its summary failed: S0 review W2) reads not analysed, and the
    // line does not claim "Analyzed". It shows only the reason, not its (all Unknown) classes.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_AnalyzedFolderWithAReason_ReadsNotAnalysed_WithoutTheOutcome(bool rich)
    {
        var reason = "the folder has no reachability report";
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", reason: reason, classes: [Unknown(RootClass.NativeEntry, reason), Unknown(RootClass.LoadTime, reason)])));

        var header = lines.IndexOf("lib/net8.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal($"  {Alert(rich)} not analysed: {reason}", lines[header + 1]);
        Assert.DoesNotContain(lines, l => l.Contains("Analyzed", StringComparison.Ordinal));
        Assert.Equal(header + 2, lines.Count);
        Assert.Contains("0 trigger(s), 0 informational statement(s) in 1 folder(s); 1 folder(s) not analysed", lines);
    }

    // A crafted folder with an outcome other than Analyzed and no Reason (S2 review N2) is not analysed: counted, listed
    // with its outcome and "no reason was given", and its classes neither listed nor counted as Unknown verdicts.
    [Theory]
    [InlineData(false, FolderOutcome.Crashed)]
    [InlineData(false, FolderOutcome.NothingLoaded)]
    [InlineData(false, FolderOutcome.TimedOut)]
    [InlineData(false, FolderOutcome.NotRun)]
    [InlineData(true, FolderOutcome.Crashed)]
    [InlineData(true, FolderOutcome.NotRun)]
    public void Write_CraftedNonAnalyzedFolderWithoutAReason_ReadsNotAnalysed_NoReasonGiven(bool rich, FolderOutcome outcome)
    {
        var summary = new ReachabilitySummary(
            [Crafted("lib/net8.0", outcome, reason: null, classes: [Unknown(RootClass.LoadTime, "crafted reason"), Unknown(RootClass.HostContract)])], 0, true);

        var lines = Write(rich, summary);

        var header = lines.IndexOf("lib/net8.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal($"  {Alert(rich)} not analysed: {outcome}: no reason was given", lines[header + 1]);
        Assert.Equal(header + 2, lines.Count);
        Assert.DoesNotContain(lines, l => l.Contains("Unknown", StringComparison.Ordinal) || l.Contains("crafted reason", StringComparison.Ordinal));
        Assert.Contains("0 trigger(s), 0 informational statement(s) in 1 folder(s); 1 folder(s) not analysed", lines);
        Assert.Equal(1, ReachabilitySectionRenderer.NotAnalysed(summary));
        Assert.Equal(0, ReachabilitySectionRenderer.UnknownVerdicts(summary));
    }

    // The Analyzed-with-a-Reason folder's classes are not counted as Unknown verdicts either (N1): what is listed is counted.
    [Fact]
    public void AnalyzedFolderWithAReason_IsNotAnalysed_AndItsUnknownClassesAreNotCounted()
    {
        var reason = "the folder has no reachability report";
        var summary = Summary(Analyzed("lib/net8.0", reason: reason, classes: [Unknown(RootClass.NativeEntry, reason), Unknown(RootClass.LoadTime, reason)]));

        Assert.Equal(1, ReachabilitySectionRenderer.NotAnalysed(summary));
        Assert.Equal(0, ReachabilitySectionRenderer.UnknownVerdicts(summary));
        Assert.Equal(Note(1, 0), ReachabilitySectionRenderer.IncompleteNote(summary));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_SameAsFolder_SaysSameFilesAsItsPrimary(bool rich)
    {
        var lines = Write(rich, Summary(
            Analyzed("lib/net8.0", statements: [Info("i")]),
            Analyzed("lib/net9.0", sameAs: "lib/net8.0")));

        var header = lines.IndexOf("lib/net9.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal("  same files as lib/net8.0", lines[header + 1]);
        Assert.Equal(header + 2, lines.Count);
    }

    // The whole-pass failure (ReachabilitySummary.Failed) has Folder == "": labelled "(package)" (S1 review N5).
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_WholePassFailure_IsLabelledPackage(bool rich)
    {
        var failed = new FolderReachSummary(string.Empty, PackageItemRole.Other, FolderOutcome.NotRun, "the graph pass failed: IOException: disk full", null, [], [], []);

        var lines = Write(rich, new ReachabilitySummary([failed], 0, false));

        var header = lines.IndexOf("(package) (Other)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal($"  {Alert(rich)} not analysed: NotRun: the graph pass failed: IOException: disk full", lines[header + 1]);
        Assert.Contains("0 trigger(s), 0 informational statement(s) in 1 folder(s); 1 folder(s) not analysed", lines);
    }

    // A quiet, fully decided folder (no statements, notes or Unknown verdict) is counted but not listed.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_QuietDecidedFolder_IsCountedButNotListed(bool rich)
    {
        var lines = Write(rich, Summary(
            Analyzed("lib/net8.0", statements: [Trigger("t")]),
            Quiet("lib/quiet")));

        Assert.Contains("1 trigger(s), 0 informational statement(s) in 2 folder(s); 0 folder(s) not analysed", lines);
        Assert.DoesNotContain(lines, l => l.Contains("lib/quiet", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: the dropped line
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_StatementsDropped_SaysTheyWereNotKeptAndAreNotInJson(bool rich)
    {
        var lines = Write(rich, new ReachabilitySummary([Analyzed("lib/net8.0", statements: [Trigger("t")])], 3, true));

        Assert.Equal(
            $"3 further statement(s) were not kept (the summary's cap of {ReachabilitySummary.MaxStatements}, triggers kept first); they are not in --json either",
            lines[^1]);
        Assert.Contains("(the summary's cap of 2000,", lines[^1], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_NoStatementsDropped_HasNoDroppedLine(bool rich)
    {
        var lines = Write(rich, Summary(Analyzed("lib/net8.0", statements: [Trigger("t")])));

        Assert.DoesNotContain(lines, l => l.Contains("not kept", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: modes and markup injection
    // The default output stays 7-bit ASCII with no leftover markup, over every kind of line the section writes.
    [Fact]
    public void Write_Ascii_IsSevenBitWithoutMarkup()
    {
        var output = string.Join("\n", Write(false, FullSummary()));

        var offender = output.FirstOrDefault(c => c > (char)0x7F || (c < ' ' && c is not '\n'));
        Assert.True(offender == '\0', $"ASCII output carried U+{(int)offender:X4}.");
        Assert.DoesNotContain("[/]", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[grey]", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[yellow]", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[red]", output, StringComparison.Ordinal);
    }

    // Rich output uses the Unicode glyphs and never their ASCII stand-ins.
    [Fact]
    public void Write_Rich_UsesTheUnicodeGlyphs_NotTheAsciiOnes()
    {
        var output = string.Join("\n", Write(true, FullSummary()));

        Assert.Contains(Alert(true), output, StringComparison.Ordinal);
        Assert.Contains(Arrow(true), output, StringComparison.Ordinal);
        Assert.Contains(More(true, 5), output, StringComparison.Ordinal);
        Assert.DoesNotContain("[!]", output, StringComparison.Ordinal);
        Assert.DoesNotContain(" -> ", output, StringComparison.Ordinal);
        Assert.DoesNotContain("...5 more...", output, StringComparison.Ordinal);
    }

    // Markup in every summary string (folder, sameAs, reason, statement text, hop, unseen, note, class reason) renders
    // literally and does not throw, on all three consoles.
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Write_MarkupInEveryString_RendersLiterally_AndDoesNotThrow(bool rich, bool ansi)
    {
        var (console, writer) = MakeConsole(rich, ansi);
        var summary = Summary(
            Analyzed(Inject + "/a", statements: [Trigger(Inject + " text", example: Example([Inject + "hop", "B[x]()"], hidden: 1, unseen: Inject + " unseen"))],
                notes: [Inject + " note"], classes: [Unknown(RootClass.HostContract, Inject + " reason")]),
            Analyzed(Inject + "/b", sameAs: Inject + "/a"),
            NotAnalysedFolder(Inject + "/c", FolderOutcome.Crashed, Inject + " crash"));

        var ex = Record.Exception(() => ReachabilitySectionRenderer.Write(console, rich, summary));

        Assert.Null(ex);
        var output = writer.ToString();
        foreach (var literal in new[] { Inject + "/a", Inject + " text", Inject + "hop", "B[x]()", Inject + " unseen", Inject + " note",
                     Inject + " reason", Inject + "/b", "same files as " + Inject + "/a", Inject + "/c", Inject + " crash" })
            Assert.Contains(literal, output, StringComparison.Ordinal);
    }

    // Lone brackets: an unclosed "[" or a stray "]" would make Spectre's parser throw if any string were not escaped.
    [Theory]
    [InlineData(false, "[")]
    [InlineData(false, "]")]
    [InlineData(false, "[[")]
    [InlineData(true, "[")]
    [InlineData(true, "]")]
    [InlineData(true, "]]")]
    public void Write_LoneBracketsInEveryString_DoNotThrow(bool rich, string bracket)
    {
        var (console, writer) = MakeConsole(rich, ansi: rich);
        var summary = Summary(
            Analyzed("f" + bracket, statements: [Info("t" + bracket, example: Example(["h" + bracket], hidden: 0, unseen: "u" + bracket))],
                notes: ["n" + bracket], classes: [Unknown(RootClass.LoadTime, "r" + bracket)]),
            Analyzed("s" + bracket, sameAs: "f" + bracket),
            NotAnalysedFolder("x" + bracket, FolderOutcome.TimedOut, "why" + bracket));

        var ex = Record.Exception(() => ReachabilitySectionRenderer.Write(console, rich, summary));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("t" + bracket, output, StringComparison.Ordinal);
        Assert.Contains("why" + bracket, output, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: through PackageReportRenderer
    // The section sits right after the Capability manifest and before the Assemblies section.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Render_WithReachability_SectionFollowsTheCapabilityManifest(bool rich)
    {
        var lines = Render(rich, Report() with { Reachability = FullSummary() });

        var manifest = lines.FindIndex(l => l.Contains("Capability manifest", StringComparison.Ordinal));
        var section = lines.FindIndex(l => l.Contains("Reachability (informational; does not affect the exit code)", StringComparison.Ordinal));
        var assemblies = lines.FindIndex(l => l.Contains("Assemblies", StringComparison.Ordinal));
        Assert.True(manifest >= 0 && section > manifest && assemblies > section, $"manifest {manifest}, section {section}, assemblies {assemblies}");
        Assert.Equal(1, lines.Count(l => l.Contains("Reachability (informational", StringComparison.Ordinal)));
    }

    // Without the flag there is no summary and no section at all: its absence is not a claim (D1).
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Render_WithoutReachability_HasNoSection(bool rich)
    {
        var output = string.Join("\n", Render(rich, Report()));

        Assert.DoesNotContain("Reachability", output, StringComparison.Ordinal);
        Assert.DoesNotContain("trigger(s)", output, StringComparison.Ordinal);
    }

    // The section adds lines and changes nothing else: the report without it is the report with it, minus the section
    // (title through its trailing blank line), so the footer and headline are untouched by an incomplete summary.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Render_IncompleteReachability_ChangesNothingButTheSection(bool rich)
    {
        var without = Render(rich, Report());
        var with = Render(rich, Report() with { Reachability = FullSummary() });

        var start = with.FindIndex(l => l.Contains("Reachability (informational", StringComparison.Ordinal));
        var end = with.FindIndex(start, l => l.Contains("Assemblies", StringComparison.Ordinal));
        Assert.True(start >= 0 && end > start, $"section {start}..{end}");
        Assert.Equal(without, with.Take(start).Concat(with.Skip(end)).ToList());
    }

    // The exit code and completeness never read the summary (decision 10: a caveat, not exit 3), whatever its state.
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void ExitCodeAndCompleteness_IgnoreTheSummary(bool strict, bool allowIncomplete)
    {
        var plain = Report();
        foreach (var summary in new[] { FullSummary(), Summary(Quiet("lib/net8.0")), new ReachabilitySummary([], 0, true) })
        {
            var with = plain with { Reachability = summary };

            Assert.Equal(Program.ScanPackageExitCode(plain, strict, allowIncomplete), Program.ScanPackageExitCode(with, strict, allowIncomplete));
            var a = CompletenessAssessment.ForPackage(plain);
            var b = CompletenessAssessment.ForPackage(with);
            Assert.Equal(a.IsComplete, b.IsComplete);
            Assert.Equal(a.Caveats, b.Caveats);
        }
    }
    #endregion

    #region Methods: fixtures
    private static ReachabilitySummary Summary(params FolderReachSummary[] folders) =>
        new(folders, 0, folders.All(f => f.Reason is null && f.Classes.All(c => c.Verdict != RootClassVerdict.Unknown)));

    // Every kind of line: triggers and informational statements with examples (hidden hops, unseen), a note, an Unknown
    // class, SameAs, a not-analysed folder, the package failure label, a quiet folder, and the dropped line.
    private static ReachabilitySummary FullSummary() => new(
    [
        Analyzed("lib/net8.0",
            statements:
            [
                Trigger("native code can reach Network", roots: 3, example: Example(["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"], hidden: 5)),
                Info("type initializers can reach code the graph cannot see", capability: null, example: Example(["A()", "B()"], unseen: "an indirect call (calli)")),
            ],
            notes: ["load-time code is not visible"],
            classes: [Unknown(RootClass.HostContract, "a reason")]),
        Analyzed("lib/net9.0", sameAs: "lib/net8.0"),
        NotAnalysedFolder("tools/net8.0/any", FolderOutcome.TimedOut, "the folder timeout ran out"),
        Quiet("lib/netstandard2.0"),
        new(string.Empty, PackageItemRole.Other, FolderOutcome.NotRun, "the pass failed", null, [], [], []),
    ], 7, false);

    private static FolderReachSummary Analyzed(
        string folder, string? reason = null, string? sameAs = null, IReadOnlyList<ReachClassVerdict>? classes = null,
        IReadOnlyList<string>? notes = null, IReadOnlyList<ReachStatement>? statements = null) =>
        new(folder, RoleOf(folder), FolderOutcome.Analyzed, reason, sameAs, classes ?? [], notes ?? [], statements ?? []);

    private static FolderReachSummary NotAnalysedFolder(string folder, FolderOutcome outcome, string reason) =>
        new(folder, RoleOf(folder), outcome, reason, null, [], [], []);

    // A folder only a crafted report could carry: any outcome, any reason (null included), any classes.
    private static FolderReachSummary Crafted(string folder, FolderOutcome outcome, string? reason, IReadOnlyList<ReachClassVerdict>? classes = null) =>
        new(folder, RoleOf(folder), outcome, reason, null, classes ?? [], [], []);

    // The stderr note's exact text (Program.RunScanPackage writes IncompleteNote's result as is).
    private static string Note(int notAnalysed, int unknown) =>
        $"scan-package: reachability INCOMPLETE ({notAnalysed} folder(s) not analysed, {unknown} class verdict(s) Unknown); see the report.";

    // The role the summary would carry, for the folders these tests name (NuGetPackage.RoleOf is internal to its library).
    private static PackageItemRole RoleOf(string folder) =>
        folder.StartsWith("lib/", StringComparison.Ordinal) ? PackageItemRole.Lib
        : folder.StartsWith("tools/", StringComparison.Ordinal) ? PackageItemRole.Tools
        : PackageItemRole.Other;

    // Analysed, decided, nothing to say.
    private static FolderReachSummary Quiet(string folder) =>
        Analyzed(folder, classes: [Decided(RootClass.NativeEntry, RootClassVerdict.None), Decided(RootClass.TypeInitializer, RootClassVerdict.Reaches)]);

    private static ReachStatement Trigger(string text, int roots = 1, ReachExample? example = null) =>
        new(ReachStatementKind.Trigger, RootClass.NativeEntry, Capability.Network, true, roots, text, example);

    private static ReachStatement Info(string text, int roots = 1, Capability? capability = Capability.Cryptography, ReachExample? example = null) =>
        new(ReachStatementKind.Informational, RootClass.TypeInitializer, capability, true, roots, text, example);

    private static ReachExample Example(IReadOnlyList<string> hops, int hidden = 0, string? unseen = null) =>
        new(ReachEvidence.Bound, hops, hidden, unseen);

    private static ReachClassVerdict Unknown(RootClass @class, params string[] reasons) => new(@class, 1, RootClassVerdict.Unknown, reasons);

    private static ReachClassVerdict Decided(RootClass @class, RootClassVerdict verdict) => new(@class, 1, verdict, []);

    // An otherwise-clean report: vulnerabilities checked, YARA completed, no assemblies.
    private static PackageCapabilityReport Report() =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            VulnerabilitiesStatus: VulnerabilityScanStatus.Completed,
            YaraScanStatus: Silvergun.PackageAnalysis.NuGet.Yara.YaraScanStatus.Completed);
    #endregion

    #region Methods: console helpers
    private static List<string> Write(bool rich, ReachabilitySummary summary)
    {
        var (console, writer) = MakeConsole(rich, ansi: false);
        ReachabilitySectionRenderer.Write(console, rich, summary);
        return Lines(writer);
    }

    private static List<string> Render(bool rich, PackageCapabilityReport report)
    {
        var (console, writer) = MakeConsole(rich, ansi: false);
        PackageReportRenderer.Render(console, report, "Some.Package.nupkg");
        return Lines(writer);
    }

    // The output's lines, trailing spaces trimmed, without the empty string after the final newline.
    private static List<string> Lines(StringWriter writer)
    {
        var lines = writer.ToString().Split('\n').Select(l => l.TrimEnd('\r', ' ')).ToList();
        if (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);
        return lines;
    }

    // rich sets the console's Unicode capability (the renderer's mode in PackageReportRenderer); ansi adds real styles.
    private static (IAnsiConsole Console, StringWriter Writer) MakeConsole(bool rich, bool ansi)
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = ansi ? AnsiSupport.Yes : AnsiSupport.No,
            ColorSystem = ansi ? ColorSystemSupport.Standard : ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = rich;
        console.Profile.Width = 240;
        return (console, writer);
    }

    private static string Alert(bool rich) => rich ? char.ConvertFromUtf32(0x2716) : "[!]";

    private static string Bullet(bool rich) => rich ? char.ConvertFromUtf32(0x00B7) : "-";

    private static string Arrow(bool rich) => rich ? " " + char.ConvertFromUtf32(0x2192) + " " : " -> ";

    private static string More(bool rich, int n) =>
        rich ? $"{char.ConvertFromUtf32(0x2026)}{n} more{char.ConvertFromUtf32(0x2026)}" : $"...{n} more...";
    #endregion

    #region Fields
    private const string Inject = "[red]x[/]";
    #endregion
}
