#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;
using Xunit.Abstractions;

/// <summary>
/// ADR 0034 decision 2 through <see cref="YaraXWorkerScanner.ScanFiles"/>, the default Windows backend. Every listed file
/// needs a genuine <c>scanned</c> result from the worker; one that is gone at scan time is refused parent-side BEFORE it
/// is sent (its link check cannot read it), rather than with the link reason. Since I5 the message LEADS with the gone
/// files, named once under <c>1 of them no longer exists (removed after it was listed): …</c> (or <c>k of them no longer
/// exist (each removed after it was listed): …</c>), then <c>; the others: …</c> with each other file's own reason, and no
/// parentheses nest. Only FileNotFound/DirectoryNotFound mean gone: a junction keeps the link reason, and attributes that
/// cannot be read for any other reason (access denied) keep the catch-all. Verification (a) of I1.
///
/// <para>Two halves. The in-process half runs the real parent class on a genuine FAKE worker (the FakeYaraProbe's
/// <c>--fake-worker</c> role, through the internal test constructor), whose request log is the evidence of what was and
/// was not SENT. The real-worker half runs the PRODUCTION constructor in a YaraXProbe child (<c>production-files</c>), with
/// the real CLI worker, the real engine and rules, and the <see cref="HermeticWiperSample"/> positive, under a private
/// USERPROFILE so the worker's rules cache is never the user's; one profile per class, warm after the first run.</para>
///
/// <para>Which exception the refusal catches: deleting a file, or an intermediate directory, makes the walk's first missing
/// component's attributes fail with <see cref="FileNotFoundException"/>; a deleted ROOT makes the first component below it
/// fail with <see cref="DirectoryNotFoundException"/> (its parent is gone too). Both are pinned below as platform facts and
/// both reach the same reason.</para>
/// </summary>
public sealed class YaraInventoryYaraXTests(YaraInventoryYaraXTests.Profile profile, ITestOutputHelper output)
    : IClassFixture<YaraInventoryYaraXTests.Profile>
{
    #region Methods: the parent on a genuine fake worker
    [Fact]
    public void ScanFiles_WithAListedFileDeleted_RefusesItAsGone_SendsOnlyTheOthers_AndKeepsTheirHits()
    {
        using var script = new FakeWorkerScript("inv-gone").GenuineThroughout();
        using var tree = new ScanTree("inv-gone");
        var kept = new[] { tree.Write("a.bin"), tree.Write(@"sub\b.bin") };
        var gone = tree.Write("gone.bin");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        File.Delete(gone);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Equal(kept.Order(StringComparer.Ordinal), script.SentPaths.Order(StringComparer.Ordinal));
        Assert.Equal(kept.Order(StringComparer.Ordinal), ex.PartialFindings.Select(h => h.FullPath).Order(StringComparer.Ordinal));
        // I5: the gone file is named under the leading singular clause, once, with no per-file reason after it.
        Assert.Equal(
            $"YARA-X did not scan 1 of 3 file(s) under '{YaraPathSafety.Escape(tree.Root)}': {GoneOne}'gone.bin'. 2 hit(s) found in the files that were scanned are reported; the rest is NOT verified and must not be reported as clean.",
            ex.Message);
        Assert.DoesNotContain("it is a link", ex.Message, StringComparison.Ordinal);
        AssertNoNestedParentheses(ex.Message);
        script.AssertNoOrphans();
    }

    // Every listed file gone: incomplete, never empty — and no worker run at all past the availability probe, because
    // there is nothing left to send.
    [Fact]
    public void ScanFiles_WithEveryListedFileDeleted_IsIncomplete_AndSendsNothing()
    {
        using var script = new FakeWorkerScript("inv-allgone").GenuineThroughout();
        using var tree = new ScanTree("inv-allgone");
        tree.Write("a.bin");
        tree.Write(@"sub\b.bin");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        foreach (var file in listed)
            File.Delete(file);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Empty(ex.PartialFindings);
        // The plural lead, both files named under it in list order, and no "the others" (nothing else was unscanned).
        Assert.Contains(
            $"did not scan 2 of 2 file(s) under '{YaraPathSafety.Escape(tree.Root)}': {GoneMany(2)}{Named(tree.Root, listed)}. 0 hit(s)",
            ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("the others", ex.Message, StringComparison.Ordinal);
        Assert.Empty(script.SentPaths);
        Assert.Single(script.Pids);   // the availability probe only
        script.AssertNoOrphans();
    }

    // The ROOT deleted: the DirectoryNotFound path of the refusal (the first component below the root has no parent).
    [Fact]
    public void ScanFiles_WhenTheRootIsDeleted_RefusesEveryFileAsGone()
    {
        using var script = new FakeWorkerScript("inv-noroot").GenuineThroughout();
        using var tree = new ScanTree("inv-noroot");
        tree.Write("a.bin");
        tree.Write(@"sub\b.bin");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        Directory.Delete(tree.Root, recursive: true);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Contains(
            $"did not scan 2 of 2 file(s) under '{YaraPathSafety.Escape(tree.Root)}': {GoneMany(2)}{Named(tree.Root, listed)}. 0 hit(s)",
            ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("the others", ex.Message, StringComparison.Ordinal);
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }

    // A missing INTERMEDIATE directory: the files under it are refused as gone; the file beside it is sent and scanned.
    [Fact]
    public void ScanFiles_WhenAnIntermediateDirectoryIsDeleted_RefusesTheFilesUnderItAsGone()
    {
        using var script = new FakeWorkerScript("inv-nodir").GenuineThroughout();
        using var tree = new ScanTree("inv-nodir");
        var kept = tree.Write("a.bin");
        tree.Write(@"sub\deeper\c.bin");
        tree.Write(@"sub\d.bin");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        Directory.Delete(Path.Combine(tree.Root, "sub"), recursive: true);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Equal(new[] { kept }, script.SentPaths);
        Assert.Equal(kept, Assert.Single(ex.PartialFindings).FullPath);
        // Both files under the deleted directory lead under the plural clause, in list order.
        var underSub = listed.Where(f => f != kept).ToArray();
        Assert.Equal(2, underSub.Length);
        Assert.Contains(
            $"did not scan 2 of 3 file(s) under '{YaraPathSafety.Escape(tree.Root)}': {GoneMany(2)}{Named(tree.Root, underSub)}. 1 hit(s)",
            ex.Message, StringComparison.Ordinal);
        Assert.Contains(@"'sub\deeper\c.bin'", ex.Message, StringComparison.Ordinal);
        Assert.Contains(@"'sub\d.bin'", ex.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    // Mixed causes: a gone file and a real link (a junction) in the same list each keep their OWN reason. The missing-file
    // mapping must not swallow the link refusal, and the link reason must not be used for the gone file.
    [Fact]
    public void ScanFiles_WithAGoneFileAndAJunction_GivesEachItsOwnReason()
    {
        using var script = new FakeWorkerScript("inv-mixed").GenuineThroughout();
        using var tree = new ScanTree("inv-mixed");
        var kept = tree.Write("a.bin");
        var gone = tree.Write("gone.bin");
        tree.Junction("link");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        Assert.Contains(listed, f => f.EndsWith(@"link\secret.bin", StringComparison.Ordinal));   // precondition: listed through the junction
        File.Delete(gone);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Equal(new[] { kept }, script.SentPaths);
        // The gone file leads under its own clause, named without a reason; the junction follows under "; the others:"
        // carrying its own link reason. Each is named exactly once.
        Assert.Equal(
            $"YARA-X did not scan 2 of 3 file(s) under '{YaraPathSafety.Escape(tree.Root)}': {GoneOne}'gone.bin'; the others: '{@"link\secret.bin"} ({LinkReason}; following a link would scan content outside the package)'. 1 hit(s) found in the files that were scanned are reported; the rest is NOT verified and must not be reported as clean.",
            ex.Message);
        Assert.Equal(1, CountOf(ex.Message, "gone.bin"));
        Assert.Equal(1, CountOf(ex.Message, "no longer exist"));
        AssertNoNestedParentheses(ex.Message);
        script.AssertNoOrphans();
    }

    // I5: with NOTHING gone the message is the one it always was — each unscanned file with its reason in parentheses, no
    // gone clause, no "the others". Pinned byte for byte on the junction-only shape.
    [Fact]
    public void ScanFiles_WithOnlyAJunction_AndNothingGone_TheMessageIsUnchanged()
    {
        using var script = new FakeWorkerScript("inv-nogone").GenuineThroughout();
        using var tree = new ScanTree("inv-nogone");
        var kept = tree.Write("a.bin");
        tree.Junction("link");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Equal(new[] { kept }, script.SentPaths);
        Assert.Equal(
            $"YARA-X did not scan 1 of 2 file(s) under '{YaraPathSafety.Escape(tree.Root)}': '{@"link\secret.bin"} ({LinkReason}; following a link would scan content outside the package)'. 1 hit(s) found in the files that were scanned are reported; the rest is NOT verified and must not be reported as clean.",
            ex.Message);
        Assert.DoesNotContain("no longer exist", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("the others", ex.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    // I5, the plural lead with others: two gone files lead under "each removed after it was listed", the junction follows
    // under "; the others:" with its reason, and no parentheses nest.
    [Fact]
    public void ScanFiles_WithTwoGoneFilesAndAJunction_LeadsWithThePluralClause_ThenTheOthersWithTheirReasons()
    {
        using var script = new FakeWorkerScript("inv-twogone").GenuineThroughout();
        using var tree = new ScanTree("inv-twogone");
        var kept = tree.Write("a.bin");
        var gone = new[] { tree.Write("g1.bin"), tree.Write("g2.bin") };
        tree.Junction("link");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        foreach (var file in gone)
            File.Delete(file);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Equal(new[] { kept }, script.SentPaths);
        var goneInListOrder = listed.Where(f => gone.Contains(f, StringComparer.Ordinal)).ToArray();
        Assert.Equal(
            $"YARA-X did not scan 3 of 4 file(s) under '{YaraPathSafety.Escape(tree.Root)}': {GoneMany(2)}{Named(tree.Root, goneInListOrder)}; the others: '{@"link\secret.bin"} ({LinkReason}; following a link would scan content outside the package)'. 1 hit(s) found in the files that were scanned are reported; the rest is NOT verified and must not be reported as clean.",
            ex.Message);
        AssertNoNestedParentheses(ex.Message);
        script.AssertNoOrphans();
    }

    // N6: a listed file whose attributes CANNOT BE READ (not gone: access denied — the user is denied the file and listing
    // its parent, so neither the file nor the parent's entry for it answers) keeps the catch-all link reason, never the
    // gone one, and is not sent. Staged under a ControlledTempDir; the Deny ACEs are removed before cleanup.
    [Fact]
    public void ScanFiles_WhenAListedFilesAttributesCannotBeRead_RefusesItWithTheCatchAll_NotAsGone()
    {
        using var script = new FakeWorkerScript("inv-denied").GenuineThroughout();
        using var dir = new ControlledTempDir("inv-x-denied");
        var root = dir.CreateDirectory("root");
        var kept = Path.Combine(root, "a.bin");
        File.WriteAllBytes(kept, [1, 2, 3]);
        var locked = Path.Combine(root, "locked");
        Directory.CreateDirectory(locked);
        var denied = Path.Combine(locked, "denied.bin");
        File.WriteAllBytes(denied, [1, 2, 3]);
        var listed = YaraInventoryDefaultLoopTests.Inventory(root);
        var user = Sids.User().Value;
        RawAcl.SetDacl(denied, $"D:P(D;;FA;;;{user})");
        RawAcl.SetDacl(locked, $"D:P(D;;0x1;;;{user})(A;OICI;FA;;;{user})");
        try
        {
            Assert.Throws<UnauthorizedAccessException>(() => File.GetAttributes(@"\\?\" + denied));   // precondition: unreadable, not missing
            using var scanner = script.Scanner();

            var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(root, listed));

            Assert.Equal(new[] { kept }, script.SentPaths);
            Assert.Contains("did not scan 1 of 2 file(s)", ex.Message, StringComparison.Ordinal);
            Assert.Contains(@"'locked\denied.bin (" + LinkReason, ex.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("no longer exist", ex.Message, StringComparison.Ordinal);
            script.AssertNoOrphans();
        }
        finally
        {
            RawAcl.SetDacl(locked, RawAcl.OwnerOnlyDacl());
            RawAcl.SetDacl(denied, RawAcl.OwnerOnlyDacl());
        }
    }

    // The gone file's name is attacker-authored: escaped in the message.
    [Fact]
    public void ScanFiles_AGoneFileWithABidiName_IsNamedEscaped()
    {
        using var script = new FakeWorkerScript("inv-bidi").GenuineThroughout();
        using var tree = new ScanTree("inv-bidi");
        tree.Write("a.bin");
        var gone = tree.Write("exe." + Rlo + "txt.bin");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        File.Delete(gone);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Contains(GoneOne + "'exe." + EscapedRlo + "txt.bin'. ", ex.Message, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
        script.AssertNoOrphans();
    }

    [Fact]
    public void ScanFiles_WithAnEmptyList_ReturnsEmpty_AndSendsNothing()
    {
        using var script = new FakeWorkerScript("inv-empty").GenuineThroughout();
        using var tree = new ScanTree("inv-empty");
        tree.Write("a.bin");
        using var scanner = script.Scanner();

        Assert.Empty(scanner.ScanFiles(tree.Root, []));
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }

    [Fact]
    public void ScanFiles_WithANullList_ThrowsArgumentNullException()
    {
        using var script = new FakeWorkerScript("inv-null").GenuineThroughout();
        using var tree = new ScanTree("inv-null");
        using var scanner = script.Scanner();

        Assert.Throws<ArgumentNullException>(() => scanner.ScanFiles(tree.Root, null!));
        script.AssertNoOrphans();
    }

    // A null ROOT leaves nothing to bound the link walk by, so no listed file can be vouched for: every one is refused as
    // a link it could not check, and nothing is sent. Never "scanned, clean".
    [Fact]
    public void ScanFiles_WithANullRoot_RefusesEveryFile_AndSendsNothing()
    {
        using var script = new FakeWorkerScript("inv-nullroot").GenuineThroughout();
        using var tree = new ScanTree("inv-nullroot");
        tree.Write("a.bin");
        tree.Write(@"sub\b.bin");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(null!, listed));

        Assert.Contains("did not scan 2 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, CountOf(ex.Message, "it is a link, lies under a linked directory, or could not be checked for either"));
        Assert.Empty(ex.PartialFindings);
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }

    // The two platform facts the summary relies on, on the verbatim form the link walk uses.
    [Fact]
    public void Platform_AMissingLeafIsFileNotFound_AndAMissingParentIsDirectoryNotFound()
    {
        using var tree = new ScanTree("inv-facts");

        Assert.Throws<FileNotFoundException>(() => File.GetAttributes(@"\\?\" + Path.Combine(tree.Root, "missing")));
        Assert.Throws<DirectoryNotFoundException>(() => File.GetAttributes(@"\\?\" + Path.Combine(tree.Root, "missing", "deeper")));
    }
    #endregion

    #region Methods: the REAL worker (production constructor, in a YaraXProbe child)
    [Fact]
    [Trait("Category", "Slow")]
    public void RealWorker_ScanFiles_WithAListedFileDeleted_IsIncomplete_NamesItAsGone_AndKeepsTheRealHit()
    {
        using var tree = new ScanTree("inv-real-gone");
        var payload = tree.Write("payload.dll", HermeticWiperSample.Bytes);
        tree.Write(@"sub\notes.txt", Encoding.ASCII.GetBytes("nothing to see here"));
        tree.Write("gone.dll", HermeticWiperSample.Bytes);

        var run = Probe("production-files", tree.Root, "del=gone.dll");

        Assert.Equal("True", run["available"]);
        Assert.Equal("3", run["listed"]);
        Assert.Equal("incomplete", run["result"]);
        Assert.Equal(new[] { $"{payload}|{HermeticWiperSample.RuleName}" }, run.All("partial"));
        Assert.Contains("did not scan 1 of 3 file(s)", run.Message, StringComparison.Ordinal);
        Assert.Contains("': " + GoneOne + "'gone.dll'. 1 hit(s)", run.Message, StringComparison.Ordinal);
        AssertNoNestedParentheses(run.Message);
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void RealWorker_ScanFiles_WithEveryListedFileDeleted_IsIncomplete_NeverEmpty()
    {
        using var tree = new ScanTree("inv-real-allgone");
        tree.Write("payload.dll", HermeticWiperSample.Bytes);
        tree.Write(@"sub\notes.txt", Encoding.ASCII.GetBytes("nothing to see here"));

        var run = Probe("production-files", tree.Root, "del=payload.dll", @"del=sub\notes.txt");

        Assert.Equal("incomplete", run["result"]);
        Assert.Empty(run.All("partial"));
        Assert.Contains("did not scan 2 of 2 file(s)", run.Message, StringComparison.Ordinal);
        Assert.Contains("': " + GoneMany(2), run.Message, StringComparison.Ordinal);
        Assert.Contains("'payload.dll'", run.Message, StringComparison.Ordinal);
        Assert.Contains(@"'sub\notes.txt'", run.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("the others", run.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void RealWorker_ScanFiles_WhenTheRootIsDeleted_IsIncomplete()
    {
        using var tree = new ScanTree("inv-real-noroot");
        tree.Write("payload.dll", HermeticWiperSample.Bytes);

        var run = Probe("production-files", tree.Root, "rmroot");

        Assert.Equal("incomplete", run["result"]);
        Assert.Contains("': " + GoneOne + "'payload.dll'. ", run.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void RealWorker_ScanFiles_WhenAnIntermediateDirectoryIsDeleted_IsIncomplete_AndKeepsTheRealHit()
    {
        using var tree = new ScanTree("inv-real-nodir");
        var payload = tree.Write("payload.dll", HermeticWiperSample.Bytes);
        tree.Write(@"sub\deeper\gone.dll", HermeticWiperSample.Bytes);

        var run = Probe("production-files", tree.Root, "rmdir=sub");

        Assert.Equal("incomplete", run["result"]);
        Assert.Equal(new[] { $"{payload}|{HermeticWiperSample.RuleName}" }, run.All("partial"));
        Assert.Contains("': " + GoneOne + @"'sub\deeper\gone.dll'. ", run.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void RealWorker_ScanFiles_WithAGoneFileAndAJunction_GivesEachItsOwnReason()
    {
        using var tree = new ScanTree("inv-real-mixed");
        var payload = tree.Write("payload.dll", HermeticWiperSample.Bytes);
        tree.Write("gone.dll", HermeticWiperSample.Bytes);
        tree.Junction("link");

        var run = Probe("production-files", tree.Root, "del=gone.dll");

        Assert.Equal("3", run["listed"]);
        Assert.Equal("incomplete", run["result"]);
        Assert.Equal(new[] { $"{payload}|{HermeticWiperSample.RuleName}" }, run.All("partial"));
        Assert.Contains("': " + GoneOne + "'gone.dll'; the others: " + @"'link\secret.bin (" + LinkReason, run.Message, StringComparison.Ordinal);
        AssertNoNestedParentheses(run.Message);
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void RealWorker_ScanFiles_WithAnEmptyList_ReturnsEmpty()
    {
        using var tree = new ScanTree("inv-real-empty");
        tree.Write("payload.dll", HermeticWiperSample.Bytes);

        var run = Probe("production-files", tree.Root, "empty");

        Assert.Equal("complete", run["result"]);
        Assert.Empty(run.All("hit"));
    }

    // No behaviour change for an undisturbed tree: the real worker's ScanFiles over the listed tree reports exactly what
    // its ScanDirectory does, on a tree with hits and on a clean one.
    [Theory]
    [Trait("Category", "Slow")]
    [InlineData(true)]
    [InlineData(false)]
    public void RealWorker_ScanFiles_OverAnUndisturbedTree_ReturnsWhatScanDirectoryReturns(bool withHits)
    {
        using var tree = new ScanTree("inv-real-parity");
        if (withHits)
        {
            tree.Write("payload.dll", HermeticWiperSample.Bytes);
            tree.Write(@"sub\again.dll", HermeticWiperSample.Bytes);
        }
        tree.Write(@"sub\notes.txt", Encoding.ASCII.GetBytes("nothing to see here"));

        var viaFiles = Probe("production-files", tree.Root);
        var viaDirectory = Probe("production-files", tree.Root, "directory");

        Assert.Equal("complete", viaFiles["result"]);
        Assert.Equal("complete", viaDirectory["result"]);
        Assert.Equal(viaDirectory.All("hit").Order(StringComparer.Ordinal), viaFiles.All("hit").Order(StringComparer.Ordinal));
        Assert.Equal(withHits ? 2 : 0, viaFiles.All("hit").Count(h => h.EndsWith("|" + HermeticWiperSample.RuleName, StringComparison.Ordinal)));
    }

    // ADR 0034 end to end with the default Windows backend: PackageScanner.Scan in the probe, the production YaraXWorkerScanner
    // behind the Storage Sense double of YaraInventoryPackageScannerTests (it deletes on the way into ScanFiles AND
    // ScanDirectory, so wired back to ScanDirectory this reads Completed).
    [Fact]
    [Trait("Category", "Slow")]
    public void RealWorker_PackageScan_WhenAnExtractedFileIsDeletedBeforeYara_IsUnavailable_NamesItAsGone_AndKeepsTheRealFinding()
    {
        using var tree = new TempTree();
        var nupkg = YaraInventoryPackageScannerTests.Package(tree, "PkgInvYaraX", HermeticWiperSample.Bytes);

        var run = Probe("production-package", nupkg, YaraInventoryPackageScannerTests.VanishName);

        Assert.Equal("Unavailable", run["status"]);
        Assert.Equal(new[] { $"{HermeticWiperSample.RuleName}|content/payload.bin" }, run.All("finding"));
        var reason = run.Reason!;
        Assert.Contains("did not scan 1 of 4 file(s)", reason, StringComparison.Ordinal);
        var clause = reason.IndexOf("': " + GoneOne + "'", StringComparison.Ordinal);
        Assert.True(clause >= 0, reason);
        Assert.Contains("vanish" + EscapedRlo + ".bin'. ", reason[clause..], StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(reason);
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void RealWorker_PackageScan_WhenEveryExtractedFileIsDeletedBeforeYara_IsUnavailable_NotCompletedAndClean()
    {
        using var tree = new TempTree();
        var nupkg = YaraInventoryPackageScannerTests.Package(tree, "PkgInvYaraXAll", HermeticWiperSample.Bytes);

        var run = Probe("production-package", nupkg, "*");

        Assert.Equal("Unavailable", run["status"]);
        Assert.Empty(run.All("finding"));
        Assert.Contains("did not scan 4 of 4 file(s)", run.Reason, StringComparison.Ordinal);
    }
    #endregion

    #region Helpers
    // The I5 leading clauses (YaraPathSafety.NoLongerExist): the gone files are named once under one of these, ahead of
    // "; the others: …", never with a per-file reason of their own.
    private const string GoneOne = "1 of them no longer exists (removed after it was listed): ";

    private static string GoneMany(int count) => $"{count} of them no longer exist (each removed after it was listed): ";

    // The files as the message names them: root-relative, quoted, comma-separated, in the given order.
    private static string Named(string root, IEnumerable<string> files) =>
        string.Join(", ", files.Select(f => "'" + YaraPathSafety.Escape(YaraPathSafety.Relative(root, f)) + "'"));

    // I5: no parenthesis opens inside another (the old per-file "(it no longer exists (removed …))" did).
    private static void AssertNoNestedParentheses(string message)
    {
        var depth = 0;
        foreach (var c in message)
        {
            depth += c == '(' ? 1 : c == ')' ? -1 : 0;
            Assert.True(depth <= 1, $"nested parentheses in: {message}");
        }
    }

    private const string LinkReason = "it is a link, lies under a linked directory, or could not be checked for either";

    private YaraXProbeRun Probe(params string[] args) => YaraXProbeRunner.Run(profile.Root, output, args);

    private static int CountOf(string text, string part)
    {
        var count = 0;
        for (var at = text.IndexOf(part, StringComparison.Ordinal); at >= 0; at = text.IndexOf(part, at + part.Length, StringComparison.Ordinal))
            count++;
        return count;
    }

    private const char Rlo = (char)0x202E;
    private const string EscapedRlo = @"\" + "u202e";
    #endregion

    #region Nested types
    /// <summary>One private USERPROFILE for the class, so the real worker's rules cache is never the user's (and is warm after the first run).</summary>
    public sealed class Profile : IDisposable
    {
        public Profile() => dir = new YaraXTempDir("inv-profile");

        public string Root => dir.Root;

        public void Dispose() => dir.Dispose();

        private readonly YaraXTempDir dir;
    }
    #endregion
}

/// <summary>
/// Runs the YaraXProbe (the parent backend in a fresh process) under a private USERPROFILE, and parses its
/// <c>key=value</c> report. The real worker it launches inherits that profile, so its rules cache lands in it.
/// </summary>
internal static class YaraXProbeRunner
{
    #region Methods
    internal static YaraXProbeRun Run(string profileRoot, ITestOutputHelper output, params string[] args)
    {
        Assert.True(File.Exists(ProbeExe), $"the YARA-X probe was not found at '{ProbeExe}'.");
        var psi = new ProcessStartInfo(ProbeExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(ProbeExe)!,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment.Remove("SILVERGUN_YARA_ENGINE");
        psi.Environment["USERPROFILE"] = profileRoot;

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(180_000))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail("the YARA-X probe did not exit within 180 s");
        }
        process.WaitForExit();
        var run = new YaraXProbeRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
        output.WriteLine(run.Report);
        Assert.True(run.Exit == 0, $"the YARA-X probe exited {run.Exit}:\n{run.Report}");
        return run;
    }
    #endregion

    #region Fields
    private static readonly string ProbeExe = Path.Combine(AppContext.BaseDirectory, "Silvergun.PackageAnalysis.NuGet.Tests.YaraXProbe.exe");
    #endregion
}

/// <summary>What one YaraXProbe run printed: <c>key=value</c> lines, base64 messages and log records decoded.</summary>
internal sealed record YaraXProbeRun(int Exit, string Stdout, string Stderr)
{
    public string? this[string key] => All(key).FirstOrDefault();

    public string[] All(string key) =>
        Stdout.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.StartsWith(key + "=", StringComparison.Ordinal)).Select(l => l[(key.Length + 1)..]).ToArray();

    public (string Level, string Message)[] Logs =>
        All("log").Select(l => l.Split('|', 2)).Select(p => (p[0], Decode(p[1]))).ToArray();

    public string Message => this["message"] is { } m ? Decode(m) : "";

    public string? Reason => this["reason"] is { } r && r != "<null>" ? Decode(r) : null;

    public string Report => $"exit={Exit}\nstdout:\n{(Stdout.Length > 20000 ? Stdout[..20000] + "..." : Stdout)}\nstderr:\n{Stderr}";

    private static string Decode(string base64) => Encoding.UTF8.GetString(Convert.FromBase64String(base64));
}
#endif
