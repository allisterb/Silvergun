namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Task round E, W1: <b>a file reached THROUGH a linked directory is never re-scanned on its own, nor copied.</b> On Linux
/// <c>Directory.GetFiles</c> follows a directory symlink while <c>yara -r -N</c> does not, so a file under a linked
/// directory is enumerated but gets no coverage-sentinel line, and lands among the files the individual pass re-scans.
/// Before round E only the LEAF was checked for being a link, so that pass handed the file to a single-file yara — which
/// opens the path it is given and follows every link in it, out of the package — or, for an unsafe name, <c>File.Copy</c>'d
/// it to the staging dir first, following the link the same way. Content from outside the package was then scanned and
/// blamed on an in-package path. Now any linked component between the scanned root and the file makes it unrecovered:
/// no launch, no copy, and the scan is incomplete (carrying the hits it has), never complete.
///
/// <para>Linux-gated (<see cref="LinuxFactAttribute"/>): the symlinks need no privilege there, and an unsafe name needs a
/// filesystem that can hold a control character. The engine is the <c>FakeYaraProbe</c>; <c>sentinelSkip</c> withholds
/// the linked file's coverage line exactly as <c>yara -r -N</c> would (the probe's own enumeration follows the link, like
/// <c>Directory.GetFiles</c>), and its invocation log is the evidence that nothing was launched on — or copied from —
/// the linked file.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliLinkedDirectoryTests
{
    #region Methods
    // An ordinary name under a linked directory: refused before any single-file launch. Before round E it was launched,
    // its "hit" recovered, and the scan read Completed with a finding from outside the package.
    [LinuxFact]
    public void ScanDirectory_WhenAnUncoveredFileLiesUnderALinkedDirectory_LeavesItUnrecoveredWithoutALaunch()
    {
        using var outside = new TempTree();
        outside.Write("outside.bin", "content from outside the package\n");
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        Directory.CreateSymbolicLink(Path.Combine(tree.Root, "content", "linked"), outside.Root);
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule",
            sentinelSkip: "outside.bin");
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("linked/outside.bin", ex.Message, StringComparison.Ordinal);
        Assert.Empty(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root));
        Assert.Equal(payload, Assert.Single(ex.PartialFindings).FullPath);
    }

    // The link need not be the file's parent: any directory between the root and the file counts.
    [LinuxFact]
    public void ScanDirectory_WhenTheLinkedDirectoryIsAnAncestorFurtherUp_StillRefusesTheFile()
    {
        using var outside = new TempTree();
        outside.Write("deep/er/outside.bin", "content from outside the package\n");
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        Directory.CreateSymbolicLink(Path.Combine(tree.Root, "content", "linked"), outside.Root);
        using var fake = new FakeYaraBinary(recordInvocations: true, echoRule: "Fake_Rule", sentinelSkip: "outside.bin");
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("linked/deep/er/outside.bin", ex.Message, StringComparison.Ordinal);
        Assert.Empty(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root));
        Assert.Empty(ex.PartialFindings);
    }

    // An UNSAFE name under a linked directory goes through the safe-copy path: it must not be copied (File.Copy follows the
    // link) — so there is no launch on a staged copy either — and it is unrecovered. Before round E only the leaf was
    // checked there too: the copy was made, scanned, and its hit credited to the in-package path.
    [LinuxFact]
    public void ScanDirectory_WhenAnUnsafeNamedFileLiesUnderALinkedDirectory_NeitherCopiesNorLaunchesIt()
    {
        using var outside = new TempTree();
        outside.Write("out\nside.bin", "content from outside the package\n");
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        Directory.CreateSymbolicLink(Path.Combine(tree.Root, "content", "linked"), outside.Root);
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule");
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains(@"linked/out\nside.bin", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(fake.Invocations, i => i.Contains("silvergun-yara-safe-", StringComparison.Ordinal));
        Assert.Empty(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root));
        Assert.Equal(payload, Assert.Single(ex.PartialFindings).FullPath);
    }

    // The leaf check survives the parent walk: a linked FILE several ordinary directories deep, among the uncovered files,
    // is still refused before any launch. (A leaf link at the top of the tree is pinned by YaraCliCoverageSentinelTests
    // and, for an unsafe name, by YaraCliRecoveryBoundsTests.)
    [LinuxFact]
    public void ScanDirectory_WhenAnUncoveredFileIsALinkSeveralDirectoriesDeep_LeavesItUnrecoveredWithoutALaunch()
    {
        using var outside = new TempTree();
        var elsewhere = Path.GetFullPath(outside.Write("outside.bin", "content from outside the package\n"));
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        var link = Path.Combine(tree.Root, "content", "a", "b", "link.bin");
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        File.CreateSymbolicLink(link, elsewhere);
        using var fake = new FakeYaraBinary(recordInvocations: true, echoRule: "Fake_Rule", sentinelSkip: "link.bin");
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("a/b/link.bin", ex.Message, StringComparison.Ordinal);
        Assert.Empty(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root));
    }

    // The control: an uncovered file under ORDINARY nested directories is re-scanned as before (the walk does not refuse
    // everything below the root), and its recovered hit makes the scan complete.
    [LinuxFact]
    public void ScanDirectory_WhenAnUncoveredFileLiesUnderOrdinaryDirectories_ReScansItAndCompletes()
    {
        using var tree = new TempTree();
        var nested = Path.GetFullPath(tree.Write("content/a/b/late.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(recordInvocations: true, echoRule: "Fake_Rule", sentinelSkip: "late.bin");
        using var scanner = new YaraCliScanner();

        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Equal(nested, Assert.Single(hits).FullPath);
        Assert.Equal(nested, YaraCliCoverageSentinelTests.Field(
            Assert.Single(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root)), "target"));
    }
    #endregion
}
