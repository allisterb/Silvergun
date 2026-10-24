namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// Task round E (queued cosmetic): <c>PackageScanner</c>'s YARA INCOMPLETE / UNAVAILABLE log lines embed the backend's
/// exception message, and every backend message is a whole sentence ending in a period — so the format's own period made
/// it "…must not be reported as clean.. 1 match(es) found…". The line must read as one sentence break, never two
/// periods, on all three catch sites: an incomplete scan that carried hits, one that carried none, and any other
/// exception.
///
/// <para>The backends are fakes overriding <see cref="IYaraScanner.ScanFiles"/> (what <c>PackageScanner</c> calls since
/// ADR 0034) and <see cref="IYaraScanner.ScanDirectory"/> to throw (no engine, no environment
/// variable), injected through <c>PackageScanner.Scan</c>'s seam; the warnings come from
/// <see cref="WarningCapture"/>.</para>
/// </summary>
public sealed class YaraIncompleteScanLogTextTests
{
    #region Methods
    [Theory]
    [InlineData("incomplete-with-hits", "YARA scan INCOMPLETE for")]
    [InlineData("incomplete-without-hits", "YARA scanning UNAVAILABLE for")]
    [InlineData("other-exception", "YARA scanning UNAVAILABLE for")]
    public void Scan_WhenTheYaraScanFails_LogsTheMessageWithoutADoubledPeriod(string failure, string lead)
    {
        using var tree = new TempTree();
        var id = "PkgLogText" + failure.Replace("-", string.Empty, StringComparison.Ordinal);
        var nupkg = YaraCliStderrErrorLineTests.WritePackage(tree, id, [("content/payload.bin", "ordinary content\n")]);
        using var warnings = new WarningCapture();

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: new ThrowingBackend(failure));

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var line = Assert.Single(warnings.Warnings, w => w.StartsWith($"{lead} {id}", StringComparison.Ordinal));
        Assert.Contains(Sentence, line, StringComparison.Ordinal);   // the right line: the backend's message is in it
        Assert.DoesNotContain("..", line, StringComparison.Ordinal);
    }
    #endregion

    #region Nested types
    // A healthy-looking backend whose directory scan fails the way the named case says. The message is a whole sentence
    // ending in '.', like every message the real backends throw.
    private sealed class ThrowingBackend(string failure) : IYaraScanner
    {
        public bool Available => true;

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => [];

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir) => Fail(rootDir);

        // PackageScanner scans the package's extraction inventory through ScanFiles (ADR 0034), so that is the entry the
        // failure has to come out of; ScanDirectory fails the same way for any direct caller.
        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files) => Fail(rootDir);

        private IReadOnlyList<(string FullPath, YaraMatch Match)> Fail(string rootDir) => failure switch
        {
            "incomplete-with-hits" => throw new YaraScanIncompleteException(
                Sentence + ".", null,
                [(Path.Combine(rootDir, "content", "payload.bin"), new YaraMatch("Fake_Rule", null, [], []))]),
            "incomplete-without-hits" => throw new YaraScanIncompleteException(Sentence + "."),
            _ => throw new InvalidOperationException(Sentence + "."),
        };
    }
    #endregion

    #region Fields
    private const string Sentence = "YARA did not scan everything, so this package must not be reported as clean";
    #endregion
}
