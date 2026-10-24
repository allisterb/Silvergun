#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// ADR 0034, I5 W-a, with the REAL in-process engine: <b>a locked file is not "gone"</b>. libyara.NET throws
/// <see cref="FileNotFoundException"/> for ANY failure to open a file (<c>Scanner.h</c>), so a file another process holds
/// with <see cref="FileShare.None"/> used to be named "no longer exists (removed after it was listed)" — a false cause in
/// the report for a file that is right there. Now only the disk (<see cref="YaraTree.Missing"/>) can say a file is gone:
/// <c>LibYaraScanner</c> wraps libyara's not-found for an existing file in an <see cref="IOException"/>, and the per-file
/// loop names a file gone only when the disk confirms it.
///
/// <para>The lock is a <see cref="FileStream"/> opened with <see cref="FileShare.None"/>: <see cref="File.Exists"/>
/// (GetFileAttributes) is unaffected, so the product's own missing-file guard passes and the failure is libyara's own
/// open (the C1 seam of <c>LibYaraScannerPoisoningTests</c>). Released in a <c>using</c> before the tree is removed.</para>
/// </summary>
public sealed class YaraLockedFileIsNotGoneTests
{
    #region Methods
    // The headline: a share-locked existing file next to a deleted one. Only the deleted one is under the gone clause; the
    // locked one is under "the others".
    [Fact]
    public void LibYara_ScanFiles_WithAShareLockedFileBesideADeletedOne_NamesOnlyTheDeletedOneAsGone()
    {
        IYaraScanner scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; ScanFile would short-circuit before the open.");
        using var tree = new TempTree();
        var locked = Path.GetFullPath(tree.Write("content/locked.dll", "ordinary content\n"));
        var gone = Path.GetFullPath(tree.Write("content/gone.dll", "ordinary content\n"));
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        File.Delete(gone);

        YaraScanIncompleteException ex;
        using (new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.True(File.Exists(locked), "precondition: the locked file still exists for File.Exists");
            ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));
        }

        Assert.Equal(
            $"YARA could not scan 2 of 2 file(s) under '{tree.Root}': 1 of them no longer exists (removed after it was listed): '{Path.Combine("content", "gone.dll")}'; the others: '{Path.Combine("content", "locked.dll")}'. 0 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // The per-file exception for the locked file: an IOException that says what happened, wrapping libyara's not-found —
    // never a bare FileNotFoundException, which the loop (and any reader) would take for "gone". The warning says the same.
    [Fact]
    public void LibYara_ScanFile_OnAShareLockedFile_WrapsLibyarasNotFoundInAnIOException_NeverABareFileNotFound()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; ScanFile would short-circuit before the open.");
        using var tree = new TempTree();
        var locked = Path.GetFullPath(tree.Write("content/locked.dll", "ordinary content\n"));
        using var warnings = new WarningCapture();

        YaraScanIncompleteException ex;
        using (new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None))
            ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(locked));

        var wrapper = Assert.IsType<IOException>(ex.InnerException);   // exactly IOException: not its FileNotFound subtype
        Assert.Equal(LockedWording, wrapper.Message);
        Assert.IsType<FileNotFoundException>(wrapper.InnerException);   // libyara's own exception, kept
        Assert.Equal($"YARA could not scan '{locked}': {LockedWording}. This file was NOT scanned and must not be reported as clean.", ex.Message);
        Assert.DoesNotContain("no longer exist", ex.Message, StringComparison.Ordinal);
        Assert.Contains(warnings.Warnings, w => w == $"YARA scan failed for {locked}: {LockedWording}");
    }

    // Once the lock is released the same file scans normally: the failure was the lock, not the file.
    [Fact]
    public void LibYara_ScanFile_OnceTheLockIsReleased_ScansTheFile()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        using var tree = new TempTree();
        var file = Path.GetFullPath(tree.Write("content/payload.dll", HermeticWiperSample.Bytes));

        using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None))
            Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(file));

        Assert.Contains(scanner.ScanFile(file), m => m.Rule == HermeticWiperSample.RuleName);
    }
    #endregion

    #region Fields
    private const string LockedWording =
        "the file exists but could not be opened (a share lock or an access denial, which libyara.NET reports as not found)";
    #endregion
}
#endif
