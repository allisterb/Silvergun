namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0034 decision 4: <see cref="YaraTree.Files"/>, the one enumeration all three <c>ScanDirectory</c> implementations
/// share. <b>Only a root that verifiably does not exist is "nothing to scan"</b> (<c>null</c>); a root that exists but is
/// not a directory, or whose attributes cannot be read, or whose tree will not enumerate, throws
/// <see cref="YaraScanIncompleteException"/>. It replaced <c>Directory.Exists(root) ? enumerate : empty</c>, and
/// <see cref="Directory.Exists"/> answers <c>false</c> for a root that exists but cannot be read — which then read as a
/// completed, empty, clean scan.
///
/// <para>The deny-read root is the discriminating case, and it needs the PARENT to refuse listing too: Windows answers a
/// root's attributes through the parent directory's entry when the root itself is denied (and .NET falls back to
/// <c>FindFirstFile</c>), and on Linux <c>stat</c> needs only search permission on the parent. So with only the root
/// denied, <c>Directory.Exists</c> still says true and the old code failed closed at the enumeration; with the parent
/// denied as well, it says false, and only the new helper fails closed. Both shapes are covered, and each arrange step
/// asserts its own precondition, so neither can pass vacuously (e.g. under an account the ACE or mode does not bind).</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraTreeFilesTests
{
    #region Methods: YaraTree.Files itself
    [Fact]
    public void Files_ForARootThatDoesNotExist_IsNull()
    {
        using var tree = new TempTree();

        Assert.Null(YaraTree.Files(Path.Combine(tree.Root, "missing"), "YARA"));
        Assert.Null(YaraTree.Files(Path.Combine(tree.Root, "missing", "deeper"), "YARA"));   // a missing parent too
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Files_ForANullEmptyOrBlankRoot_IsNull(string? root) =>
        Assert.Null(YaraTree.Files(root, "YARA"));

    // A root that exists as a FILE is not "nothing to scan": something is there, and it was not scanned as the tree it
    // was supposed to be. Directory.Exists answered false here, so the old code returned empty.
    [Fact]
    public void Files_ForARootThatIsAFile_ThrowsIncomplete_NamingTheEngineAndTheRootEscaped()
    {
        using var tree = new TempTree();
        var root = tree.Write("not-a-dir" + Rlo + ".bin", "content");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraTree.Files(root, "YARA-X"));

        Assert.StartsWith("YARA-X could not read '", ex.Message, StringComparison.Ordinal);
        Assert.Contains("as a directory: it exists but is not one", ex.Message, StringComparison.Ordinal);
        Assert.Contains("not-a-dir" + EscapedRlo + ".bin", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
    }

    // The ordinary case: every file, recursively, with the same call NuGetPackage.YaraInventory is taken with.
    [Fact]
    public void Files_ForAnExistingTree_IsEveryFileUnderIt()
    {
        using var tree = new TempTree();
        tree.Write("a.bin", "a");
        tree.Write("content/nested/b.bin", "b");

        var files = YaraTree.Files(tree.Root, "YARA");

        Assert.NotNull(files);
        Assert.Equal(Directory.GetFiles(tree.Root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal), files!.Order(StringComparer.Ordinal));
        Assert.Equal(2, files.Length);
    }

    // An empty directory is a real, readable root with nothing in it: an empty list, not null and not a throw.
    [Fact]
    public void Files_ForAnEmptyDirectory_IsEmpty()
    {
        using var tree = new TempTree();

        Assert.Equal(Array.Empty<string>(), YaraTree.Files(tree.Root, "YARA"));
    }
    #endregion

    #region Methods: YaraTree.Missing (ADR 0034, I4: naming a listed file that is gone)
    [Fact]
    public void Missing_ForAMissingFile_IsTheFileNotFoundException()
    {
        using var tree = new TempTree();

        Assert.IsType<FileNotFoundException>(YaraTree.Missing(Path.Combine(tree.Root, "gone.bin")));
    }

    [Fact]
    public void Missing_ForAFileUnderAMissingDirectory_IsTheDirectoryNotFoundException()
    {
        using var tree = new TempTree();

        Assert.IsType<DirectoryNotFoundException>(YaraTree.Missing(Path.Combine(tree.Root, "vanished", "gone.bin")));
    }

    [Fact]
    public void Missing_ForAnExistingFile_IsNull()
    {
        using var tree = new TempTree();

        Assert.Null(YaraTree.Missing(tree.Write("here.bin", "x")));
    }

    // A directory exists: it is not "gone", whatever else is wrong with scanning it as a file.
    [Fact]
    public void Missing_ForADirectory_IsNull()
    {
        using var tree = new TempTree();

        Assert.Null(YaraTree.Missing(tree.Root));
    }

    // Null and empty are malformed, not missing (ArgumentException / ArgumentNullException are not read as gone), so a
    // caller keeps its own reason for them.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Missing_ForANullOrEmptyPath_IsNull(string? path) =>
        Assert.Null(YaraTree.Missing(path));

    // The Linux twin of the Deny-ACE case: a parent the user may not search makes the file's attributes unreadable, which
    // is not "gone".
    [LinuxFact]
    public void Missing_OnLinux_ForAFileUnderAParentDenyingSearch_IsNull()
    {
        using var tree = new TempTree();
        var file = tree.Write("parent/denied.bin", "content");
        var parent = Path.Combine(tree.Root, "parent");
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxFact] must have gated this test to Linux.");
        File.SetUnixFileMode(parent, UnixFileMode.None);
        try
        {
            Assert.Throws<UnauthorizedAccessException>(() => File.GetAttributes(file));   // precondition (not running as root)

            Assert.Null(YaraTree.Missing(file));
        }
        finally
        {
            File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }
    #endregion

    #region Methods: a root a backend's ScanDirectory is handed but cannot read (Linux: chmod 000)
    [LinuxOnlyTheory]
    [MemberData(nameof(Backends))]
    public void ScanDirectory_OnLinux_WhenTheRootsParentDeniesSearch_FailsClosed(string backend)
    {
        using var tree = new TempTree();
        var parent = Path.Combine(tree.Root, "parent");
        var root = Path.Combine(parent, "root");
        Directory.CreateDirectory(Path.Combine(root, "content"));
        File.WriteAllText(Path.Combine(root, "content", "a.bin"), "content");
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxOnlyTheory] must have gated this test to Linux.");
        File.SetUnixFileMode(parent, UnixFileMode.None);
        try
        {
            Assert.False(Directory.Exists(root), "precondition: with the parent's search denied, Directory.Exists must read the root as absent (is this suite running as root?)");
            Assert.Throws<UnauthorizedAccessException>(() => File.GetAttributes(root));

            var ex = Assert.Throws<YaraScanIncompleteException>(() => Scan(backend, root));

            Assert.Contains("could not read", ex.Message, StringComparison.Ordinal);
            Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
            Assert.IsType<UnauthorizedAccessException>(ex.InnerException);
        }
        finally
        {
            File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [LinuxOnlyTheory]
    [MemberData(nameof(Backends))]
    public void ScanDirectory_OnLinux_WhenTheRootItselfIsMode000_FailsClosed(string backend)
    {
        using var tree = new TempTree();
        var root = Path.Combine(tree.Root, "root");
        Directory.CreateDirectory(Path.Combine(root, "content"));
        File.WriteAllText(Path.Combine(root, "content", "a.bin"), "content");
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxOnlyTheory] must have gated this test to Linux.");
        File.SetUnixFileMode(root, UnixFileMode.None);
        try
        {
            Assert.True(Directory.Exists(root), "precondition: the root itself is still visible through its parent");
            Assert.Throws<UnauthorizedAccessException>(() => Directory.GetFiles(root, "*", SearchOption.AllDirectories));

            var ex = Assert.Throws<YaraScanIncompleteException>(() => Scan(backend, root));

            Assert.Contains("could not enumerate", ex.Message, StringComparison.Ordinal);
            Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }
    #endregion

#if WINDOWS
    #region Methods: a root a backend's ScanDirectory is handed but cannot read (Windows: a Deny ACE)
    // The discriminating Windows shape: the user is denied everything on the root AND listing its parent, so neither the
    // root's own attributes nor its parent's entry for it can be read. Directory.Exists then says false — the old code's
    // "nothing to scan" — and every backend must instead fail closed. Staged under a ControlledTempDir (C:\Temp\sg-c1-*,
    // only the user controls it); every Deny ACE is removed again before cleanup.
    [Theory]
    [MemberData(nameof(Backends))]
    public void ScanDirectory_OnWindows_WhenTheRootAndItsParentDenyTheUser_FailsClosed(string backend)
    {
        using var dir = new ControlledTempDir("inv-deny-both");
        var parent = dir.CreateDirectory("parent");
        var root = Path.Combine(parent, "root");
        Directory.CreateDirectory(Path.Combine(root, "content"));
        File.WriteAllText(Path.Combine(root, "content", "a.bin"), "content");
        var user = Sids.User().Value;
        RawAcl.SetDacl(root, $"D:P(D;;FA;;;{user})(A;OICI;FA;;;{user})");
        RawAcl.SetDacl(parent, $"D:P(D;;0x1;;;{user})(A;OICI;FA;;;{user})");
        try
        {
            Assert.False(Directory.Exists(root), "precondition: Directory.Exists must read the denied root as absent, or this test cannot tell the old code from the new");
            Assert.Throws<UnauthorizedAccessException>(() => File.GetAttributes(root));

            var ex = Assert.Throws<YaraScanIncompleteException>(() => Scan(backend, root));

            Assert.Contains("could not read '", ex.Message, StringComparison.Ordinal);
            Assert.Contains("unknown number of files under it went unscanned", ex.Message, StringComparison.Ordinal);
            Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
            Assert.IsType<UnauthorizedAccessException>(ex.InnerException);
        }
        finally
        {
            RawAcl.SetDacl(parent, RawAcl.OwnerOnlyDacl());
            RawAcl.SetDacl(root, RawAcl.OwnerOnlyDacl());
        }
    }

    // The weaker shape: only the root denies the user. Its attributes still come through the parent, so it reads as a
    // directory and the enumeration is what fails. The old code failed closed here too; the new one must not regress it.
    [Theory]
    [MemberData(nameof(Backends))]
    public void ScanDirectory_OnWindows_WhenOnlyTheRootDeniesTheUser_FailsClosedAtTheEnumeration(string backend)
    {
        using var dir = new ControlledTempDir("inv-deny-root");
        var root = dir.CreateDirectory("root");
        Directory.CreateDirectory(Path.Combine(root, "content"));
        File.WriteAllText(Path.Combine(root, "content", "a.bin"), "content");
        var user = Sids.User().Value;
        RawAcl.SetDacl(root, $"D:P(D;;FA;;;{user})(A;OICI;FA;;;{user})");
        try
        {
            Assert.True(Directory.Exists(root), "precondition: the denied root is still visible through its parent's entry");
            Assert.Throws<UnauthorizedAccessException>(() => Directory.GetFiles(root, "*", SearchOption.AllDirectories));

            var ex = Assert.Throws<YaraScanIncompleteException>(() => Scan(backend, root));

            Assert.Contains("could not enumerate", ex.Message, StringComparison.Ordinal);
            Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            RawAcl.SetDacl(root, RawAcl.OwnerOnlyDacl());
        }
    }

    // The accepted I1 judgement call: a root Windows refuses as a NAME (here '<') used to read as "does not exist" through
    // Directory.Exists; now its attributes fail with an IO error other than not-found, so it fails closed.
    [Fact]
    public void Files_OnWindows_ForARootWithACharacterWindowsRefuses_ThrowsIncomplete()
    {
        using var dir = new ControlledTempDir("inv-odd-root");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraTree.Files(dir.Combine("a<b"), "YARA"));

        Assert.Contains("could not read", ex.Message, StringComparison.Ordinal);
    }

    // YaraTree.Missing for a file the user is denied (the file, and listing its parent, so neither answers its attributes):
    // it exists, so it is NOT missing — access denied keeps its own reason in every caller. Every Deny ACE is removed again.
    [Fact]
    public void Missing_OnWindows_ForAFileTheUserIsDenied_IsNull()
    {
        using var dir = new ControlledTempDir("inv-missing-deny");
        var parent = dir.CreateDirectory("parent");
        var file = Path.Combine(parent, "denied.bin");
        File.WriteAllText(file, "content");
        var user = Sids.User().Value;
        RawAcl.SetDacl(file, $"D:P(D;;FA;;;{user})");
        RawAcl.SetDacl(parent, $"D:P(D;;0x1;;;{user})(A;OICI;FA;;;{user})");
        try
        {
            Assert.Throws<UnauthorizedAccessException>(() => File.GetAttributes(file));   // precondition: unreadable, not missing

            Assert.Null(YaraTree.Missing(file));
        }
        finally
        {
            RawAcl.SetDacl(parent, RawAcl.OwnerOnlyDacl());
            RawAcl.SetDacl(file, RawAcl.OwnerOnlyDacl());
        }
    }
    #endregion
#endif

    #region Helpers
    public static TheoryData<string> Backends() => new(BackendNames);

    // Each backend's ScanDirectory over `root`: the interface's default (LibYaraScanner's path), the classic CLI (the
    // FakeYaraProbe as its yara: it is never reached, the root check comes first), and on Windows the YARA-X parent on a
    // genuine fake worker (the check is parent-side, after the availability probe).
    private static IReadOnlyList<(string FullPath, YaraMatch Match)> Scan(string backend, string root)
    {
        switch (backend)
        {
            case "default loop":
                return ((IYaraScanner)new NeverScanner()).ScanDirectory(root);
            case "yara cli":
            {
                using var fake = new FakeYaraBinary();
                using var scanner = new YaraCliScanner();
                return scanner.ScanDirectory(root);
            }
#if WINDOWS
            case "yara-x worker":
            {
                using var script = new FakeWorkerScript("inv-deny").GenuineThroughout();
                using var scanner = script.Scanner();
                try
                {
                    return scanner.ScanDirectory(root);
                }
                finally
                {
                    Assert.Empty(script.SentPaths);   // nothing under an unreadable root was ever sent
                    script.AssertNoOrphans();
                }
            }
#endif
            default:
                throw new ArgumentOutOfRangeException(nameof(backend), backend, null);
        }
    }

    private static readonly string[] BackendNames =
#if WINDOWS
        ["default loop", "yara cli", "yara-x worker"];
#else
        ["default loop", "yara cli"];
#endif

    private const char Rlo = (char)0x202E;
    private const string EscapedRlo = @"\" + "u202e";
    #endregion

    #region Nested types
    // The default ScanDirectory, over the shared per-file loop (YaraScanLoop.Run, LibYaraScanner's ScanFiles), with a
    // ScanFile that must never be reached (the root check comes first).
    private sealed class NeverScanner : IYaraScanner
    {
        public bool Available => true;

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files) =>
            YaraScanLoop.Run(this, rootDir, files);

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) =>
            throw new InvalidOperationException($"ScanFile was reached for '{fullPath}' under a root that could not be read");
    }
    #endregion
}

/// <summary>
/// The <see cref="TheoryAttribute"/> twin of <see cref="LinuxFactAttribute"/>: a Linux-only scenario (here a directory
/// mode the current user is refused by) run over a set of backends. A VISIBLE skip elsewhere, never an early return.
/// </summary>
public sealed class LinuxOnlyTheoryAttribute : TheoryAttribute
{
    #region Constructors
    public LinuxOnlyTheoryAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = "Needs POSIX permission bits (chmod 000) to stage a root the current user cannot read; the Windows twin uses a Deny ACE. Run the suite under WSL (dotnet test <proj> -f net10.0) for this to execute.";
    }
    #endregion
}
