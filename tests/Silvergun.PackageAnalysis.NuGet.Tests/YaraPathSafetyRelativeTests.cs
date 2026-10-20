namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System.IO;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// <c>YaraPathSafety.Relative</c> — the display-only "path under the root" used by every YARA log line and exception
/// message (<c>IYaraScanner.Relative</c> and <c>YaraCliScanner.Describe</c>). It is a <b>lexical</b> prefix strip at a
/// separator boundary, deliberately not <see cref="Path.GetRelativePath(string, string)"/>: that resolves both
/// operands through the platform normalizer, which renders a device-named entry such as <c>COM1.dll</c> as
/// <c>\\.\COM1</c> on Windows (ADR 0030, sixth instance) — a message naming the wrong thing for exactly the hostile
/// names it exists to report. Reachable here through the assembly's <c>InternalsVisibleTo</c>.
/// </summary>
public sealed class YaraPathSafetyRelativeTests
{
    #region Methods
    // The defect the helper exists to avoid: a device-named entry under the root renders as its own name. On Windows
    // this discriminates — measured 2026-10-19 on .NET 10, Path.GetRelativePath(root, root\COM1.dll) and
    // (root, root\lib\COM1.dll) both return "\\.\COM1" — so a regression back to it fails here. On Linux the device
    // names are ordinary names and the test pins only the lexical strip.
    [Theory]
    [InlineData("COM1.dll")]
    [InlineData("NUL")]
    [InlineData("aux.txt")]
    public void Relative_ForADeviceNamedEntryUnderTheRoot_IsTheEntryNameNotADevicePath(string name)
    {
        var root = Path.Combine(Path.GetTempPath(), "silvergun-relative-root");

        Assert.Equal(name, YaraPathSafety.Relative(root, Path.Combine(root, name)));
        Assert.Equal(Path.Combine("lib", name), YaraPathSafety.Relative(root, Path.Combine(root, "lib", name)));
    }

    // A shared string prefix that does not end at a separator is not containment: /a/bc/x is not under /a/b.
    [Fact]
    public void Relative_ForANonBoundaryPrefix_LeavesThePathUnchanged()
    {
        var root = Path.Combine(Path.GetTempPath(), "a", "b");
        var sibling = Path.Combine(Path.GetTempPath(), "a", "bc", "x");

        Assert.Equal(sibling, YaraPathSafety.Relative(root, sibling));
    }

    // A root spelled with a trailing separator strips the same way, without leaving a leading separator behind.
    [Fact]
    public void Relative_WithATrailingSeparatorOnTheRoot_StripsCleanly()
    {
        var root = Path.Combine(Path.GetTempPath(), "silvergun-relative-root");
        var path = Path.Combine(root, "content", "payload.bin");

        Assert.Equal(Path.Combine("content", "payload.bin"), YaraPathSafety.Relative(root + Path.DirectorySeparatorChar, path));
        Assert.Equal(Path.Combine("content", "payload.bin"), YaraPathSafety.Relative(root, path));
    }

    // No root to strip: the path is returned as it was given.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Relative_WithANullOrEmptyRoot_LeavesThePathUnchanged(string? root)
    {
        var path = Path.Combine(Path.GetTempPath(), "content", "payload.bin");

        Assert.Equal(path, YaraPathSafety.Relative(root, path));
    }

    // Outside the root, and the root itself, are left alone too — there is nothing under the root to name.
    [Fact]
    public void Relative_ForAPathOutsideTheRootOrTheRootItself_LeavesItUnchanged()
    {
        var root = Path.Combine(Path.GetTempPath(), "silvergun-relative-root");
        var elsewhere = Path.Combine(Path.GetTempPath(), "elsewhere", "x.bin");

        Assert.Equal(elsewhere, YaraPathSafety.Relative(root, elsewhere));
        Assert.Equal(root, YaraPathSafety.Relative(root, root));
    }

    // Lexical means lexical: the text is not normalized, escaped or resolved — escaping is the caller's job at the
    // message boundary, so a control character in the name survives the strip and is still there to escape.
    [Fact]
    public void Relative_DoesNotNormalizeOrEscapeTheRemainder()
    {
        var root = Path.Combine(Path.GetTempPath(), "silvergun-relative-root");
        var name = "pay" + (char)0x0A + "load .bin";

        Assert.Equal(name, YaraPathSafety.Relative(root, root + Path.DirectorySeparatorChar + name));
    }
    #endregion
}
