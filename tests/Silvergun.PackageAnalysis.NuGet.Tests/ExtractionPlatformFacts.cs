namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Xunit;

/// <summary>
/// Gates a test to <b>Windows</b>, for the ADR 0030 sixth-instance scenarios whose outcome is decided by the
/// operating system rather than by Silvergun: Windows cannot create a file whose name is a reserved DOS device
/// (<c>COM1.dll</c>), cannot hold two names differing only in case, and cannot hold a control character in a
/// filename — so RecursiveExtractor skips or renames the entry (measured 2026-08-22: it does so <b>silently</b>,
/// still returning <c>Ok</c>) and the declared entry ends up in
/// <see cref="NuGetPackage.UninventoriedEntryNames"/>. On Linux the very same package extracts and inventories
/// completely, so the assertion is a different one and lives in the <see cref="LinuxExtractionFactAttribute"/>
/// twin. The divergence is real, is outside our control, and is pinned on both sides deliberately rather than
/// papered over with a lowest-common-denominator assertion.
///
/// <para><b>Skip, not an early return</b> (same reasoning as <c>LinuxYaraFactAttribute</c>): a body that returns
/// early reports <b>Passed</b> on the platform where it never ran, which is exactly the false assurance this ADR
/// is about. With <c>Skip</c> set, "did this actually run?" is answerable from the test output alone.</para>
/// </summary>
public sealed class WindowsExtractionFactAttribute : FactAttribute
{
    #region Constructors
    public WindowsExtractionFactAttribute(string because)
    {
        if (!OperatingSystem.IsWindows())
            Skip = $"Windows-only by construction: {because}. The Linux behaviour of the same package is asserted "
                 + "by the paired [LinuxExtractionFact] — run the suite on both (ADR 0030, sixth instance).";
    }
    #endregion
}

/// <summary>The Linux twin of <see cref="WindowsExtractionFactAttribute"/>; see that type for why both exist.</summary>
public sealed class LinuxExtractionFactAttribute : FactAttribute
{
    #region Constructors
    public LinuxExtractionFactAttribute(string because)
    {
        if (!OperatingSystem.IsLinux())
            Skip = $"Linux-only by construction: {because}. The Windows behaviour of the same package is asserted "
                 + "by the paired [WindowsExtractionFact] — run the suite under WSL "
                 + "(dotnet test <proj> -f net10.0) for this to execute (ADR 0030, sixth instance).";
    }
    #endregion
}
