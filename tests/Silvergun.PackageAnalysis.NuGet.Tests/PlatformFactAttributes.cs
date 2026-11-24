namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Xunit;

// Facts and theories whose expected behaviour exists on one side of Linux only (docs/agent/tasks/yarax-worker-linux.md):
// the other side is a VISIBLE skip with the reason, never an early-return pass. Unlike LinuxFactAttribute (ADR 0029: names
// NTFS cannot hold), these need nothing but the OS.

/// <summary>Runs on Linux only.</summary>
public sealed class OnLinuxFactAttribute : FactAttribute
{
    #region Constructors
    public OnLinuxFactAttribute() => Skip = PlatformSkip.UnlessLinux;
    #endregion
}

/// <summary>Runs on Linux only.</summary>
public sealed class OnLinuxTheoryAttribute : TheoryAttribute
{
    #region Constructors
    public OnLinuxTheoryAttribute() => Skip = PlatformSkip.UnlessLinux;
    #endregion
}

/// <summary>Runs everywhere but Linux.</summary>
public sealed class NonLinuxFactAttribute : FactAttribute
{
    #region Constructors
    public NonLinuxFactAttribute() => Skip = PlatformSkip.OnLinux;
    #endregion
}

/// <summary>Runs everywhere but Linux.</summary>
public sealed class NonLinuxTheoryAttribute : TheoryAttribute
{
    #region Constructors
    public NonLinuxTheoryAttribute() => Skip = PlatformSkip.OnLinux;
    #endregion
}

internal static class PlatformSkip
{
    #region Properties
    internal static string? UnlessLinux => OperatingSystem.IsLinux() ? null
        : "Linux behaviour (docs/agent/tasks/yarax-worker-linux.md). Run the net10.0 suite under WSL (tests/scripts/wsl-test.ps1) for this to execute.";

    internal static string? OnLinux => OperatingSystem.IsLinux()
        ? "Holds off Linux only; Linux has its own test of this behaviour (docs/agent/tasks/yarax-worker-linux.md)."
        : null;
    #endregion
}
