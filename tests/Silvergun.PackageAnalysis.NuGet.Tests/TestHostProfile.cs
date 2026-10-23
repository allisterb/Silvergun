#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Keeps the YARA-X workers this test host starts away from the real user's rules cache (T6b of
/// <c>docs/agent/tasks/yarax-worker.md</c>).
///
/// <para><b>Why.</b> Since T6b the net10.0-windows default backend is the out-of-process YARA-X worker, so every
/// <c>PackageScanner.Scan</c> in this host that does not inject a backend reaches <c>YaraScannerFactory.Shared</c>,
/// which resolves the <c>Silvergun.CLI.exe</c> in this test bin (amendment (o)) and runs REAL workers (measured: 11 of
/// them for <c>NuGetPackageTests</c> alone). A worker inherits this process's environment, and its rules cache is
/// <c>%LOCALAPPDATA%\Silvergun\yara-x-rules</c>, which in a new process follows <c>USERPROFILE</c> (measured, and what
/// <c>YaraWorkerVerbWindowsTests</c> relies on). Left alone, the suite reads the developer's real cache and, whenever
/// it has no entry for the current rules (a fresh machine, or any rule edit), WRITES one there.</para>
///
/// <para><b>What.</b> Before any test runs, <c>USERPROFILE</c> for this process (and so for every child that does not
/// set its own) is a private <c>silvergun-yara-x-testhost-profile-*</c> temp directory, removed at exit (the suite's temp
/// leak check counts it if it survives). This host's OWN known folders stay the real ones: <c>UserProfile</c> never
/// follows the variable, while <c>LocalApplicationData</c> and <c>ApplicationData</c> do when first resolved after it is
/// set but are cached per process once resolved (both measured 2026-10-22 under .NET 10), so they are resolved first.
/// Nothing in this host (the NuGet reference resolver, NuGet's own caches and config) therefore sees a different
/// profile; <see cref="TestHostProfileTests"/> pins that. Tests that give a child its own <c>USERPROFILE</c> still do.</para>
/// </summary>
internal static class TestHostProfile
{
    #region Properties
    /// <summary>The private profile every worker this host starts inherits.</summary>
    internal static string Root => profile.Root;
    #endregion

    #region Methods
#pragma warning disable CA2255 // a test assembly's process-wide setup, before xunit runs anything: the intended use
    [ModuleInitializer]
#pragma warning restore CA2255
    internal static void Isolate()
    {
        // Resolved (and so cached for this process) BEFORE the variable changes: see the class remarks.
        foreach (var folder in new[] { Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolder.ApplicationData, Environment.SpecialFolder.UserProfile })
            _ = Environment.GetFolderPath(folder, Environment.SpecialFolderOption.DoNotVerify);
        Environment.SetEnvironmentVariable("USERPROFILE", profile.Root);
        AppDomain.CurrentDomain.ProcessExit += (_, _) => profile.Dispose();
    }
    #endregion

    #region Fields
    private static readonly YaraXTempDir profile = new("testhost-profile");
    #endregion
}
#endif
