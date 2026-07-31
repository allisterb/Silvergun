namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;

using Silvergun;
using Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture;

/// <summary>
/// Shared xUnit class fixture for the self-referential-enum regression: builds the cyclic fixture once with
/// <see cref="CyclicEnumPatcher"/> and runs the out-of-process probe over it once, so every fact asserts
/// against the same generated file and the same child-process run.
/// <para>
/// Three cycles are introduced, all in one image: <see cref="SelfReferentialSubject"/> becomes its own
/// underlying type (the one-step cycle), and <see cref="PingSubject"/>/<see cref="PongSubject"/> become each
/// other's (a two-step cycle, which a naive "is it the same type?" guard would not catch).
/// <see cref="SaneControl"/> is left alone as the control.
/// </para>
/// </summary>
public sealed class CyclicEnumFixture : IDisposable
{
    #region Constructors
    public CyclicEnumFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        CleanPath = typeof(SelfReferentialSubject).Assembly.Location;
        directory = Path.Combine(Path.GetTempPath(), $"silvergun-cyclic-enum-{Guid.NewGuid():N}");

        PatchedPath = CyclicEnumPatcher.WriteCopyWithCyclicEnums(
            CleanPath,
            Path.Combine(directory, Path.GetFileName(CleanPath)),
            [
                (nameof(SelfReferentialSubject), nameof(SelfReferentialSubject)),
                (nameof(PingSubject), nameof(PongSubject)),
                (nameof(PongSubject), nameof(PingSubject)),
            ]);

        // One child-process run, shared by every fact. The timeout is itself an assertion: a walk that chased
        // the cycle would either overflow the stack or never come back, and both show up here.
        Probe = ChildProcessProbe.Run(ProbeExe, TimeSpan.FromSeconds(60), PatchedPath);
    }
    #endregion

    #region Properties
    /// <summary>The untouched, Roslyn-built fixture assembly.</summary>
    public string CleanPath { get; }

    /// <summary>The generated copy whose three subject enums have cyclic underlying types.</summary>
    public string PatchedPath { get; }

    /// <summary>The single out-of-process run of the shipping scan path over <see cref="PatchedPath"/>.</summary>
    public ProbeResult Probe { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private readonly string directory;

    private static readonly string ProbeExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.CyclicEnumProbe");
    #endregion
}
