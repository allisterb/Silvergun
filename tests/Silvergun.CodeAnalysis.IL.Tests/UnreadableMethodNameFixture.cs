namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

/// <summary>
/// Shared xUnit class fixture for the <b>unreadable caller name</b> tests
/// (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §2.2.2 / §2.10 item 4): the clean fixture assembly
/// and a temp-directory copy of it in which exactly one method — <see cref="PatchedType"/>.<see cref="PatchedMethod"/>
/// — has an unreadable <c>MethodDef.Name</c>, built by <see cref="UnreadableMethodNamePatcher"/>. Both are
/// loaded and analyzed once, so every test compares the same before/after pair.
/// <para>
/// <b>Why <c>SensitiveOps.ReadsFiles</c>:</b> the degradation is only interesting on a method that carries
/// findings, and this one carries two (<c>System.IO.Directory.Exists</c> and <c>System.IO.File.ReadAllText</c>)
/// on a plainly-named, non-generic, non-compiler-generated declaring type. That makes "detection is preserved,
/// only the method-name field degrades" an exact statement rather than an approximate one.
/// </para>
/// <para>
/// This runs <b>in process</b> deliberately. ADR-0021 requires a child process for failure modes that
/// <c>FailFast</c>; this one is not such a mode — CCI's string-heap reader returns <c>""</c> for an out-of-range
/// offset rather than throwing or asserting, which was re-measured out of process (exit 0, Debug-built CCI)
/// before this fixture was written, and the analysis it feeds returns an ordinary success
/// <c>Result</c>.
/// </para>
/// </summary>
public sealed class UnreadableMethodNameFixture : IDisposable
{
    #region Constructors
    public UnreadableMethodNameFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        CleanPath = typeof(Shapes).Assembly.Location;
        directory = Path.Combine(Path.GetTempPath(), $"silvergun-unreadable-name-{Guid.NewGuid():N}");
        PatchedPath = UnreadableMethodNamePatcher.WriteCopyWithUnreadableMethodName(
            CleanPath,
            Path.Combine(directory, Path.GetFileName(CleanPath)),
            PatchedType,
            PatchedMethod);

        Clean = Open(CleanPath);
        Patched = Open(PatchedPath);

        CleanReport = Analyze(Clean);
        PatchedReport = Analyze(Patched);
    }
    #endregion

    #region Properties
    /// <summary>Simple name of the type declaring the method whose name was made unreadable.</summary>
    public const string PatchedType = nameof(SensitiveOps);

    /// <summary>Name of the method whose <c>MethodDef.Name</c> was made unreadable.</summary>
    public const string PatchedMethod = nameof(SensitiveOps.ReadsFiles);

    /// <summary>The declaring type as <c>ApiCallFinding.CallerType</c> renders it — the attribution that survives.</summary>
    public const string PatchedTypeFullName = "Silvergun.CodeAnalysis.IL.Tests.Fixture.SensitiveOps";

    /// <summary>The untouched fixture assembly.</summary>
    public AssemblyAnalyzer Clean { get; }

    /// <summary>The copy in which exactly one method name is unreadable.</summary>
    public AssemblyAnalyzer Patched { get; }

    /// <summary>Capability report over <see cref="Clean"/>.</summary>
    public CapabilityReport CleanReport { get; }

    /// <summary>Capability report over <see cref="Patched"/>.</summary>
    public CapabilityReport PatchedReport { get; }

    public string CleanPath { get; }

    public string PatchedPath { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Clean.Dispose();
        Patched.Dispose();

        // Best-effort: CCI memory-maps the file and releases it with the host above, but a temp file left
        // behind must never fail a test run.
        try { Directory.Delete(directory, recursive: true); } catch { /* best-effort temp cleanup */ }
    }

    private static AssemblyAnalyzer Open(string path)
    {
        var result = AssemblyAnalyzer.Load(path);
        return result.IsSuccess
            ? result.Value
            : throw new InvalidOperationException($"Failed to load '{path}': {result.Message}", result.Exception);
    }

    private static CapabilityReport Analyze(AssemblyAnalyzer assembly)
    {
        var result = new CapabilityAnalysis(assembly).Analyze();
        return result.IsSuccess
            ? result.Value
            : throw new InvalidOperationException($"Capability analysis of '{assembly.AssemblyPath}' failed: {result.Message}");
    }
    #endregion

    #region Fields
    private readonly string directory;
    #endregion
}
