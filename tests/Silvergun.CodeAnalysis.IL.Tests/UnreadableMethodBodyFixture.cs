namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;
using Silvergun.Tests.Shared;

/// <summary>
/// Shared xUnit class fixture for the per-method body-read granularity tests
/// (<c>docs/agent/tasks/per-method-body-read-granularity.md</c>): the clean fixture assembly and a temp-directory
/// copy of it in which exactly one method body — <see cref="PatchedType"/>.<see cref="PatchedMethod"/> — has been
/// made unreadable by <see cref="FatHeaderPatcher"/>. Both are loaded once, so every test compares the same
/// before/after pair.
/// <para>
/// <b>Why <c>Shapes.Loop</c>:</b> it needs a fat method header (a tiny header has no <c>CodeSize</c> field), and it
/// must contribute <b>no</b> capability and <b>no</b> obfuscation findings — that is what makes "the remaining
/// findings are unchanged" an exact equality against the clean report rather than a filtered comparison. It is a
/// plain arithmetic loop with locals: fat header, no catalog call sites, no string constants.
/// </para>
/// <para>
/// This is run <b>in process</b> deliberately. ADR-0021 requires a child process for failure modes that
/// <c>FailFast</c>, but this one is an ordinary catchable exception on the <c>method.Body</c> dereference (measured
/// in the spec, and re-measured here as a normal <c>Result</c> success), so it is observable with plain assertions.
/// The end-to-end exit-code payoff is covered out of process in <c>Silvergun.CLI.Tests</c>.
/// </para>
/// </summary>
public sealed class UnreadableMethodBodyFixture : IDisposable
{
    public UnreadableMethodBodyFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        CleanPath = typeof(Shapes).Assembly.Location;
        directory = Path.Combine(Path.GetTempPath(), $"silvergun-unreadable-body-{Guid.NewGuid():N}");
        PatchedPath = FatHeaderPatcher.WriteCopyWithUnreadableBody(
            CleanPath,
            Path.Combine(directory, Path.GetFileName(CleanPath)),
            PatchedType,
            PatchedMethod);

        Clean = Open(CleanPath);
        Patched = Open(PatchedPath);
    }

    /// <summary>Simple name of the type declaring the method whose body was corrupted.</summary>
    public const string PatchedType = nameof(Shapes);

    /// <summary>Name of the method whose body was corrupted.</summary>
    public const string PatchedMethod = nameof(Shapes.Loop);

    /// <summary>Namespace-qualified "Type.Method" of the corrupted method, as the skip entries name it.</summary>
    public const string PatchedQualifiedName = "Silvergun.CodeAnalysis.IL.Tests.Fixture.Shapes.Loop";

    /// <summary>The untouched fixture assembly.</summary>
    public AssemblyAnalyzer Clean { get; }

    /// <summary>The copy in which exactly one method body is unreadable.</summary>
    public AssemblyAnalyzer Patched { get; }

    public string CleanPath { get; }

    public string PatchedPath { get; }

    public void Dispose()
    {
        Clean.Dispose();
        Patched.Dispose();

        // Best-effort: CCI memory-maps the file, and the mapping is released with the host above, but a temp file
        // left behind must never fail a test run.
        try { Directory.Delete(directory, recursive: true); } catch { /* best-effort temp cleanup */ }
    }

    private static AssemblyAnalyzer Open(string path)
    {
        var result = AssemblyAnalyzer.Load(path);
        return result.IsSuccess
            ? result.Value
            : throw new InvalidOperationException($"Failed to load '{path}': {result.Message}", result.Exception);
    }

    private readonly string directory;
}
