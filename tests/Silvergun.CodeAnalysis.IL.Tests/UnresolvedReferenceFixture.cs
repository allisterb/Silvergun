namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Microsoft.Cci;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture;

/// <summary>
/// Shared xUnit class fixture for the reference-side naming invariant
/// (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §0). It sets up the A/B the spike measured, once:
/// the same assembly loaded from its own build output (where its siblings resolve) and from a directory
/// containing nothing but itself (where nothing resolves at all), plus a four-call-site fixture isolated the
/// same way.
/// <para>
/// <b>What "isolated" means and why it is the interesting case.</b> <c>PeReader.DefaultHost</c> probes the
/// directory of the referring unit; it does not probe for the .NET 10 BCL. So a <c>System.*</c> reference
/// never resolves anywhere, and a sibling reference resolves only when the sibling is next to the file.
/// Copying the file alone therefore turns <em>every</em> reference into one whose
/// <c>ContainingType.ResolvedType</c> and <c>ResolvedMethod</c> are CCI's <c>Dummy</c> sentinels, while the
/// <em>references themselves</em> stay intact. Capability detection reads only the reference side, so the two
/// loads must produce byte-identical names — and that only holds because nothing under <c>src/</c> reads
/// <c>ResolvedType</c>/<c>ResolvedMethod</c>. Nothing enforces that; the tests using this fixture do.
/// </para>
/// <para>
/// Run in process deliberately: this is ordinary metadata reading, and the spike measured the same six loads
/// exiting 0 in both Debug and Release. The uncatchable failure modes that need a child process (ADR-0021) are
/// covered elsewhere — see <see cref="CyclicEnumTerminationTests"/>.
/// </para>
/// </summary>
public sealed class UnresolvedReferenceFixture : IDisposable
{
    #region Constructors
    public UnresolvedReferenceFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        directory = Path.Combine(Path.GetTempPath(), $"silvergun-unresolved-{Guid.NewGuid():N}");

        // The subject of the A/B is a real, production assembly with BOTH kinds of reference: BCL references
        // that never resolve, and sibling references (Microsoft.Cci, Silvergun.Runtime, Model) that resolve
        // from its build output and stop resolving once it is alone. Without the second kind the two loads
        // would be identical and the comparison would prove nothing.
        SubjectPath = typeof(AssemblyAnalyzer).Assembly.Location;
        IsolatedSubjectPath = CopyAlone(SubjectPath, "subject");
        ThreeApiPath = CopyAlone(typeof(ThreeApis).Assembly.Location, "three-apis");

        subjectWithDependencies = Open(SubjectPath);
        subjectIsolated = Open(IsolatedSubjectPath);
        threeApis = Open(ThreeApiPath);

        WithDependencies = CallSites(subjectWithDependencies);
        Isolated = CallSites(subjectIsolated);
        ThreeApiCallSites = CallSites(threeApis);

        var analysis = new CapabilityAnalysis(threeApis).Analyze();
        ThreeApiReport = analysis.IsSuccess
            ? analysis.Value
            : throw new InvalidOperationException($"Capability analysis of the isolated fixture failed: {analysis.Message}");
    }
    #endregion

    #region Properties
    /// <summary>The subject assembly in its own build output, where its sibling references resolve.</summary>
    public string SubjectPath { get; }

    /// <summary>The same bytes, alone in an otherwise empty directory, where nothing resolves.</summary>
    public string IsolatedSubjectPath { get; }

    /// <summary>The four-call-site fixture, alone in an otherwise empty directory.</summary>
    public string ThreeApiPath { get; }

    /// <summary>Every call site of the subject, in module order, as loaded with its dependencies present.</summary>
    public IReadOnlyList<CallSite> WithDependencies { get; }

    /// <summary>The same call sites, in the same order, as loaded with nothing resolvable.</summary>
    public IReadOnlyList<CallSite> Isolated { get; }

    /// <summary>The four call sites of the isolated <see cref="ThreeApis"/> fixture.</summary>
    public IReadOnlyList<CallSite> ThreeApiCallSites { get; }

    /// <summary>The capability report produced for the isolated <see cref="ThreeApis"/> fixture.</summary>
    public CapabilityReport ThreeApiReport { get; }
    #endregion

    #region Methods
    /// <summary>Files sitting next to <paramref name="assemblyPath"/> — 1 (itself) for an isolated copy.</summary>
    public static int FilesBesideAssembly(string assemblyPath) =>
        Directory.GetFiles(Path.GetDirectoryName(Path.GetFullPath(assemblyPath))!).Length;

    public void Dispose()
    {
        subjectWithDependencies.Dispose();
        subjectIsolated.Dispose();
        threeApis.Dispose();

        // Best-effort: CCI memory-maps the file and releases it with the host above, but a temp file left
        // behind must never fail a test run.
        try { Directory.Delete(directory, recursive: true); } catch { /* best-effort temp cleanup */ }
    }

    // Every capability-bearing call site, read exactly the way CapabilityAnalysis.Callee reads them
    // (call/callvirt/newobj/ldftn/ldvirtftn with an IMethodReference operand) and in the same module order, so
    // two loads of the same bytes can be compared POSITIONALLY rather than as sets.
    private static IReadOnlyList<CallSite> CallSites(AssemblyAnalyzer assembly)
    {
        var sites = new List<CallSite>();

        foreach (var method in assembly.Methods)
        {
            if (AssemblyAnalyzer.TryReadBody(method).Body is not { } body)
                continue;

            foreach (var operation in body.Operations)
            {
                if (operation.Value is not IMethodReference callee || !IsCallSite(operation.OperationCode))
                    continue;

                var identity = CciNames.Of(callee);
                sites.Add(new CallSite(
                    AssemblyAnalyzer.TypeName(callee.ContainingType),
                    CanonicalName.ClassificationKey(identity),
                    CanonicalName.NodeId(identity),
                    ContainingTypeResolvesToDummy: callee.ContainingType.ResolvedType is Dummy,
                    MethodResolvesToDummy: callee.ResolvedMethod is Dummy,
                    CalleeReferenceIsDummy: callee is Dummy,
                    ContainingTypeReferenceIsDummy: callee.ContainingType is Dummy));
            }
        }

        return sites;
    }

    private static bool IsCallSite(OperationCode code) =>
        code is OperationCode.Call or OperationCode.Callvirt or OperationCode.Newobj
             or OperationCode.Ldftn or OperationCode.Ldvirtftn;

    // Copies one file into a directory of its own, and requires that directory to hold nothing else — the
    // isolation IS the experiment, so a stray sibling would silently weaken every test built on it.
    private string CopyAlone(string sourcePath, string name)
    {
        var target = Path.Combine(directory, name);
        Directory.CreateDirectory(target);

        var copy = Path.Combine(target, Path.GetFileName(sourcePath));
        File.Copy(sourcePath, copy);

        return Directory.GetFiles(target).Length == 1
            ? copy
            : throw new InvalidOperationException($"'{target}' was expected to hold only '{Path.GetFileName(sourcePath)}'.");
    }

    private static AssemblyAnalyzer Open(string path)
    {
        var result = AssemblyAnalyzer.Load(path);
        return result.IsSuccess
            ? result.Value
            : throw new InvalidOperationException($"Failed to load '{path}': {result.Message}", result.Exception);
    }
    #endregion

    #region Fields
    private readonly string directory;
    private readonly AssemblyAnalyzer subjectWithDependencies;
    private readonly AssemblyAnalyzer subjectIsolated;
    private readonly AssemblyAnalyzer threeApis;
    #endregion
}

/// <summary>
/// One capability-bearing call site: the three names the detector actually keys on, plus what CCI's
/// <em>resolution</em> of the same reference produced. The pairing is the whole point — the names must not
/// depend on the resolution flags.
/// </summary>
/// <param name="TypeName"><see cref="AssemblyAnalyzer.TypeName"/> of the callee's containing type — the string
/// the catalog prefix-matches.</param>
/// <param name="ClassificationKey"><see cref="CanonicalName.ClassificationKey(MethodIdentity)"/> — the key
/// <c>capabilities.cm</c> matches.</param>
/// <param name="NodeId"><see cref="CanonicalName.NodeId(MethodIdentity)"/>, including the parameter signature.</param>
/// <param name="ContainingTypeResolvesToDummy">The containing type <em>reference</em> resolved to
/// <c>Dummy.Type</c> — i.e. the definition behind it was not found.</param>
/// <param name="MethodResolvesToDummy">The method reference resolved to <c>Dummy.Method</c>.</param>
/// <param name="CalleeReferenceIsDummy">The reference itself is the <c>Dummy</c> sentinel — the one shape that
/// genuinely degrades, measured at zero occurrences.</param>
/// <param name="ContainingTypeReferenceIsDummy">Likewise for the containing type reference.</param>
public sealed record CallSite(
    string TypeName,
    string ClassificationKey,
    string NodeId,
    bool ContainingTypeResolvesToDummy,
    bool MethodResolvesToDummy,
    bool CalleeReferenceIsDummy,
    bool ContainingTypeReferenceIsDummy);
