namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Cci = Microsoft.Cci;
using ModelBytecode = Model.Bytecode;

/// <summary>
/// Loads the fixture assembly through <b>both</b> object models once — <see cref="AssemblyAnalyzer"/> (raw
/// CCI) and <see cref="AssemblyDisassembler"/> (CCIProvider/<c>Model</c>) — and renders every method
/// definition and every call-site reference with <see cref="CciNames"/> / <see cref="ModelNames"/>. The two
/// resulting <see cref="LayerNames"/> are what the cross-layer parity test compares.
/// <para>
/// Bodies are read in their <em>bytecode</em> form on both sides (no TAC lifting), so the two walks see the
/// same instruction stream. Nothing here touches the network, the NuGet cache or any assembly other than the
/// fixture, so the comparison is deterministic and offline.
/// </para>
/// </summary>
public sealed class CanonicalNameLayersFixture : IDisposable
{
    #region Constructors
    /// <summary>The default subject: the shared netstandard2.0 fixture assembly.</summary>
    public CanonicalNameLayersFixture()
        : this(typeof(Shapes).Assembly.Location)
    {
    }

    /// <summary>
    /// The same two-layer rendering over an arbitrary assembly, so the parity contract can be asserted against
    /// another flavour of the toolchain (e.g. the net472 matrix fixture, which references <c>mscorlib</c>
    /// rather than <c>System.Runtime</c>) without duplicating the walk.
    /// <para>
    /// Deliberately <b>not</b> public: xUnit rejects a class fixture type that declares more than one public
    /// constructor, so the parameterized form is internal and composed by
    /// <see cref="Net472CanonicalNameLayersFixture"/> rather than used as a class fixture directly.
    /// </para>
    /// </summary>
    internal CanonicalNameLayersFixture(string fixturePath)
    {
        Runtime.Initialize("Silvergun", "TESTS");

        FixturePath = fixturePath;

        var cci = AssemblyAnalyzer.Load(FixturePath);
        if (!cci.IsSuccess)
            throw new InvalidOperationException($"Failed to load AssemblyAnalyzer for '{FixturePath}': {cci.Message}", cci.Exception);

        var model = AssemblyDisassembler.Create(FixturePath);
        if (!model.IsSuccess)
        {
            cci.Value.Dispose();
            throw new InvalidOperationException($"Failed to create AssemblyDisassembler for '{FixturePath}': {model.Message}", model.Exception);
        }

        analyzer = cci.Value;
        disassembler = model.Value;

        // Both handles are live from here on, so a failure while rendering must not leak them: an xUnit class
        // fixture whose constructor throws is never disposed.
        try
        {
            CciLayer = FromCci(analyzer);
            ModelLayer = FromModel(disassembler);
        }
        catch (Exception)
        {
            Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    /// <summary>Absolute path of the fixture assembly both layers read.</summary>
    public string FixturePath { get; }

    /// <summary>
    /// The raw CCI view of the fixture assembly, for the few tests that need an actual
    /// <see cref="Cci.ITypeReference"/> rather than a rendered name — <see cref="CciLayer"/> keeps only names.
    /// Valid for the lifetime of this fixture.
    /// </summary>
    public AssemblyAnalyzer CciAssembly => analyzer;

    /// <summary>Names rendered from raw CCI.</summary>
    public LayerNames CciLayer { get; }

    /// <summary>Names rendered from Analysis.Net's <c>Model</c>.</summary>
    public LayerNames ModelLayer { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        analyzer.Dispose();
        disassembler.Dispose();
    }

    // Every method definition whose body can actually be READ, plus every call/callvirt/newobj/ldftn/ldvirtftn
    // operand in it. AssemblyAnalyzer.Methods yields body-read CANDIDATES (!IsAbstract && !IsExternal, no Body
    // dereference — see docs/agent/tasks/per-method-body-read-granularity.md), so the body must be taken through
    // TryReadBody rather than dereferenced here. The guard comes BEFORE the definition is recorded so a candidate
    // with no readable body contributes neither a definition nor a call site: that is the set the Model side walks
    // (it enumerates bodied methods), and admitting a bodiless method on the CCI side only would break parity
    // silently — Dummy.MethodBody.Operations is empty, so the extra definition would arrive with no call sites and
    // no exception to point at it.
    private static LayerNames FromCci(AssemblyAnalyzer assembly)
    {
        var definitions = new List<MethodIdentity>();
        var callSites = new List<MethodIdentity>();

        foreach (var method in assembly.Methods)
        {
            if (AssemblyAnalyzer.TryReadBody(method) is not { Body: { } body })
                continue;

            definitions.Add(CciNames.Of(method));

            foreach (var operation in body.Operations)
            {
                if (IsCallSite(operation.OperationCode) && operation.Value is Cci.IMethodReference callee)
                    callSites.Add(CciNames.Of(callee));
            }
        }

        return LayerNames.From("CCI", definitions, callSites);
    }

    // The Model counterparts: MethodCallInstruction / CreateObjectInstruction / LoadMethodAddressInstruction.
    private static LayerNames FromModel(AssemblyDisassembler assembly)
    {
        var definitions = new List<MethodIdentity>();
        var callSites = new List<MethodIdentity>();

        foreach (var method in assembly.Methods)
        {
            definitions.Add(ModelNames.Of(method));

            foreach (var instruction in method.Body.Instructions)
            {
                var callee = instruction switch
                {
                    ModelBytecode.MethodCallInstruction call => call.Method,
                    ModelBytecode.CreateObjectInstruction create => create.Constructor,
                    ModelBytecode.LoadMethodAddressInstruction load => load.Method,
                    _ => null,
                };

                if (callee is not null)
                    callSites.Add(ModelNames.Of(callee));
            }
        }

        return LayerNames.From("Model", definitions, callSites);
    }

    private static bool IsCallSite(Cci.OperationCode code) =>
        code is Cci.OperationCode.Call or Cci.OperationCode.Callvirt or Cci.OperationCode.Newobj
             or Cci.OperationCode.Ldftn or Cci.OperationCode.Ldvirtftn;
    #endregion

    #region Fields
    private readonly AssemblyAnalyzer analyzer;
    private readonly AssemblyDisassembler disassembler;
    #endregion
}

/// <summary>
/// The canonical names one object model produced for the fixture assembly: both keys, for both method
/// definitions and call-site references. Sets are ordinal; the call-site <em>lists</em> keep duplicates so a
/// test can assert that two distinct instantiations collapse onto one node id.
/// </summary>
public sealed record LayerNames(
    string Layer,
    IReadOnlyList<MethodIdentity> Definitions,
    IReadOnlyList<MethodIdentity> CallSites,
    IReadOnlyList<string> CallSiteNodeIdList,
    IReadOnlySet<string> DefinitionKeys,
    IReadOnlySet<string> DefinitionNodeIds,
    IReadOnlySet<string> CallSiteKeys,
    IReadOnlySet<string> CallSiteNodeIds)
{
    #region Methods
    public static LayerNames From(string layer, IReadOnlyList<MethodIdentity> definitions, IReadOnlyList<MethodIdentity> callSites) =>
        new(layer,
            definitions,
            callSites,
            [.. callSites.Select(CanonicalName.NodeId)],
            Set(definitions.Select(CanonicalName.ClassificationKey)),
            Set(definitions.Select(CanonicalName.NodeId)),
            Set(callSites.Select(CanonicalName.ClassificationKey)),
            Set(callSites.Select(CanonicalName.NodeId)));

    private static IReadOnlySet<string> Set(IEnumerable<string> names) => new HashSet<string>(names, StringComparer.Ordinal);
    #endregion
}
