namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Microsoft.Cci;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture;

/// <summary>
/// Shared xUnit class fixture that hands out <b>real, CCI-produced <see cref="ITypeReference"/>s</b> for every
/// element-type construction — vector array, multi-dimensional array, pointer, managed pointer — and for the two
/// shapes that must not be confused with one (a plain named type and a generic instance).
/// <para>
/// Every reference here comes out of a genuinely loaded assembly
/// (<see cref="ElementTypeConstructions"/> in the metadata-shapes fixture), read through
/// <see cref="AssemblyAnalyzer"/>, never hand-built. That matters: CCI stubbing is a large residual gap in this
/// suite, and a stub proves only that the predicate matches the interfaces the stub chose to implement — not
/// that CCI ever produces those interfaces for the shapes in question.
/// </para>
/// <para>
/// The declaring types are read as <b>field types</b> because that is the one position in CCI's model where a
/// by-ref decodes into an <see cref="IManagedPointerTypeReference"/> rather than into a boolean flag beside the
/// element type — see the remarks on <see cref="ElementTypeConstructions"/>.
/// </para>
/// <para>
/// Run in process deliberately: this is ordinary metadata reading of a Roslyn-emitted assembly, the same thing
/// <see cref="UnresolvedReferenceFixture"/> does. The uncatchable failure modes that need a child process
/// (ADR-0021) are covered elsewhere.
/// </para>
/// </summary>
public sealed class ElementTypeConstructionFixture : IDisposable
{
    #region Constructors
    public ElementTypeConstructionFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        Path = typeof(ThreeApis).Assembly.Location;

        var result = AssemblyAnalyzer.Load(Path);
        Assembly = result.IsSuccess
            ? result.Value
            : throw new InvalidOperationException($"Failed to load '{Path}': {result.Message}", result.Exception);

        shapes = Assembly.Module.GetAllTypes()
            .OfType<INamedTypeDefinition>()
            .SingleOrDefault(type => AssemblyAnalyzer.TypeName(type) == ShapesTypeName)
            ?? throw new InvalidOperationException(
                $"'{ShapesTypeName}' is missing from '{Path}'. It carries every element-type construction this "
                + "fixture hands out; without it the exclusion tests would have nothing real to assert on.");
    }
    #endregion

    #region Properties
    /// <summary>The loaded metadata-shapes fixture assembly.</summary>
    public AssemblyAnalyzer Assembly { get; }

    /// <summary>The file the assembly was loaded from.</summary>
    public string Path { get; }
    #endregion

    #region Methods
    /// <summary>
    /// The declared type of one field of <see cref="ElementTypeConstructions"/>, exactly as CCI decoded it from
    /// the field signature blob. Missing or ambiguous is a hard error: a silently absent field would turn every
    /// assertion built on it into a test of nothing.
    /// </summary>
    public ITypeReference FieldType(string fieldName) =>
        shapes.Fields.SingleOrDefault(field => field.Name.Value == fieldName)?.Type
            ?? throw new InvalidOperationException(
                $"'{ShapesTypeName}' declares no single field named '{fieldName}'.");

    /// <summary>
    /// The containing type of the callee at the single call site of the named <see cref="ThreeApis"/> method —
    /// i.e. a reference obtained the same way <c>CapabilityAnalysis.Match</c> obtains the one it tests, rather
    /// than from a signature position.
    /// </summary>
    public ITypeReference CalleeContainingType(string methodName)
    {
        var method = Assembly.Methods.Single(m => m.Name.Value == methodName);
        var body = AssemblyAnalyzer.TryReadBody(method).Body
            ?? throw new InvalidOperationException($"'{methodName}' has no readable body.");

        return body.Operations
            .Where(op => op.OperationCode is OperationCode.Call or OperationCode.Callvirt or OperationCode.Newobj)
            .Select(op => op.Value)
            .OfType<IMethodReference>()
            .Select(callee => callee.ContainingType)
            .Single();
    }

    public void Dispose() => Assembly.Dispose();
    #endregion

    #region Fields
    /// <summary>The type carrying every construction, by its <see cref="AssemblyAnalyzer.TypeName"/> rendering.</summary>
    public const string ShapesTypeName =
        "Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture.ElementTypeConstructions";

    private readonly INamedTypeDefinition shapes;
    #endregion
}
