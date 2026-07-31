namespace Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture;

using System.Collections.Generic;
using System.Diagnostics;

/// <summary>
/// The four <b>element-type constructions</b> — vector array, multi-dimensional array, unmanaged pointer and
/// managed (by-ref) pointer — plus the two shapes that must <em>not</em> be treated as one, carried as
/// <b>field types</b> so that a test can hand real CCI <c>ITypeReference</c>s to
/// <c>CapabilityAnalysis.IsElementTypeConstruction</c> without hand-building a stub.
/// <para>
/// <b>Why fields and not parameters or locals.</b> CCI models a by-ref <em>parameter</em>, <em>local</em> and
/// <em>return</em> as a boolean flag beside the ELEMENT type (<c>ParameterWithMetadata.IsByReference</c>,
/// <c>ILocalDefinition.IsReference</c>) rather than as a wrapping type reference, so none of those positions
/// ever yields an <c>IManagedPointerTypeReference</c>. A <b>ref field</b> (C# 11) does: CCI's
/// <c>FieldSignatureConverter</c> (<c>ext/analysis-net/cci/PEReaderAndWriter/PEReader/PEFileToObjectModel.cs</c>)
/// calls <c>GetTypeReference()</c> on the field signature with no by-ref peek, so <c>ELEMENT_TYPE_BYREF</c>
/// decodes through <c>GetModuleManagedPointerType</c> into a real <c>ManagedPointerType</c>. A ref field
/// requires a <c>ref struct</c>, which is why this is one.
/// </para>
/// <para>
/// <b>Element types are catalogued on purpose where the language allows it.</b>
/// <see cref="System.Diagnostics.Process"/> is the <c>ProcessExecution</c> prefix in
/// <c>CapabilityAnalysis.Catalog</c>, and <c>System.Diagnostics.Process[]</c>,
/// <c>System.Diagnostics.Process[,]</c> and <c>System.Diagnostics.Process&amp;</c> all begin with it — that is
/// the false positive the exclusion exists to prevent. The pointer field is <c>int*</c> instead, because C#
/// permits a pointer only to an unmanaged type and every catalogued type is a class; no <c>Process*</c> is
/// expressible in any language CCI reads.
/// </para>
/// <para>
/// Nothing here is executed, no method is declared and no call site is emitted, so this type adds nothing to
/// the call-site, method-count or finding bookkeeping of the assembly (which is copied alone into an empty
/// directory by <c>UnresolvedReferenceFixture</c>, where every call site must fail to resolve).
/// </para>
/// </summary>
public unsafe ref struct ElementTypeConstructions
{
    /// <summary>Rank-1 vector of a catalogued element type: <c>System.Diagnostics.Process[]</c>.</summary>
    public Process[] ProcessVector;

    /// <summary>Rank-2 array of a catalogued element type: <c>System.Diagnostics.Process[,]</c>.</summary>
    public Process[,] ProcessMatrix;

    /// <summary>
    /// An unmanaged pointer: <c>System.Int32*</c>. The element type cannot be a catalogued one — see the type
    /// remarks.
    /// </summary>
    public int* PointerCell;

    /// <summary>
    /// A <b>ref field</b> over a catalogued element type: <c>System.Diagnostics.Process&amp;</c> — the only
    /// position in CCI's model that produces an <c>IManagedPointerTypeReference</c>.
    /// </summary>
    public ref Process ManagedPointerCell;

    /// <summary>
    /// NEGATIVE CONTROL — the plain named type itself, <c>System.Diagnostics.Process</c>, which is exactly what
    /// the catalog is meant to match and must never be excluded.
    /// </summary>
    public Process NamedProcess;

    /// <summary>
    /// NEGATIVE CONTROL — a generic instance, <c>System.Collections.Generic.List&lt;System.Diagnostics.Process&gt;</c>.
    /// Generic instances must keep classifying normally: the container name leads the rendering, so a catalogued
    /// argument can only appear inside the <c>&lt;…&gt;</c> list where a prefix match cannot reach it.
    /// </summary>
    public List<Process> ProcessList;
}
