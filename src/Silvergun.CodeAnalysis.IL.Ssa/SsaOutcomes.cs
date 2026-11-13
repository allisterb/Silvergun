namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

using Silvergun.CodeAnalysis.IL;

/// <summary>Why a method did not lift to verified SSA. Any of them makes the method Unknown.</summary>
public enum SsaFailureKind
{
    /// <summary>Its body, or a member it needs, could not be read.</summary>
    Unreadable,
    /// <summary>CCI failed an assertion while reading what the method needs (the read may be degraded).</summary>
    ReaderAssertion,
    /// <summary>The adapter cannot express the input in Cilica's model (malformed or unsupported metadata).</summary>
    Adapter,
    /// <summary>A fact about a type outside the folder that no reference proves (ruling D3).</summary>
    UnresolvedFact,
    /// <summary>A per-method bound (<see cref="SsaBounds"/>) was exceeded.</summary>
    Bounds,
    /// <summary>Cilica's importer rejected the body.</summary>
    Import,
    /// <summary>The imported IR failed <c>IRVerifier</c>.</summary>
    Verify,
    /// <summary><c>SsaPromotion</c> failed.</summary>
    Ssa,
    /// <summary>The promoted IR failed <c>IRVerifier</c>.</summary>
    VerifyAfterSsa,
}

/// <summary>The facts about a type outside the folder that only its definition could prove.</summary>
public enum UnresolvedFact
{
    /// <summary>The referenced type is not in the assembly the reference names.</summary>
    Type,
    /// <summary>Whether a type is a value type: no signature in the folder encodes it consistently.</summary>
    ValueTypeness,
    /// <summary>Whether a value type is an enum, and of what underlying type.</summary>
    EnumOrStruct,
    /// <summary>A base chain, beyond a reference type being assignable to <c>object</c>.</summary>
    BaseType,
    /// <summary>The interfaces a type implements.</summary>
    Interfaces,
    /// <summary>A generic type's arity, where its uses disagree with its name.</summary>
    Arity,
    /// <summary>A field or method the type is referenced as having.</summary>
    Member,
}

/// <summary>Thrown for a question about a type outside the folder that no reference answers; fails one method, as Unknown.</summary>
public sealed class UnresolvedFactException : Exception
{
    #region Constructors
    public UnresolvedFactException(UnresolvedFact fact, string typeName, string? detail = null)
        : base($"Unresolved {fact} of '{typeName}'" + (detail is null ? "" : ": " + detail))
    {
        Fact = fact;
        TypeName = typeName;
    }
    #endregion

    #region Properties
    public UnresolvedFact Fact { get; }

    /// <summary>The type's metadata name, raw (escape it before display).</summary>
    public string TypeName { get; }
    #endregion
}

/// <summary>Thrown when the adapter cannot express malformed or unsupported input in Cilica's model; fails one method.</summary>
public sealed class SsaAdapterException : Exception
{
    #region Constructors
    public SsaAdapterException(string message, Exception? inner = null, SsaFailureKind kind = SsaFailureKind.Adapter)
        : base(message, inner) => Kind = kind;
    #endregion

    #region Properties
    public SsaFailureKind Kind { get; }

    /// <summary>The failure depends on the path that reached it (a nesting bound), not on the input alone: never memoised.</summary>
    public bool IsPathDependent { get; init; }
    #endregion
}

/// <summary>Bounds on hostile input. Exceeding one fails the method (or the type) it is met in, never the session.</summary>
public sealed record SsaBounds
{
    #region Properties
    public static SsaBounds Default { get; } = new();

    /// <summary>Type nesting, generic and signature depth, and base-chain length, like <c>ModelNames.MaxDepth</c>.</summary>
    public int MaxDepth { get; init; } = 64;

    /// <summary>Instructions in one method body.</summary>
    public int MaxInstructions { get; init; } = 100_000;

    /// <summary>Exception clauses in one method body.</summary>
    public int MaxExceptionClauses { get; init; } = 4_096;

    /// <summary>Bytes of one RVA field's data.</summary>
    public int MaxMappedDataBytes { get; init; } = 16 * 1024 * 1024;

    /// <summary>
    /// Adapter answers nested one inside another (a constraint, base or member chain reached through Cilica's lazy getters).
    /// Past it the asking method fails as Bounds; the stack is also checked.
    /// </summary>
    public int MaxNesting { get; init; } = 256;

    /// <summary>Type-forwarder hops followed for one type.</summary>
    public int MaxForwarderHops { get; init; } = 16;

    /// <summary>
    /// Parts one mapped type expands to as a tree, a shared part counted each time it is used. Metadata can name a TypeSpec
    /// inside another's signature, so a few rows can make a type that doubles per level, and Cilica walks types as trees.
    /// </summary>
    public int MaxTypeParts { get; init; } = 4_096;

    /// <summary>Bytes of RVA field data kept for one assembly (aliasing fields share one copy).</summary>
    public long MaxMappedDataBytesPerAssembly { get; init; } = 64L * 1024 * 1024;
    #endregion

    #region Methods
    /// <summary>Throws if a bound is not positive.</summary>
    public SsaBounds Validated()
    {
        if (MaxDepth <= 0 || MaxInstructions <= 0 || MaxExceptionClauses <= 0 || MaxMappedDataBytes <= 0
            || MaxNesting <= 0 || MaxForwarderHops <= 0 || MaxMappedDataBytesPerAssembly <= 0 || MaxTypeParts <= 0)
            throw new ArgumentOutOfRangeException(nameof(SsaBounds), "Every bound must be positive");
        return this;
    }
    #endregion
}

/// <summary>One assembly of the folder: read, or lost whole with the reason.</summary>
public sealed record SsaAssembly(string Path, string? Name, string? Error)
{
    #region Properties
    public bool IsLoaded => Error is null;
    #endregion
}

/// <summary>Why one method is Unknown.</summary>
public sealed record SsaFailure(SsaFailureKind Kind, string Reason);

/// <summary>
/// One method's outcome: verified SSA (<see cref="Body"/>), or Unknown (<see cref="Failure"/>). <see cref="Method"/> is the
/// <see cref="CciNames"/> identity, the join to <c>MethodGraph</c> (with IL offsets); <see cref="MethodToken"/> is its
/// MethodDef token in <see cref="AssemblyPath"/>, an exact join to anything else that reads the file.
/// <see cref="SsaFailure.Reason"/> may carry metadata names: escape it before display.
/// </summary>
public sealed record SsaMethodOutcome(string AssemblyPath, uint MethodToken, MethodIdentity Method, SsaFailure? Failure, Cilica.IR.MethodBody? Body)
{
    #region Properties
    public bool IsLifted => Failure is null;

    public string NodeId => CanonicalName.NodeId(Method);

    /// <summary>
    /// The IL offset each instruction of <see cref="Body"/> was imported from, the opcode's own (not its prefix's), as in
    /// <c>MethodEdge.Offset</c>. Covers every <c>CallInst</c>, <c>NewObjInst</c> and <c>FuncAddrInst</c>, and the
    /// <c>InitializeArray</c> and <c>CallIndirect</c> intrinsics; synthesized instructions (such as phis, guards, argument
    /// copies, store coercions, block-split and leave branches, <c>initobj</c>) have none, and several instructions may
    /// share an offset. Only instructions in the body; empty when not
    /// lifted. Its keys hold the IR alive: drop it together with <see cref="Body"/>.
    /// </summary>
    public IReadOnlyDictionary<Cilica.IR.Instruction, int> ILOffsets { get; init; } = ReadOnlyDictionary<Cilica.IR.Instruction, int>.Empty;
    #endregion

    #region Methods
    /// <summary>The IL offset <paramref name="instruction"/> was imported from, or null when it has none.</summary>
    public uint? OffsetOf(Cilica.IR.Instruction instruction) =>
        ILOffsets.TryGetValue(instruction, out var offset) ? (uint)offset : null;
    #endregion
}
