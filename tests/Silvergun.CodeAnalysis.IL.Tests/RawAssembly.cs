namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// An assembly written row by row through <see cref="MetadataBuilder"/> (BCL, no NuGet), for the SSA adapter's shapes that
/// neither csc nor <see cref="System.Reflection.Emit.PersistedAssemblyBuilder"/> writes: references into assemblies that
/// do not exist, with the CLASS/VALUETYPE encodings a test chooses; cyclic base types; duplicate type names; raw tokens
/// and the <c>no.</c> prefix. Saved, then read as metadata only, never loaded.
/// <para>
/// Rows go in order: a type owns the methods and fields added after it and before the next type, so callers add a type,
/// then its members. Its references point at <c>System.Runtime</c>, as compiled code does, so binding them exercises the
/// host's facades and forwarders; without <c>withRuntime</c> it has no references at all (CCI then takes a module that
/// defines <c>System.Object</c> as its own core library).
/// </para>
/// </summary>
internal sealed class RawAssembly
{
    #region Constructors
    public RawAssembly(string name, bool withRuntime = true)
    {
        Name = name;
        bodies = new MethodBodyStreamEncoder(ilStream);
        Metadata.AddModule(0, Metadata.GetOrAddString(name + ".dll"), Metadata.GetOrAddGuid(Mvid(name)), default, default);
        Metadata.AddAssembly(Metadata.GetOrAddString(name), new Version(1, 0, 0, 0), default, default, 0, AssemblyHashAlgorithm.None);
        if (withRuntime)
        {
            Runtime = Metadata.AddAssemblyReference(Metadata.GetOrAddString("System.Runtime"), new Version(10, 0, 0, 0), default,
                Metadata.GetOrAddBlob(new byte[] { 0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A }), default, default);
            Object = TypeRef(Runtime, "System", "Object");
        }
        Metadata.AddTypeDefinition(0, default, Metadata.GetOrAddString("<Module>"), default, NextField, NextMethod);
    }
    #endregion

    #region Properties
    public string Name { get; }

    public MetadataBuilder Metadata { get; } = new();

    /// <summary>The <c>System.Runtime</c> reference (nil without <c>withRuntime</c>).</summary>
    public AssemblyReferenceHandle Runtime { get; }

    /// <summary><c>[System.Runtime]System.Object</c>.</summary>
    public TypeReferenceHandle Object { get; }

    /// <summary>The handle the next <see cref="Type"/> call returns (or, with <paramref name="ahead"/>, a later one).</summary>
    public TypeDefinitionHandle NextType(int ahead = 0) => MetadataTokens.TypeDefinitionHandle(Metadata.GetRowCount(TableIndex.TypeDef) + 1 + ahead);

    private FieldDefinitionHandle NextField => MetadataTokens.FieldDefinitionHandle(Metadata.GetRowCount(TableIndex.Field) + 1);

    private MethodDefinitionHandle NextMethod => MetadataTokens.MethodDefinitionHandle(Metadata.GetRowCount(TableIndex.MethodDef) + 1);
    #endregion

    #region Methods
    public AssemblyReferenceHandle AssemblyRef(string name) =>
        Metadata.AddAssemblyReference(Metadata.GetOrAddString(name), new Version(1, 0, 0, 0), default, default, default, default);

    /// <summary>A TypeRef scoped to an assembly reference, or (nested) to another TypeRef.</summary>
    public TypeReferenceHandle TypeRef(EntityHandle scope, string? ns, string name) =>
        Metadata.AddTypeReference(scope, ns is null ? default : Metadata.GetOrAddString(ns), Metadata.GetOrAddString(name));

    /// <summary>A type definition; its members are the ones added next.</summary>
    public TypeDefinitionHandle Type(string? ns, string name, EntityHandle baseType, TypeAttributes attributes = TypeAttributes.Public | TypeAttributes.Class) =>
        Metadata.AddTypeDefinition(attributes, ns is null ? default : Metadata.GetOrAddString(ns), Metadata.GetOrAddString(name), baseType, NextField, NextMethod);

    public FieldDefinitionHandle Field(string name, FieldAttributes attributes, Action<SignatureTypeEncoder> type)
    {
        var blob = new BlobBuilder();
        type(new BlobEncoder(blob).Field().Type());
        return Metadata.AddFieldDefinition(attributes, Metadata.GetOrAddString(name), Metadata.GetOrAddBlob(blob));
    }

    /// <summary>
    /// A method of the last type, with the body <paramref name="emit"/> writes (branches through its labels), and the
    /// locals <paramref name="locals"/> declares, if any (or, verbatim, <paramref name="localSignature"/>).
    /// </summary>
    public MethodDefinitionHandle Method(
        string name, MethodAttributes attributes, BlobBuilder signature, Action<InstructionEncoder> emit,
        Action<LocalVariablesEncoder>? locals = null, int localCount = 0, bool initLocals = true, int maxStack = 8,
        byte[]? localSignature = null)
    {
        var il = new InstructionEncoder(new BlobBuilder(), new ControlFlowBuilder());
        emit(il);
        var localsHandle = localSignature is null ? default : StandaloneSignature(localSignature);
        if (locals is not null)
        {
            var blob = new BlobBuilder();
            locals(new BlobEncoder(blob).LocalVariableSignature(localCount));
            localsHandle = Metadata.AddStandaloneSignature(Metadata.GetOrAddBlob(blob));
        }
        var offset = bodies.AddMethodBody(il, maxStack, localsHandle, initLocals ? MethodBodyAttributes.InitLocals : MethodBodyAttributes.None);
        return Metadata.AddMethodDefinition(attributes, MethodImplAttributes.IL, Metadata.GetOrAddString(name),
            Metadata.GetOrAddBlob(signature), offset, MetadataTokens.ParameterHandle(Metadata.GetRowCount(TableIndex.Param) + 1));
    }

    /// <summary>A public static method of the last type.</summary>
    public MethodDefinitionHandle Static(string name, BlobBuilder signature, Action<InstructionEncoder> emit) =>
        Method(name, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, signature, emit);

    /// <summary>A public instance method of the last type.</summary>
    public MethodDefinitionHandle Instance(string name, BlobBuilder signature, Action<InstructionEncoder> emit) =>
        Method(name, MethodAttributes.Public | MethodAttributes.HideBySig, signature, emit);

    /// <summary>Nests <paramref name="nested"/> (flagged <c>Nested*</c>) in <paramref name="enclosing"/>; add in nested-row order.</summary>
    public void Nest(TypeDefinitionHandle nested, TypeDefinitionHandle enclosing) => Metadata.AddNestedType(nested, enclosing);

    /// <summary>A StandAloneSig row whose signature is exactly <paramref name="blob"/>.</summary>
    public StandaloneSignatureHandle StandaloneSignature(byte[] blob) => Metadata.AddStandaloneSignature(Metadata.GetOrAddBlob(blob));

    /// <summary>A ClassLayout row: <paramref name="type"/>'s packing and total size.</summary>
    public void Layout(TypeDefinitionHandle type, int size, ushort packing = 1) => Metadata.AddTypeLayout(type, packing, (uint)size);

    /// <summary>A TypeSpec whose signature is exactly <paramref name="blob"/>, well-formed or not.</summary>
    public TypeSpecificationHandle TypeSpecBytes(byte[] blob) => Metadata.AddTypeSpecification(Metadata.GetOrAddBlob(blob));

    /// <summary>A generic parameter of <paramref name="owner"/>; add them in owner order (the table is sorted).</summary>
    public GenericParameterHandle GenericParameter(EntityHandle owner, string name, int index) =>
        Metadata.AddGenericParameter(owner, GenericParameterAttributes.None, Metadata.GetOrAddString(name), index);

    public void Constraint(GenericParameterHandle parameter, EntityHandle type) => Metadata.AddGenericParameterConstraint(parameter, type);

    /// <summary>Appends <paramref name="data"/> to the mapped field data and returns its offset, for <see cref="FieldRva"/>.</summary>
    public int MappedData(byte[] data)
    {
        var offset = mappedData.Count;
        mappedData.WriteBytes(data);
        mappedData.Align(8);
        return offset;
    }

    /// <summary>Points an RVA field (flagged <c>HasFieldRVA</c>) at <paramref name="offset"/> in the mapped field data.</summary>
    public void FieldRva(FieldDefinitionHandle field, int offset) => Metadata.AddFieldRelativeVirtualAddress(field, offset);

    public MemberReferenceHandle MemberRef(EntityHandle parent, string name, BlobBuilder signature) =>
        Metadata.AddMemberReference(parent, Metadata.GetOrAddString(name), Metadata.GetOrAddBlob(signature));

    public TypeSpecificationHandle TypeSpec(Action<SignatureTypeEncoder> type)
    {
        var blob = new BlobBuilder();
        type(new BlobEncoder(blob).TypeSpecificationSignature());
        return Metadata.AddTypeSpecification(Metadata.GetOrAddBlob(blob));
    }

    /// <summary>A method signature: <paramref name="returns"/> and one encoder action per parameter.</summary>
    public static BlobBuilder MethodSig(bool instance, Action<ReturnTypeEncoder> returns, params Action<SignatureTypeEncoder>[] parameters)
    {
        var blob = new BlobBuilder();
        new BlobEncoder(blob).MethodSignature(isInstanceMethod: instance).Parameters(parameters.Length, returns, encoder =>
        {
            foreach (var parameter in parameters)
                parameter(encoder.AddParameter().Type());
        });
        return blob;
    }

    /// <summary>A field signature, for a MemberRef.</summary>
    public static BlobBuilder FieldSig(Action<SignatureTypeEncoder> type)
    {
        var blob = new BlobBuilder();
        type(new BlobEncoder(blob).Field().Type());
        return blob;
    }

    /// <summary>Writes <c>&lt;Name&gt;.dll</c> into <paramref name="directory"/> and returns its path.</summary>
    public string Save(string directory, Action<MetadataBuilder>? addRows = null)
    {
        addRows?.Invoke(Metadata);
        var image = new ManagedPEBuilder(
            new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(Metadata),
            ilStream,
            mappedFieldData: mappedData);
        var blob = new BlobBuilder();
        image.Serialize(blob);
        var path = Path.Combine(directory, Name + ".dll");
        using var file = File.Create(path);
        blob.WriteContentTo(file);
        return path;
    }

    // A fixed MVID per name, so a fixture written twice is the same bytes.
    private static Guid Mvid(string name) => new(SHA256.HashData(Encoding.UTF8.GetBytes(name)).AsSpan(0, 16));
    #endregion

    #region Fields
    private readonly BlobBuilder ilStream = new();
    private readonly BlobBuilder mappedData = new();
    private readonly MethodBodyStreamEncoder bodies;
    #endregion
}
