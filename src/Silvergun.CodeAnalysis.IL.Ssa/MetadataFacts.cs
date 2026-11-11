namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

/// <summary>
/// The row scalars CCI's object model drops, read by token from the same file: exact metadata names, raw flags (e.g. the
/// runtime-async impl bit) and TypeRef resolution scopes. CCI keeps the structure (members, signatures, bodies); this keeps
/// the scalars. Also scans the folder's signatures for how each TypeRef is encoded (CLASS or VALUETYPE), the one fact a
/// stub type's value-typeness rests on (ruling D3), which CCI keeps only as a sticky, decode-order-dependent flag.
/// </summary>
internal sealed class MetadataFacts : IDisposable
{
    #region Constructors
    private MetadataFacts(PEReader pe)
    {
        this.pe = pe;
        Reader = pe.GetMetadataReader();
    }
    #endregion

    #region Properties
    public MetadataReader Reader { get; }
    #endregion

    #region Methods
    /// <summary>Opens <paramref name="path"/>; throws if it is not readable metadata.</summary>
    public static MetadataFacts Open(string path)
    {
        var stream = File.OpenRead(path);
        PEReader? pe = null;
        try
        {
            pe = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
            return new MetadataFacts(pe);
        }
        catch
        {
            if (pe is null) stream.Dispose();
            else pe.Dispose();
            throw;
        }
    }

    /// <summary>The key of a type reference's encodings: its assembly (case-insensitive), outermost namespace, nesting chain.</summary>
    public static (string, string?, string) EncodingKey(string assembly, string? ns, string chain) => (assembly.ToUpperInvariant(), ns, chain);

    /// <summary>
    /// The assembly this one forwards the top-level type <paramref name="ns"/>.<paramref name="name"/> to, matched exactly
    /// (arity included); null if it forwards none. Throws if it forwards the name to two assemblies, or the table is too big.
    /// </summary>
    public string? ExportedTarget(string? ns, string name)
    {
        if (exports is null)
        {
            var map = new Dictionary<(string?, string), string?>();
            if (Reader.GetTableRowCount(TableIndex.ExportedType) <= MaxExportedRows)
            {
                foreach (var handle in Reader.ExportedTypes)
                {
                    var row = Reader.GetExportedType(handle);
                    if (row.Implementation.Kind != HandleKind.AssemblyReference)
                        continue;
                    var key = (Namespace(row.Namespace), Reader.GetString(row.Name));
                    var target = Reader.GetString(Reader.GetAssemblyReference((AssemblyReferenceHandle)row.Implementation).Name);
                    // Two different targets for one name is ambiguous: kept as null, and refused below.
                    map[key] = map.TryGetValue(key, out var known) && !string.Equals(known, target, StringComparison.OrdinalIgnoreCase) ? null : target;
                }
            }
            else
            {
                exportsUnreadable = true;
            }
            exports = map;
        }
        if (exportsUnreadable)
            throw new UnresolvedFactException(UnresolvedFact.Type, (ns is null ? "" : ns + ".") + name, "the assembly's exported-type table is too large to read");
        return exports.TryGetValue((ns, name), out var found)
            ? found ?? throw new UnresolvedFactException(UnresolvedFact.Type, (ns is null ? "" : ns + ".") + name, "forwarded to more than one assembly")
            : null;
    }

    public static int TableOf(uint token) => (int)(token >> 24);

    public static int RowOf(uint token) => (int)(token & 0x00FF_FFFF);

    /// <summary>The empty namespace as null, on both sides of every lookup (definitions and references).</summary>
    public string? Namespace(StringHandle handle) => handle.IsNil ? null : Reader.GetString(handle) is { Length: > 0 } ns ? ns : null;

    public (string? Namespace, string Name, TypeAttributes Attributes) TypeDef(uint token)
    {
        var row = Reader.GetTypeDefinition(MetadataTokens.TypeDefinitionHandle(Checked(token, TableIndex.TypeDef)));
        return (Namespace(row.Namespace), Reader.GetString(row.Name), row.Attributes);
    }

    public (MethodAttributes Attributes, MethodImplAttributes ImplAttributes) Method(uint token)
    {
        var row = Reader.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(Checked(token, TableIndex.MethodDef)));
        return (row.Attributes, row.ImplAttributes);
    }

    public FieldAttributes Field(uint token) =>
        Reader.GetFieldDefinition(MetadataTokens.FieldDefinitionHandle(Checked(token, TableIndex.Field))).Attributes;

    public int FieldRva(uint token) =>
        Reader.GetFieldDefinition(MetadataTokens.FieldDefinitionHandle(Checked(token, TableIndex.Field))).GetRelativeVirtualAddress();

    public GenericParameterAttributes GenericParameter(uint token) =>
        Reader.GetGenericParameter(MetadataTokens.GenericParameterHandle(Checked(token, TableIndex.GenericParam))).Attributes;

    public TypeRefRow TypeRef(uint token)
    {
        var row = Reader.GetTypeReference(MetadataTokens.TypeReferenceHandle(Checked(token, TableIndex.TypeRef)));
        var scope = row.ResolutionScope;
        var (kind, assembly, parent) = scope.IsNil ? (TypeRefScope.Nil, null, 0u) : scope.Kind switch
        {
            HandleKind.AssemblyReference => (TypeRefScope.Assembly,
                Reader.GetString(Reader.GetAssemblyReference((AssemblyReferenceHandle)scope).Name), 0u),
            HandleKind.TypeReference => (TypeRefScope.TypeRef, null, (uint)MetadataTokens.GetToken(scope)),
            HandleKind.ModuleDefinition => (TypeRefScope.Module, null, 0u),
            HandleKind.ModuleReference => (TypeRefScope.ModuleRef, null, 0u),
            _ => (TypeRefScope.Nil, null, 0u),
        };
        return new TypeRefRow(Namespace(row.Namespace), Reader.GetString(row.Name), kind, (string?)assembly, parent);
    }

    /// <summary>
    /// Signature blobs the scan could not parse; any makes this module's encodings (of its own TypeRefs) and instantiation
    /// counts unproven.
    /// </summary>
    public int UnparsedSignatures { get; private set; }

    /// <summary>
    /// How every TypeRef of this module that names another assembly is encoded across its signatures, by
    /// <see cref="EncodingKey"/>; also records each generic instantiation's argument count (<see cref="DisagreesWith"/>).
    /// Every signature blob is read once, by an iterative walk of the ECMA-335 type grammar (no recursion, so no blob is
    /// too long or too deep to read); one it cannot parse is counted in <see cref="UnparsedSignatures"/>. Never throws.
    /// </summary>
    public IReadOnlyDictionary<(string, string?, string), TypeEncoding> ScanEncodings(SsaBounds bounds)
    {
        var scanner = new SignatureScanner();
        var reader = Reader;
        var scanned = new HashSet<BlobHandle>();

        void Scan(BlobHandle blob, SignatureShape shape)
        {
            // Once per blob: rows may share one, and a blob reads the same whichever row reaches it.
            if (blob.IsNil || !scanned.Add(blob))
                return;
            try
            {
                var blobReader = reader.GetBlobReader(blob);
                scanner.Scan(ref blobReader, shape);
            }
            catch (Exception)
            {
                UnparsedSignatures++;
            }
        }

        foreach (var h in reader.TypeDefinitions)
        {
            Guard(() =>
            {
                var type = reader.GetTypeDefinition(h);
                foreach (var m in type.GetMethods())
                    Scan(reader.GetMethodDefinition(m).Signature, SignatureShape.Method);
                foreach (var f in type.GetFields())
                    Scan(reader.GetFieldDefinition(f).Signature, SignatureShape.Field);
                foreach (var p in type.GetProperties())
                    Scan(reader.GetPropertyDefinition(p).Signature, SignatureShape.Method);
            });
        }
        for (var row = 1; row <= reader.GetTableRowCount(TableIndex.TypeSpec); row++)
            Scan(reader.GetTypeSpecification(MetadataTokens.TypeSpecificationHandle(row)).Signature, SignatureShape.Type);
        foreach (var h in reader.MemberReferences)
            Guard(() => Scan(reader.GetMemberReference(h).Signature, SignatureShape.FieldOrMethod));
        for (var row = 1; row <= reader.GetTableRowCount(TableIndex.StandAloneSig); row++)
            Scan(reader.GetStandaloneSignature(MetadataTokens.StandaloneSignatureHandle(row)).Signature, SignatureShape.LocalsOrMethod);
        for (var row = 1; row <= reader.GetTableRowCount(TableIndex.MethodSpec); row++)
            Scan(reader.GetMethodSpecification(MetadataTokens.MethodSpecificationHandle(row)).Signature, SignatureShape.Instantiation);

        instantiations = scanner.Arities;
        // A blob the scan could not read may hold a conflicting encoding of any TypeRef of this module (and only of this
        // module's): those are marked as conflicting, which proves nothing about them, and nothing else is touched.
        var seen = UnparsedSignatures == 0
            ? scanner.Seen
            : reader.TypeReferences.ToDictionary(h => h, _ => TypeEncoding.Class | TypeEncoding.ValueType);
        var keyed = new Dictionary<(string, string?, string), TypeEncoding>();
        foreach (var (handle, encoding) in seen)
        {
            (string, string?, string)? key = null;
            try { key = ChainKey((uint)MetadataTokens.GetToken(handle), bounds.MaxDepth); }
            catch (Exception) { }
            if (key is { } k)
                keyed[k] = keyed.GetValueOrDefault(k) | encoding;
        }
        return keyed;
    }

    /// <summary>
    /// The <see cref="EncodingKey"/> of a TypeRef scoped to an assembly reference: that assembly, the outermost namespace and
    /// the outer-to-inner chain of names. Null for any other scope (only references to other assemblies can become stubs).
    /// </summary>
    public (string, string?, string)? ChainKey(uint typeRefToken, int maxDepth)
    {
        var names = new List<string>();
        for (var depth = 0; depth < maxDepth; depth++)
        {
            var row = TypeRef(typeRefToken);
            names.Insert(0, row.Name);
            if (row.Kind != TypeRefScope.TypeRef)
                return row.Kind == TypeRefScope.Assembly ? EncodingKey(row.AssemblyName!, row.Namespace, string.Join("/", names)) : null;
            typeRefToken = row.ParentToken;
        }
        return null;
    }

    /// <summary>
    /// Whether a signature of this (scanned) module instantiates the generic TypeDef or TypeRef <paramref name="token"/> with
    /// a number of arguments other than <paramref name="count"/>. CCI takes only as many as the name declares, so a
    /// disagreeing blob would otherwise read as a different type.
    /// </summary>
    /// <remarks>A module with an unparsed signature proves no count, so every instantiation in it disagrees.</remarks>
    public bool DisagreesWith(uint token, int count) =>
        instantiations is not null && (UnparsedSignatures > 0 || instantiations.TryGetValue(token, out var counts) && counts.Any(c => c != count));

    public void Dispose() => pe.Dispose();

    private static int Checked(uint token, TableIndex table) =>
        TableOf(token) == (int)table && RowOf(token) > 0
            ? RowOf(token)
            : throw new SsaAdapterException($"Token 0x{token:X8} is not a {table} row");

    private static void Guard(Action read)
    {
        try { read(); }
        catch (Exception) { }
    }
    #endregion

    #region Fields
    private const int MaxExportedRows = 65_536;

    private readonly PEReader pe;
    private Dictionary<(string?, string), string?>? exports;
    private Dictionary<uint, HashSet<int>>? instantiations;
    private bool exportsUnreadable;
    #endregion

    #region Child types
    /// <summary>The grammar a signature blob is read with.</summary>
    private enum SignatureShape { Type, Field, Method, FieldOrMethod, LocalsOrMethod, Instantiation }

    /// <summary>
    /// Reads signature blobs by ECMA-335 II.23.2 without recursion: an explicit stack of "types still to read" counts, so
    /// the work is linear in the blob whatever its nesting. Records each TypeRef's CLASS/VALUETYPE encoding and each
    /// generic instantiation's argument count; builds nothing. Throws <see cref="BadImageFormatException"/> on anything
    /// outside the grammar.
    /// </summary>
    private sealed class SignatureScanner
    {
        public Dictionary<TypeReferenceHandle, TypeEncoding> Seen { get; } = new();

        public Dictionary<uint, HashSet<int>> Arities { get; } = new();

        public void Scan(ref BlobReader blob, SignatureShape shape)
        {
            if (shape == SignatureShape.Type)
            {
                Types(ref blob, 1);
                return;
            }
            var header = blob.ReadSignatureHeader();
            switch (header.Kind)
            {
                // C++/CLI writes field signatures into StandAloneSig rows too.
                case SignatureKind.Field when shape is SignatureShape.Field or SignatureShape.FieldOrMethod or SignatureShape.LocalsOrMethod:
                    Types(ref blob, 1);
                    break;
                case SignatureKind.Method or SignatureKind.Property
                    when shape is SignatureShape.Method or SignatureShape.FieldOrMethod or SignatureShape.LocalsOrMethod:
                    if (header.IsGeneric)
                        blob.ReadCompressedInteger();
                    Types(ref blob, blob.ReadCompressedInteger() + 1L);
                    break;
                case SignatureKind.LocalVariables when shape == SignatureShape.LocalsOrMethod:
                case SignatureKind.MethodSpecification when shape == SignatureShape.Instantiation:
                    Types(ref blob, blob.ReadCompressedInteger());
                    break;
                default:
                    throw new BadImageFormatException("Unexpected signature header");
            }
        }

        // Reads `count` consecutive types. A frame counts the types still to read at one level; an ARRAY frame reads the
        // array shape once its element type is done.
        private void Types(ref BlobReader blob, long count)
        {
            var frames = new Stack<(long Remaining, bool ArrayShape)>();
            frames.Push((count, false));
            while (frames.Count > 0)
            {
                var (remaining, arrayShape) = frames.Pop();
                if (remaining == 0)
                {
                    if (arrayShape)
                        Shape(ref blob);
                    continue;
                }
                frames.Push((remaining - 1, arrayShape));
                // One type: any prefixes (modifiers, pinned, by-ref, pointer, vector, sentinel), then its head.
                while (true)
                {
                    var code = blob.ReadByte();
                    if (code is 0x1F or 0x20)
                    {
                        blob.ReadTypeHandle();
                        continue;
                    }
                    if (code is 0x45 or 0x10 or 0x0F or 0x1D or 0x41)
                        continue;
                    if (code is >= 0x01 and <= 0x0E or 0x16 or 0x18 or 0x19 or 0x1C)
                        break;
                    switch (code)
                    {
                        case 0x11 or 0x12:
                            Named(blob.ReadTypeHandle(), code);
                            break;
                        case 0x13 or 0x1E:
                            blob.ReadCompressedInteger();
                            break;
                        case 0x14:
                            frames.Push((1, true));
                            break;
                        case 0x15:
                        {
                            var kind = blob.ReadByte();
                            if (kind is not (0x11 or 0x12))
                                throw new BadImageFormatException("A generic instantiation of neither a class nor a value type");
                            var generic = Named(blob.ReadTypeHandle(), kind);
                            var arguments = blob.ReadCompressedInteger();
                            if (!Arities.TryGetValue(generic, out var counts))
                                Arities[generic] = counts = new HashSet<int>();
                            counts.Add(arguments);
                            frames.Push((arguments, false));
                            break;
                        }
                        case 0x1B:
                        {
                            var header = blob.ReadSignatureHeader();
                            if (header.IsGeneric)
                                blob.ReadCompressedInteger();
                            frames.Push((blob.ReadCompressedInteger() + 1L, false));
                            break;
                        }
                        default:
                            throw new BadImageFormatException($"Unexpected element type 0x{code:X2}");
                    }
                    break;
                }
            }
            // Trailing bytes are left alone, as CCI leaves them (some writers append ELEMENT_TYPE_END): it reads only the
            // declared types, so they cannot shift what it reads.
        }

        private uint Named(EntityHandle handle, byte code)
        {
            if (handle.Kind == HandleKind.TypeReference)
            {
                var typeRef = (TypeReferenceHandle)handle;
                Seen[typeRef] = Seen.GetValueOrDefault(typeRef) | (code == 0x11 ? TypeEncoding.ValueType : TypeEncoding.Class);
            }
            return (uint)MetadataTokens.GetToken(handle);
        }

        private static void Shape(ref BlobReader blob)
        {
            blob.ReadCompressedInteger();
            for (var sizes = blob.ReadCompressedInteger(); sizes > 0; sizes--)
                blob.ReadCompressedInteger();
            for (var bounds = blob.ReadCompressedInteger(); bounds > 0; bounds--)
                blob.ReadCompressedSignedInteger();
        }
    }
    #endregion
}

/// <summary>How a TypeRef's resolution scope names its container.</summary>
internal enum TypeRefScope { Assembly, TypeRef, Module, ModuleRef, Nil }

/// <summary>One TypeRef row. <see cref="ParentToken"/> is set for a nested reference, <see cref="AssemblyName"/> for a top-level one.</summary>
internal readonly record struct TypeRefRow(string? Namespace, string Name, TypeRefScope Kind, string? AssemblyName, uint ParentToken);

/// <summary>The signature encodings seen for a type reference; both is a conflict, and proves nothing.</summary>
[Flags]
internal enum TypeEncoding { None = 0, Class = 1, ValueType = 2 }
