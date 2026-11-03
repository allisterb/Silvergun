namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

/// <summary>
/// Assemblies EMITTED AT TEST TIME with <see cref="PersistedAssemblyBuilder"/> (BCL since .NET 9; no NuGet) into a
/// fresh temporary directory owned by one test class, then read back as metadata by <see cref="ModelAssemblies"/>.
/// They are not loaded or executed, except where a test uses the CLR itself as the oracle — and then only in an
/// <see cref="IsolatedLoadContext"/>, from bytes. This is how shapes reach the index that must not, or cannot, come from csc:
/// <list type="bullet">
/// <item><description>deep type nesting (a 63-rank jagged array): compiling one once drove the compiler server to
/// ~50 GB (spec §2.5's fixture incident), so deep shapes are only ever emitted;</description></item>
/// <item><description>names C# cannot spell (a method literally named <c>X`1.M</c>, a namespace <c>NS.G`1</c>);</description></item>
/// <item><description>metadata rows <see cref="PersistedAssemblyBuilder"/> cannot write — <c>ExportedType</c> type
/// forwarders, added through the <see cref="MetadataBuilder"/> overload of <c>Save</c>.</description></item>
/// </list>
/// The IL each caller emits names its target by token, so the emit itself is the oracle for which definition a site
/// binds — independent of <see cref="MemberIndex.Resolve"/>.
/// </summary>
internal sealed class EmittedAssembly : IDisposable
{
    #region Constructors
    public EmittedAssembly() => Directory = System.IO.Directory.CreateTempSubdirectory("silvergun-emit-").FullName;
    #endregion

    #region Properties
    /// <summary>The temporary directory every assembly of this instance is saved into.</summary>
    public string Directory { get; }
    #endregion

    #region Methods
    /// <summary>
    /// Emits an assembly <paramref name="name"/> whose single module <paramref name="define"/> fills (it must create every
    /// type it defines), saves it as <c>name.dll</c> in <see cref="Directory"/> (or its <paramref name="subdirectory"/>,
    /// so one name can be emitted in several variants) and returns the path.
    /// </summary>
    public string Save(string name, Action<ModuleBuilder> define, string? subdirectory = null)
    {
        var builder = new PersistedAssemblyBuilder(new AssemblyName(name), typeof(object).Assembly);
        define(builder.DefineDynamicModule(name));
        var path = PathFor(name, subdirectory);
        builder.Save(path);
        return path;
    }

    /// <summary>
    /// As <see cref="Save(string, Action{ModuleBuilder}, string?)"/>, but <paramref name="addRows"/> may add metadata
    /// rows <see cref="PersistedAssemblyBuilder"/> has no API for — <c>ExportedType</c> forwarders (see
    /// <see cref="Forwarding"/>) — before the PE image is serialized.
    /// </summary>
    public string Save(string name, Action<ModuleBuilder> define, Action<MetadataBuilder> addRows, string? subdirectory = null)
    {
        var builder = new PersistedAssemblyBuilder(new AssemblyName(name), typeof(object).Assembly);
        define(builder.DefineDynamicModule(name));
        var metadata = builder.GenerateMetadata(out var il, out var fieldData);
        addRows(metadata);
        var image = new ManagedPEBuilder(
            new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(metadata),
            il,
            fieldData);
        var blob = new BlobBuilder();
        image.Serialize(blob);
        var path = PathFor(name, subdirectory);
        using var file = File.Create(path);
        blob.WriteContentTo(file);
        return path;
    }

    /// <summary>
    /// Adds one top-level type forwarder (an <c>ExportedType</c> row flagged <c>IsTypeForwarder</c>) per entry, with one
    /// <c>AssemblyRef</c> per distinct target assembly.
    /// </summary>
    public static Action<MetadataBuilder> Forwarding(params (string Namespace, string Name, string Assembly)[] forwards) => metadata =>
    {
        var references = new Dictionary<string, AssemblyReferenceHandle>(StringComparer.Ordinal);
        foreach (var (space, name, assembly) in forwards)
        {
            if (!references.TryGetValue(assembly, out var reference))
                references[assembly] = reference = Reference(metadata, assembly);
            Forward(metadata, space, name, reference);
        }
    };

    /// <summary>
    /// A new <c>AssemblyRef</c> row: the running System.Private.CoreLib's identity for that name, otherwise version
    /// 0.0.0.0 with no public key (what <see cref="PersistedAssemblyBuilder"/> gives every emitted assembly).
    /// </summary>
    public static AssemblyReferenceHandle Reference(MetadataBuilder metadata, string assembly)
    {
        var core = typeof(object).Assembly.GetName();
        return assembly == core.Name
            ? metadata.AddAssemblyReference(metadata.GetOrAddString(core.Name), core.Version!, default, metadata.GetOrAddBlob(core.GetPublicKeyToken()!), default, default)
            : metadata.AddAssemblyReference(metadata.GetOrAddString(assembly), new Version(0, 0, 0, 0), default, default, default, default);
    }

    /// <summary>A top-level type forwarder row for <paramref name="space"/>.<paramref name="name"/> to <paramref name="implementation"/>.</summary>
    public static ExportedTypeHandle Forward(MetadataBuilder metadata, string space, string name, EntityHandle implementation) =>
        metadata.AddExportedType(
            TypeAttributes.NotPublic | TypeForwarder,
            metadata.GetOrAddString(space),
            metadata.GetOrAddString(name),
            implementation,
            0);

    /// <summary>
    /// Adds one <c>File</c> row for <paramref name="module"/> (a module file of this assembly that is never written) and
    /// one top-level <c>ExportedType</c> row per type, implemented by that file — a multi-module assembly's export, which
    /// CoreCLR refuses to load (FileLoadException) and .NET Framework would follow into the netmodule.
    /// </summary>
    public static Action<MetadataBuilder> ExportingFromModule(string module, params (string Namespace, string Name)[] types) => metadata =>
    {
        var file = metadata.AddAssemblyFile(metadata.GetOrAddString(module), metadata.GetOrAddBlob(new byte[20]), containsMetadata: true);
        foreach (var (space, name) in types)
            metadata.AddExportedType(TypeAttributes.Public, metadata.GetOrAddString(space), metadata.GetOrAddString(name), file, 0);
    };

    /// <summary>
    /// Overwrites, in the file at <paramref name="path"/>, every WHOLE NUL-bounded occurrence of the ASCII
    /// <paramref name="placeholder"/> with <paramref name="bytes"/> (same length) — how a <c>#Strings</c> entry gets bytes
    /// no emitter writes, e.g. invalid UTF-8. Returns the number of entries overwritten (a suffix-shared entry is not
    /// NUL-preceded, so it is never touched: callers assert the count).
    /// </summary>
    public static int PatchString(string path, string placeholder, byte[] bytes)
    {
        var from = System.Text.Encoding.ASCII.GetBytes(placeholder);
        if (bytes.Length != from.Length)
            throw new ArgumentException($"'{placeholder}' is {from.Length} bytes; the patch is {bytes.Length}.", nameof(bytes));
        var image = File.ReadAllBytes(path);
        var count = 0;
        for (var i = 1; i + from.Length < image.Length; i++)
            if (image[i - 1] == 0 && image[i + from.Length] == 0 && image.AsSpan(i, from.Length).SequenceEqual(from))
            {
                bytes.CopyTo(image, i);
                count++;
            }
        File.WriteAllBytes(path, image);
        return count;
    }

    /// <summary>
    /// The file offset and RAW size (alignment padding included) of the <c>#Strings</c> stream, from the metadata root's
    /// stream headers (ECMA-335 II.24.2.1-2) — SRM's <c>GetHeapSize</c> leaves trailing NUL padding out.
    /// </summary>
    public static (int Start, int Size) StringsStream(byte[] image)
    {
        using var pe = new PEReader(new MemoryStream(image));
        var root = pe.PEHeaders.MetadataStartOffset;
        var at = root + 16 + BitConverter.ToInt32(image, root + 12) + 2;
        var streams = BitConverter.ToUInt16(image, at);
        at += 2;
        for (var i = 0; i < streams; i++)
        {
            var (offset, size) = (BitConverter.ToInt32(image, at), BitConverter.ToInt32(image, at + 4));
            var end = Array.IndexOf(image, (byte)0, at + 8);
            var name = System.Text.Encoding.ASCII.GetString(image, at + 8, end - at - 8);
            at = at + 8 + ((end - at - 8 + 4) & ~3);
            if (name == "#Strings")
                return (root + offset, size);
        }
        throw new InvalidOperationException("No #Strings stream.");
    }

    /// <summary>The last entry of the raw <c>#Strings</c> stream (ASCII), ignoring the NULs that end it.</summary>
    public static string LastStringsEntry(byte[] image)
    {
        var (start, size) = StringsStream(image);
        var last = Array.FindLastIndex(image, start + size - 1, size, b => b != 0);
        var first = Array.LastIndexOf(image, (byte)0, last) + 1;
        return System.Text.Encoding.ASCII.GetString(image, first, last - first + 1);
    }

    /// <summary>
    /// Sets every NUL at the end of the raw <c>#Strings</c> stream to <c>X</c>, so its last entry runs unterminated to
    /// the end of the heap. Returns the entry as it was.
    /// </summary>
    public static string UnterminateLastStringsEntry(string path)
    {
        var image = File.ReadAllBytes(path);
        var entry = LastStringsEntry(image);
        var (start, size) = StringsStream(image);
        var from = Array.FindLastIndex(image, start + size - 1, size, b => b != 0) + 1;
        Array.Fill(image, (byte)'X', from, start + size - from);
        File.WriteAllBytes(path, image);
        return entry;
    }

    /// <summary>
    /// As <see cref="Save(string, Action{ModuleBuilder}, Action{MetadataBuilder}, string?)"/> (no extra rows when
    /// <paramref name="addRows"/> is null), but with a public <c>Padding.P…</c> type whose name length is varied until
    /// the raw <c>#Strings</c> stream ends in at least two NULs; then only its LAST byte — alignment padding after the
    /// last terminator — is set to <c>X</c> (review 6 W-C's junk tail).
    /// </summary>
    public string SaveWithJunkStringsPadding(string name, Action<ModuleBuilder> define, Action<MetadataBuilder>? addRows, string subdirectory)
    {
        for (var pad = 0; pad < 4; pad++)
        {
            void Define(ModuleBuilder module)
            {
                define(module);
                module.DefineType("Padding.P" + new string('p', pad), TypeAttributes.Public | TypeAttributes.Class).CreateType();
            }
            var path = addRows is null ? Save(name, Define, $"{subdirectory}-pad{pad}") : Save(name, Define, addRows, $"{subdirectory}-pad{pad}");
            var image = File.ReadAllBytes(path);
            var (start, size) = StringsStream(image);
            if (image[start + size - 1] != 0 || image[start + size - 2] != 0)
                continue;
            image[start + size - 1] = (byte)'X';
            File.WriteAllBytes(path, image);
            return path;
        }
        throw new InvalidOperationException($"No padding length gave {name} a #Strings stream ending in two NULs.");
    }

    /// <summary>A public method on <paramref name="owner"/> taking <paramref name="parameter"/> and returning the constant <paramref name="value"/>.</summary>
    public static MethodBuilder Returning(TypeBuilder owner, string name, Type parameter, int value, bool isStatic = false)
    {
        var method = owner.DefineMethod(
            name,
            MethodAttributes.Public | MethodAttributes.HideBySig | (isStatic ? MethodAttributes.Static : 0),
            typeof(int),
            [parameter]);
        var il = method.GetILGenerator();
        il.Emit(OpCodes.Ldc_I4, value);
        il.Emit(OpCodes.Ret);
        return method;
    }

    /// <summary>
    /// A public static parameterless <c>int</c> method <paramref name="name"/> on <paramref name="callers"/> whose body is
    /// <c>newobj Generic&lt;argument&gt;::.ctor; ldnull|ldc.i4.1; callvirt Generic&lt;argument&gt;::target; ret</c>.
    /// </summary>
    public static void CallThroughInstantiation(
        TypeBuilder callers, string name, TypeBuilder generic, ConstructorBuilder constructor, MethodBuilder target, Type argument)
    {
        var closed = generic.MakeGenericType(argument);
        var il = callers.DefineMethod(name, MethodAttributes.Public | MethodAttributes.Static, typeof(int), Type.EmptyTypes).GetILGenerator();
        il.Emit(OpCodes.Newobj, TypeBuilder.GetConstructor(closed, constructor));
        il.Emit(argument == typeof(int) ? OpCodes.Ldc_I4_1 : OpCodes.Ldnull);
        il.Emit(OpCodes.Callvirt, TypeBuilder.GetMethod(closed, target));
        il.Emit(OpCodes.Ret);
    }

    /// <summary>A public static parameterless <c>int</c> method <paramref name="name"/>: <c>ldnull; call target; ret</c>.</summary>
    public static void CallStatic(TypeBuilder callers, string name, MethodBuilder target)
    {
        var il = callers.DefineMethod(name, MethodAttributes.Public | MethodAttributes.Static, typeof(int), Type.EmptyTypes).GetILGenerator();
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Call, target);
        il.Emit(OpCodes.Ret);
    }

    /// <summary><paramref name="element"/> wrapped in <paramref name="ranks"/> single-dimensional array levels (<c>element[]…[]</c>).</summary>
    public static Type Jagged(Type element, int ranks)
    {
        var type = element;
        for (var i = 0; i < ranks; i++)
            type = type.MakeArrayType();
        return type;
    }

    private string PathFor(string name, string? subdirectory)
    {
        var directory = subdirectory is null ? Directory : System.IO.Directory.CreateDirectory(Path.Combine(Directory, subdirectory)).FullName;
        return Path.Combine(directory, name + ".dll");
    }

    public void Dispose()
    {
        // Best effort: the readers are disposed first by the owning fixture; a file still held (e.g. by an AV scanner)
        // only leaves a stray temp directory behind.
        try
        {
            System.IO.Directory.Delete(Directory, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
    #endregion

    #region Fields
    // ECMA-335 II.23.1.15 TypeAttributes.IsTypeForwarder; System.Reflection.TypeAttributes has no member for it.
    private const TypeAttributes TypeForwarder = (TypeAttributes)0x00200000;
    #endregion
}
