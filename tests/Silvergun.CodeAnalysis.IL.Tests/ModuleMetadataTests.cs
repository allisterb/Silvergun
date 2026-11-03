namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <see cref="ModuleMetadata"/> (A2 S3, spec §6 and decision D3; "S3 outcome"): what Model drops from a module, read
/// with SRM from the file. Over EMITTED assemblies (<see cref="EmittedAssembly"/>; read, never loaded) whose
/// <c>&lt;Module&gt;</c> methods and MethodImpl rows are written by hand: the module initializer and method count, the
/// renamed-implementation count (and the explicit implementations it must not count), the never-<see cref="ModuleMetadata.None"/>
/// failure modes, and <see cref="ModuleMetadata.Merge"/>.
/// </summary>
public sealed class ModuleMetadataTests : IDisposable
{
    #region Constructors
    public ModuleMetadataTests() => emitted = new EmittedAssembly();
    #endregion

    #region Methods
    /// <summary>
    /// A static <c>.cctor</c> on <c>&lt;Module&gt;</c> is a module initializer; the count is every <c>&lt;Module&gt;</c>
    /// method, the initializer included.
    /// </summary>
    [Fact]
    public void Read_AModuleWithAStaticConstructor_HasAModuleInitializer_AndCountsItsMethods()
    {
        var path = emitted.Save("WithInitializer", module =>
        {
            Global(module, ".cctor", MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
            Global(module, "Helper", MethodAttributes.Public | MethodAttributes.Static);
            module.CreateGlobalFunctions();
        });

        var read = ModuleMetadata.Read(path);

        Assert.True(read.IsReadable);
        Assert.True(read.HasModuleInitializer);
        Assert.Equal(2, read.ModuleMethods);
        Assert.Equal(0, read.RenamedImplementations);
    }

    /// <summary>
    /// No module initializer: an assembly whose <c>&lt;Module&gt;</c> is empty, and one whose only global method is a
    /// static method of another name. Readable either way, never Unreadable.
    /// </summary>
    [Fact]
    public void Read_AModuleWithoutAStaticConstructor_HasNone()
    {
        var empty = ModuleMetadata.Read(emitted.Save("Plain", module => module.DefineType("Plain.T", TypeAttributes.Public).CreateType()));
        var helperOnly = ModuleMetadata.Read(emitted.Save("HelperOnly", module =>
        {
            Global(module, "Helper", MethodAttributes.Public | MethodAttributes.Static);
            module.CreateGlobalFunctions();
        }));

        Assert.True(empty.IsReadable);
        Assert.False(empty.HasModuleInitializer);
        Assert.Equal(0, empty.ModuleMethods);
        Assert.True(helperOnly.IsReadable);
        Assert.False(helperOnly.HasModuleInitializer);
        Assert.Equal(1, helperOnly.ModuleMethods);
    }

    /// <summary>
    /// A MethodImpl row whose implementation's name is neither the declared method's nor ends in it (decision D3) is
    /// counted — against an own interface method (a MethodDef declaration) and a platform one (a MemberRef). The C#
    /// explicit-implementation shape (<c>Renames.IThing.Run</c> for <c>Run</c>, <c>System.IDisposable.Dispose</c> for
    /// <c>Dispose</c>) and a same-named override are not: exactly 2 of 5 rows.
    /// </summary>
    [Fact]
    public void Read_CountsRenamedMethodImpls_ButNotExplicitOrSameNamedOnes()
    {
        var path = emitted.Save("Renames", module =>
        {
            var thing = module.DefineType("Renames.IThing", TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract);
            var run = thing.DefineMethod("Run", Abstract, typeof(void), Type.EmptyTypes);
            var dispose = typeof(IDisposable).GetMethod(nameof(IDisposable.Dispose))!;

            var renamed = module.DefineType("Renames.Renamed", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [thing, typeof(IDisposable)]);
            renamed.DefineMethodOverride(Body(renamed.DefineMethod("Execute", Implementation, typeof(void), Type.EmptyTypes)), run);
            renamed.DefineMethodOverride(Body(renamed.DefineMethod("Close", Implementation, typeof(void), Type.EmptyTypes)), dispose);

            var @explicit = module.DefineType("Renames.Explicit", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [thing, typeof(IDisposable)]);
            @explicit.DefineMethodOverride(Body(@explicit.DefineMethod("Renames.IThing.Run", Implementation, typeof(void), Type.EmptyTypes)), run);
            @explicit.DefineMethodOverride(Body(@explicit.DefineMethod("System.IDisposable.Dispose", Implementation, typeof(void), Type.EmptyTypes)), dispose);

            var same = module.DefineType("Renames.Same", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [thing]);
            same.DefineMethodOverride(Body(same.DefineMethod("Run", Implementation, typeof(void), Type.EmptyTypes)), run);

            foreach (var type in new[] { thing, renamed, @explicit, same })
                type.CreateType();
        });

        var read = ModuleMetadata.Read(path);

        Assert.True(read.IsReadable);
        Assert.Equal(2, read.RenamedImplementations);
        Assert.False(read.HasModuleInitializer);
    }

    /// <summary>A null path, a missing file and a file of garbage bytes are each <see cref="ModuleMetadata.Unreadable"/>, never None.</summary>
    [Fact]
    public void Read_ANullPathAMissingFileOrGarbage_IsUnreadable_NeverNone()
    {
        var garbage = Path.Combine(emitted.Directory, "garbage.dll");
        File.WriteAllBytes(garbage, [0x4D, 0x5A, 0x00, 0x01, 0xFF, 0xFE, 0x13, 0x37]);
        var text = Path.Combine(emitted.Directory, "text.dll");
        File.WriteAllText(text, "not a portable executable");

        foreach (var read in new[] { ModuleMetadata.Read(null), ModuleMetadata.Read(Path.Combine(emitted.Directory, "missing.dll")), ModuleMetadata.Read(garbage), ModuleMetadata.Read(text) })
        {
            Assert.Same(ModuleMetadata.Unreadable, read);
            Assert.NotSame(ModuleMetadata.None, read);
            Assert.False(read.IsReadable);
        }
        Assert.True(ModuleMetadata.None.IsReadable);
    }

    /// <summary>
    /// <see cref="ModuleMetadata.Merge"/>, for one name loaded more than once: no copies is None; any unreadable (or
    /// missing, null) copy makes the merge unreadable; otherwise any copy's initializer counts and the counts are the most
    /// any copy reports.
    /// </summary>
    [Fact]
    public void Merge_IsUnreadableIfAnyCopyIs_OtherwiseTheMostAnyCopyReports()
    {
        Assert.Same(ModuleMetadata.None, ModuleMetadata.Merge([]));
        Assert.Same(ModuleMetadata.Unreadable, ModuleMetadata.Merge([ModuleMetadata.Of(true, 1, 0), ModuleMetadata.Unreadable]));
        Assert.Same(ModuleMetadata.Unreadable, ModuleMetadata.Merge([ModuleMetadata.Of(true, 1, 0), null]));

        var merged = ModuleMetadata.Merge([ModuleMetadata.Of(false, 2, 5), ModuleMetadata.None, ModuleMetadata.Of(true, 3, 1)]);

        Assert.Equal((true, true, 3, 5), (merged.IsReadable, merged.HasModuleInitializer, merged.ModuleMethods, merged.RenamedImplementations));
        var none = ModuleMetadata.Merge([ModuleMetadata.None, ModuleMetadata.None]);
        Assert.Equal((true, false, 0, 0), (none.IsReadable, none.HasModuleInitializer, none.ModuleMethods, none.RenamedImplementations));
    }

    /// <summary><see cref="ModuleMetadata.Of"/> is readable and clamps negative counts to zero.</summary>
    [Fact]
    public void Of_IsReadable_AndClampsNegativeCounts()
    {
        var of = ModuleMetadata.Of(false, -1, -2);

        Assert.Equal((true, false, 0, 0), (of.IsReadable, of.HasModuleInitializer, of.ModuleMethods, of.RenamedImplementations));
    }

    // ---- hand-built MethodImpl tables (S3 review 1) --------------------------------------------------------------------

    /// <summary>
    /// W1: many MethodImpl rows sharing one long name are judged per pair of name strings. 2,000 rows naming one
    /// 2,000-character body against <c>Decl</c> are all renamed; 2,000 rows whose body and declaration share that one
    /// long name are all not. (No cost pin: a robust one is not available here, so this pins the counts only.)
    /// </summary>
    [Theory]
    [InlineData(false, 2000)]
    [InlineData(true, 0)]
    public void Read_ManyRowsSharingOneLongName_AreCountedPerRow(bool sameName, int renamed)
    {
        var name = new string('x', 2000);
        var rows = Enumerable.Repeat((Body: 2, Declared: 3), 2000).ToArray();

        var read = ModuleMetadata.Read(HandBuilt($"long-{sameName}", [name, sameName ? name : "Decl"], rows));

        Assert.True(read.IsReadable);
        Assert.True(read.HasModuleInitializer);
        Assert.Equal(renamed, read.RenamedImplementations);
    }

    /// <summary>
    /// W2: a MethodImpl row whose body is an out-of-range MethodDef (row 9999) counts as renamed, and no longer costs
    /// the module its readability: the module initializer is still known. The valid row beside it, whose body and
    /// declaration share a name, is judged normally (not renamed).
    /// </summary>
    [Fact]
    public void Read_AMalformedMethodImplRow_CountsAsRenamed_AndTheModuleStaysReadable()
    {
        var read = ModuleMetadata.Read(HandBuilt("badrow", ["Run", "Run"], [(2, 3), (9999, 3)]));

        Assert.True(read.IsReadable);
        Assert.True(read.HasModuleInitializer);
        Assert.Equal(1, read.ModuleMethods);
        Assert.Equal(1, read.RenamedImplementations);
    }

    /// <summary>
    /// N3: an implementation name that is not valid UTF-8 (decoded to U+FFFD) counts as renamed — even against a
    /// declaration of the very same (invalid) name, which would otherwise compare equal. The unpatched control is not
    /// renamed, so the count comes from the U+FFFD rule alone.
    /// </summary>
    [Fact]
    public void Read_AnImplementationNameOfInvalidUtf8_CountsAsRenamed()
    {
        var control = HandBuilt("utf8-control", ["QQQQ", "QQQQ"], [(2, 3)]);
        var patched = HandBuilt("utf8-patched", ["QQQQ", "QQQQ"], [(2, 3)]);
        Assert.Equal(1, EmittedAssembly.PatchString(patched, "QQQQ", [0xFF, 0xFE, 0xFD, 0xFC]));

        Assert.Equal(0, ModuleMetadata.Read(control).RenamedImplementations);
        var read = ModuleMetadata.Read(patched);
        Assert.True(read.IsReadable);
        Assert.Equal(1, read.RenamedImplementations);
    }

    /// <summary>
    /// N6: the implemented-name rule is applied to BOTH names, as CHA applies it. A declaration whose name has a
    /// top-level dot (<c>Prefix.Run</c>) implemented by <c>Run</c> or by <c>Other.Run</c> is not renamed; by <c>Walk</c>
    /// it is: 1 of 3 rows.
    /// </summary>
    [Fact]
    public void Read_ADeclaredNameWithATopLevelDot_IsComparedByItsImplementedName()
    {
        // MethodDef rows: 1 <Module>..cctor, 2 Run, 3 Prefix.Run, 4 Other.Run, 5 Walk.
        var read = ModuleMetadata.Read(HandBuilt("dotted", ["Run", "Prefix.Run", "Other.Run", "Walk"], [(2, 3), (4, 3), (5, 3)]));

        Assert.True(read.IsReadable);
        Assert.Equal(1, read.RenamedImplementations);
    }

    public void Dispose() => emitted.Dispose();

    // A PE written row by row with MetadataBuilder (after the S3 review probe; written, never loaded): MethodDef row 1
    // is <Module>'s static .cctor, rows 2.. are `methods` on class P.C, and one MethodImpl row (class C) per entry of
    // `rows`, naming MethodDef rows by number (out of range allowed). Saved in this test's temporary directory.
    private string HandBuilt(string name, string[] methods, (int Body, int Declared)[] rows)
    {
        var md = new MetadataBuilder();
        md.AddModule(0, md.GetOrAddString($"{name}.dll"), md.GetOrAddGuid(Guid.NewGuid()), default, default);
        md.AddAssembly(md.GetOrAddString(name), new Version(1, 0), default, default, 0, AssemblyHashAlgorithm.Sha1);
        var corlib = md.AddAssemblyReference(md.GetOrAddString("System.Runtime"), new Version(10, 0), default, default, 0, default);
        var objectRef = md.AddTypeReference(corlib, md.GetOrAddString("System"), md.GetOrAddString("Object"));

        var staticSignature = new BlobBuilder();
        new BlobEncoder(staticSignature).MethodSignature().Parameters(0, r => r.Void(), p => { });
        var instanceSignature = new BlobBuilder();
        new BlobEncoder(instanceSignature).MethodSignature(isInstanceMethod: true).Parameters(0, r => r.Void(), p => { });

        md.AddMethodDefinition(MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
            MethodImplAttributes.IL, md.GetOrAddString(".cctor"), md.GetOrAddBlob(staticSignature), -1, default);
        foreach (var method in methods)
            md.AddMethodDefinition(MethodAttributes.Public | MethodAttributes.Virtual, MethodImplAttributes.IL,
                md.GetOrAddString(method), md.GetOrAddBlob(instanceSignature), -1, default);

        md.AddTypeDefinition(default, default, md.GetOrAddString("<Module>"), default,
            MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(1));
        var type = md.AddTypeDefinition(TypeAttributes.Public | TypeAttributes.Class, md.GetOrAddString("P"), md.GetOrAddString("C"), objectRef,
            MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(2));
        foreach (var (body, declared) in rows)
            md.AddMethodImplementation(type, MetadataTokens.MethodDefinitionHandle(body), MetadataTokens.MethodDefinitionHandle(declared));

        var pe = new ManagedPEBuilder(PEHeaderBuilder.CreateLibraryHeader(), new MetadataRootBuilder(md, suppressValidation: true), new BlobBuilder());
        var blob = new BlobBuilder();
        pe.Serialize(blob);
        var path = Path.Combine(emitted.Directory, $"{name}.dll");
        File.WriteAllBytes(path, blob.ToArray());
        return path;
    }

    // A global (<Module>) method with an empty body.
    private static void Global(ModuleBuilder module, string name, MethodAttributes attributes) =>
        module.DefineGlobalMethod(name, attributes, typeof(void), Type.EmptyTypes).GetILGenerator().Emit(OpCodes.Ret);

    private static MethodBuilder Body(MethodBuilder method)
    {
        method.GetILGenerator().Emit(OpCodes.Ret);
        return method;
    }
    #endregion

    #region Fields
    private const MethodAttributes Abstract = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.Abstract | MethodAttributes.NewSlot;
    private const MethodAttributes Implementation = MethodAttributes.Private | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Final;

    private readonly EmittedAssembly emitted;
    #endregion
}
