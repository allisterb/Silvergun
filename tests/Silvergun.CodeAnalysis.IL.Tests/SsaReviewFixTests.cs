namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

using Cilica.AsmIO;

using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// The SSA adapter's S2 review fixes (docs/agent/tasks/ssa-adapter.md), on small fixtures written row by row: primitives
/// only from the framework (C1), ambiguous type names (W8), exact forwarders (W7), per-assembly stub encodings (W2), no
/// stub fields through a folder type (N3), shared RVA data (W5), and bound validation. The hostile ones (cycles, deep
/// chains, own core libraries) are in <see cref="SsaHostileShapeTests"/>, in a child process.
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaReviewFixTests
{
    #region Methods
    // ---- C1: primitives ----------------------------------------------------------------------------------------------

    /// <summary><c>[Evil]System.Int32</c>, in an assembly whose core is System.Runtime, is a type named Int32 in a stub, not int.</summary>
    [Fact]
    public void ATypeRefToSystemInt32_InANonFrameworkAssembly_IsNotThePrimitive()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("EvilIntUser");
        raw.TypeRef(raw.Runtime, "System", "String");
        raw.TypeRef(raw.Runtime, "System", "ValueType");
        var evilInt = raw.TypeRef(raw.AssemblyRef("Evil"), "System", "Int32");
        raw.Type("Users", "User", raw.Object);
        raw.Static("TokenOfEvilInt", StaticVoid, il =>
        {
            il.OpCode(ILOpCode.Ldtoken);
            il.Token(evilInt);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
        });

        using var lifted = new SsaLifted([raw.Save(temp.Path)]);

        var operand = Operand(lifted.Il("User", "TokenOfEvilInt"), ILCode.Ldtoken);
        Assert.NotSame(PrimType.Int32, operand);
        var type = Assert.IsAssignableFrom<TypeDefOrSpec>(operand);
        Assert.Equal(("System", "Int32", "Evil [stub]"), (type.Namespace, type.Name, type.Module.AsmName.Name));
    }

    // ---- W8: ambiguous names -----------------------------------------------------------------------------------------

    /// <summary>A reference by name to a type its assembly defines twice cannot say which: an unresolved type.</summary>
    [Fact]
    public void AReferenceByName_ToATypeDefinedTwice_IsAnUnresolvedType()
    {
        using var temp = new SsaTempDirectory();
        var dupes = new RawAssembly("Dupes2");
        dupes.Type("Dup", "Twin", dupes.Object);
        dupes.Type("Dup", "Twin", dupes.Object);
        var user = new RawAssembly("DupUser");
        var twin = user.TypeRef(user.AssemblyRef("Dupes2"), "Dup", "Twin");
        user.Type("Users", "User", user.Object);
        user.Static("TokenOfTwin", StaticVoid, TokenOf(twin));
        user.Static("Plain", StaticInt, Returns42);

        using var lifted = new SsaLifted([dupes.Save(temp.Path), user.Save(temp.Path)]);

        SsaLifted.AssertFailed(lifted.Of("User", "TokenOfTwin"), SsaFailureKind.UnresolvedFact, "defined more than once");
        SsaLifted.AssertLifted(lifted.Of("User", "Plain"));
    }

    // ---- W7: exact forwarders ----------------------------------------------------------------------------------------

    /// <summary>
    /// <c>Fwd</c> forwards <c>Dep.Foo`2</c> to <c>DepImpl</c>, which defines both <c>Foo`1</c> and <c>Foo`2</c>: the
    /// forwarder satisfies <c>[Fwd]Dep.Foo`2</c> only. A match by name without arity would have found <c>Foo`1</c>.
    /// </summary>
    [Fact]
    public void AForwarder_SatisfiesOnlyTheArityItNames()
    {
        using var temp = new SsaTempDirectory();
        var implementation = new RawAssembly("DepImpl");
        var one = implementation.Type("Dep", "Foo`1", implementation.Object);
        var two = implementation.Type("Dep", "Foo`2", implementation.Object);
        implementation.GenericParameter(one, "T", 0);
        implementation.GenericParameter(two, "T1", 0);
        implementation.GenericParameter(two, "T2", 1);
        var forwarder = new RawAssembly("Fwd");
        var user = new RawAssembly("FwdUser");
        var fwd = user.AssemblyRef("Fwd");
        var fooOne = user.TypeRef(fwd, "Dep", "Foo`1");
        var fooTwo = user.TypeRef(fwd, "Dep", "Foo`2");
        user.Type("Users", "User", user.Object);
        user.Static("TokenOfFooOne", StaticVoid, TokenOf(fooOne));
        user.Static("TokenOfFooTwo", StaticVoid, TokenOf(fooTwo));

        using var lifted = new SsaLifted(
        [
            implementation.Save(temp.Path),
            forwarder.Save(temp.Path, EmittedAssembly.Forwarding(("Dep", "Foo`2", "DepImpl"))),
            user.Save(temp.Path),
        ]);

        SsaLifted.AssertFailed(lifted.Of("User", "TokenOfFooOne"), SsaFailureKind.UnresolvedFact, "Unresolved Type of 'Dep.Foo`1'");
        var resolved = Assert.IsType<TypeDef>(Operand(lifted.Il("User", "TokenOfFooTwo"), ILCode.Ldtoken));
        Assert.Equal("Foo`2", resolved.Name);
        Assert.StartsWith("DepImpl [", resolved.Module.AsmName.Name);
    }

    [Fact]
    public void ANameForwardedToTwoAssemblies_IsAnUnresolvedType()
    {
        using var temp = new SsaTempDirectory();
        var forwarder = new RawAssembly("Fwd2");
        var user = new RawAssembly("Fwd2User");
        var bar = user.TypeRef(user.AssemblyRef("Fwd2"), "Dep", "Bar");
        user.Type("Users", "User", user.Object);
        user.Static("TokenOfBar", StaticVoid, TokenOf(bar));
        user.Static("Plain", StaticInt, Returns42);
        var paths = new List<string>();
        foreach (var name in new[] { "DepA", "DepB" })
        {
            var target = new RawAssembly(name);
            target.Type("Dep", "Bar", target.Object);
            paths.Add(target.Save(temp.Path));
        }
        paths.Add(forwarder.Save(temp.Path, metadata =>
        {
            EmittedAssembly.Forward(metadata, "Dep", "Bar", EmittedAssembly.Reference(metadata, "DepA"));
            EmittedAssembly.Forward(metadata, "Dep", "Bar", EmittedAssembly.Reference(metadata, "DepB"));
        }));
        paths.Add(user.Save(temp.Path));

        using var lifted = new SsaLifted(paths);

        SsaLifted.AssertFailed(lifted.Of("User", "TokenOfBar"), SsaFailureKind.UnresolvedFact, "forwarded to more than one assembly");
        SsaLifted.AssertLifted(lifted.Of("User", "Plain"));
    }

    // ---- W2: stub encodings are per assembly -------------------------------------------------------------------------

    /// <summary>A signature encoding <c>[A]N.T</c> as CLASS proves nothing about <c>[B]N.T</c>, a different type.</summary>
    [Fact]
    public void AStubsEncoding_ComesOnlyFromReferencesToItsOwnAssembly()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("TwoMissing");
        var inA = raw.TypeRef(raw.AssemblyRef("A"), "N", "T");
        var inB = raw.TypeRef(raw.AssemblyRef("B"), "N", "T");
        var ctorA = raw.MemberRef(inA, ".ctor", RawAssembly.MethodSig(true, r => r.Void()));
        var ctorB = raw.MemberRef(inB, ".ctor", RawAssembly.MethodSig(true, r => r.Void()));
        raw.Type("Users", "User", raw.Object);
        raw.Static("EncodesA", RawAssembly.MethodSig(false, r => r.Void(), p => p.Type(inA, isValueType: false)), il => il.OpCode(ILOpCode.Ret));
        raw.Static("NewA", StaticObject, NewObject(ctorA));
        raw.Static("NewB", StaticObject, NewObject(ctorB));

        using var lifted = new SsaLifted([raw.Save(temp.Path)]);

        SsaLifted.AssertLifted(lifted.Of("User", "NewA"));
        SsaLifted.AssertFailed(lifted.Of("User", "NewB"), SsaFailureKind.UnresolvedFact, "Unresolved ValueTypeness of 'N.T'");
    }

    // ---- N3: no stub fields through a folder type --------------------------------------------------------------------

    /// <summary>
    /// <c>Derived : [Missing]Missing.Base</c>. A reference to <c>Missing.Base::F</c> makes a stub field; a reference to
    /// <c>Derived::F</c> must not find it: a stub's fields are only what other references named, which proves nothing
    /// about what <c>Derived</c> inherits.
    /// </summary>
    [Fact]
    public void AFieldOfAFolderType_IsNotFoundInAStubAncestor()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("Inherits");
        var missingBase = raw.TypeRef(raw.AssemblyRef(SsaStubFixture.MissingAssembly), "Missing", "Base");
        var derived = raw.NextType();
        var viaBase = raw.MemberRef(missingBase, "F", RawAssembly.FieldSig(t => t.Int32()));
        var viaDerived = raw.MemberRef(derived, "F", RawAssembly.FieldSig(t => t.Int32()));
        raw.Type("Users", "Derived", missingBase);
        raw.Type("Users", "User", raw.Object);
        raw.Static("EncodesBase", RawAssembly.MethodSig(false, r => r.Void(), p => p.Type(missingBase, isValueType: false)), il => il.OpCode(ILOpCode.Ret));
        raw.Static("ViaStub", StaticInt, LoadStatic(viaBase));
        raw.Static("ViaDerived", StaticInt, LoadStatic(viaDerived));

        using var lifted = new SsaLifted([raw.Save(temp.Path)]);

        SsaLifted.AssertLifted(lifted.Of("User", "ViaStub"));
        SsaLifted.AssertFailed(lifted.Of("User", "ViaDerived"), SsaFailureKind.UnresolvedFact, "no field 'F'");
    }

    // ---- W5: RVA data ------------------------------------------------------------------------------------------------

    /// <summary>Two RVA fields aliasing one block of data share one copy of it.</summary>
    [Fact]
    public void RvaFieldsAliasingOneBlock_ShareTheirData()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("Rva");
        var offset = raw.MappedData([1, 2, 3, 4, 5, 6, 7, 8]);
        raw.Type("Data", "Blocks", raw.Object);
        const FieldAttributes Rva = FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRVA;
        var a = raw.Field("A", Rva, t => t.Int64());
        var b = raw.Field("B", Rva, t => t.Int64());
        raw.FieldRva(a, offset);
        raw.FieldRva(b, offset);
        raw.Static("Read", RawAssembly.MethodSig(false, r => r.Type().Int64()), il =>
        {
            il.OpCode(ILOpCode.Ldsfld);
            il.Token(a);
            il.OpCode(ILOpCode.Ldsfld);
            il.Token(b);
            il.OpCode(ILOpCode.Add);
            il.OpCode(ILOpCode.Ret);
        });

        using var lifted = new SsaLifted([raw.Save(temp.Path)]);

        var fields = lifted.Il("Blocks", "Read").Instructions.Where(i => i.OpCode == ILCode.Ldsfld).Select(i => Assert.IsType<FieldDef>(i.Operand)).ToArray();
        Assert.Equal(["A", "B"], fields.Select(f => f.Name));
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, fields[0].MappedData);
        Assert.Same(fields[0].MappedData, fields[1].MappedData);
    }

    // ---- Round 2 -----------------------------------------------------------------------------------------------------

    /// <summary>R2-C1: <c>coreclr</c> is not a framework assembly (only managed files of the runtime directory are), so a folder one binds.</summary>
    [Fact]
    public void AFolderAssemblyNamedLikeANativeRuntimeFile_BindsAsAFolderAssembly()
    {
        using var temp = new SsaTempDirectory();
        var coreclr = new RawAssembly("coreclr");
        coreclr.Type("Native", "Thing", coreclr.Object);
        var user = new RawAssembly("CoreclrUser");
        var thing = user.TypeRef(user.AssemblyRef("coreclr"), "Native", "Thing");
        user.Type("Users", "User", user.Object);
        user.Static("TokenOfThing", StaticVoid, TokenOf(thing));

        using var lifted = new SsaLifted([coreclr.Save(temp.Path), user.Save(temp.Path)]);

        var resolved = Assert.IsType<TypeDef>(Operand(lifted.Il("User", "TokenOfThing"), ILCode.Ldtoken));
        Assert.StartsWith("coreclr [", resolved.Module.AsmName.Name);
    }

    /// <summary>
    /// R2-W3: the only evidence that <c>Gen`1</c> is used with two arguments sits in a local-variable signature of over
    /// 1 KB (1,100 int32 locals and one <c>Gen`1&lt;int32, int32&gt;</c>). It is still read, so every use of that row fails.
    /// </summary>
    [Fact]
    public void ATruncatedInstantiation_InALongLocalsSignature_StillFailsAsArity()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("LongLocals");
        var generic = raw.TypeRef(raw.AssemblyRef(SsaStubFixture.MissingAssembly), "Missing", "Gen`1");
        var ofOne = raw.TypeSpec(t => t.GenericInstantiation(generic, 1, isValueType: false).AddArgument().Int32());
        raw.Type("Users", "User", raw.Object);
        raw.Method("ManyLocals", MethodAttributes.Public | MethodAttributes.Static, StaticVoid, il => il.OpCode(ILOpCode.Ret), locals =>
        {
            for (var i = 0; i < 1_100; i++)
                locals.AddVariable().Type().Int32();
            var arguments = locals.AddVariable().Type().GenericInstantiation(generic, 2, isValueType: false);
            arguments.AddArgument().Int32();
            arguments.AddArgument().Int32();
        }, localCount: 1_101);
        raw.Static("CastsOfOne", StaticObject, il =>
        {
            il.OpCode(ILOpCode.Ldnull);
            il.OpCode(ILOpCode.Castclass);
            il.Token(ofOne);
            il.OpCode(ILOpCode.Ret);
        });

        using var lifted = new SsaLifted([raw.Save(temp.Path)]);

        SsaLifted.AssertFailed(lifted.Of("User", "CastsOfOne"), SsaFailureKind.UnresolvedFact, "Unresolved Arity of 'Missing.Gen`1'");
        SsaLifted.AssertFailed(lifted.Of("User", "ManyLocals"), SsaFailureKind.UnresolvedFact, "Unresolved Arity of 'Missing.Gen`1'");
    }

    /// <summary>R2-W3: a blob outside the grammar is counted, not ignored; a module without one counts none.</summary>
    [Fact]
    public void ScanEncodings_CountsTheBlobsItCannotParse()
    {
        using var temp = new SsaTempDirectory();
        var broken = new RawAssembly("Unparsed");
        broken.TypeSpecBytes([0xFF]);
        var clean = new RawAssembly("Clean");
        clean.TypeSpecBytes([.. Enumerable.Repeat((byte)0x1D, 5_000), 0x08]);

        using var brokenFacts = MetadataFacts.Open(broken.Save(temp.Path));
        using var cleanFacts = MetadataFacts.Open(clean.Save(temp.Path));
        brokenFacts.ScanEncodings(SsaBounds.Default);
        cleanFacts.ScanEncodings(SsaBounds.Default);

        Assert.True(brokenFacts.UnparsedSignatures > 0);
        Assert.Equal(0, cleanFacts.UnparsedSignatures);
    }

    /// <summary>R2-W4: once <see cref="SsaBounds.MaxMappedDataBytesPerAssembly"/> is spent, a further field gets no data.</summary>
    [Fact]
    public void RvaData_PastThePerAssemblyBudget_IsNotRead()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("RvaBudget");
        var first = raw.MappedData([1, 2, 3, 4, 5, 6, 7, 8]);
        var second = raw.MappedData([9, 10, 11, 12, 13, 14, 15, 16]);
        raw.Type("Data", "Blocks", raw.Object);
        const FieldAttributes Rva = FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRVA;
        var a = raw.Field("A", Rva, t => t.Int64());
        var b = raw.Field("B", Rva, t => t.Int64());
        raw.FieldRva(a, first);
        raw.FieldRva(b, second);
        raw.Static("Read", RawAssembly.MethodSig(false, r => r.Type().Int64()), il =>
        {
            il.OpCode(ILOpCode.Ldsfld);
            il.Token(a);
            il.OpCode(ILOpCode.Ldsfld);
            il.Token(b);
            il.OpCode(ILOpCode.Add);
            il.OpCode(ILOpCode.Ret);
        });

        using var lifted = new SsaLifted([raw.Save(temp.Path)], SsaBounds.Default with { MaxMappedDataBytesPerAssembly = 8 });

        var fields = lifted.Il("Blocks", "Read").Instructions.Where(i => i.OpCode == ILCode.Ldsfld).Select(i => Assert.IsType<FieldDef>(i.Operand)).ToArray();
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, fields[0].MappedData);
        Assert.Null(fields[1].MappedData);
    }

    /// <summary>R2-N2: a TypeRef scoped to its own module that names a type defined twice there is ambiguous too.</summary>
    [Fact]
    public void AModuleScopedReference_ToATypeDefinedTwice_IsAnUnresolvedType()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("Dupes3");
        var twin = raw.TypeRef(EntityHandle.ModuleDefinition, "Dup", "Twin");
        raw.Type("Dup", "Twin", raw.Object);
        raw.Type("Dup", "Twin", raw.Object);
        raw.Type("Users", "User", raw.Object);
        raw.Static("TokenOfTwin", StaticVoid, TokenOf(twin));
        raw.Static("Plain", StaticInt, Returns42);

        using var lifted = new SsaLifted([raw.Save(temp.Path)]);

        SsaLifted.AssertFailed(lifted.Of("User", "TokenOfTwin"), SsaFailureKind.UnresolvedFact, "defined more than once");
        SsaLifted.AssertLifted(lifted.Of("User", "Plain"));
    }

    // ---- Round 3 -----------------------------------------------------------------------------------------------------

    /// <summary>
    /// R3-W1: a StandAloneSig row holding a FIELD signature (C++/CLI emits them) is within the grammar, so the module's
    /// instantiation counts stay proven and its generic cast lifts.
    /// </summary>
    [Fact]
    public void AFieldSignatureInAStandAloneSigRow_IsParsed_AndGenericsStillLift()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("FieldSigRow");
        raw.StandaloneSignature([0x06, 0x08]);
        var action = raw.TypeRef(raw.Runtime, "System", "Action`1");
        raw.Type("Users", "User", raw.Object);
        raw.Static("CastsAction", StaticObject, CastNullTo(raw.TypeSpec(t => t.GenericInstantiation(action, 1, isValueType: false).AddArgument().Int32())));
        var path = raw.Save(temp.Path);

        Assert.Equal(0, Unparsed(path));
        using var lifted = new SsaLifted([path]);
        SsaLifted.AssertLifted(lifted.Of("User", "CastsAction"));
    }

    /// <summary>R3-W1: a local-variable signature with a trailing ELEMENT_TYPE_END byte after its one local is accepted.</summary>
    [Fact]
    public void ALocalsSignatureWithATrailingByte_IsParsed_AndTheMethodLifts()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("TrailingByte");
        raw.Type("Users", "User", raw.Object);
        raw.Method("OneLocal", MethodAttributes.Public | MethodAttributes.Static, StaticInt, il =>
        {
            il.LoadConstantI4(1);
            il.StoreLocal(0);
            il.LoadLocal(0);
            il.OpCode(ILOpCode.Ret);
        }, localSignature: [0x07, 0x01, 0x08, 0x00]);
        var path = raw.Save(temp.Path);

        Assert.Equal(0, Unparsed(path));
        using var lifted = new SsaLifted([path]);
        var local = Assert.Single(lifted.Il("User", "OneLocal").Locals);
        Assert.Same(PrimType.Int32, local.Type);
    }

    /// <summary>
    /// R3-W3: an RVA field of a 12-byte struct (ClassLayout size 12), whose data block runs on for 64 bytes, gets exactly
    /// its 12 bytes.
    /// </summary>
    [Fact]
    public void RvaData_IsTheFieldsLayoutSize_NotTheRestOfTheBlock()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("RvaLayout");
        var block = Enumerable.Range(1, 64).Select(i => (byte)i).ToArray();
        var offset = raw.MappedData(block);
        var twelve = raw.Type("Data", "Twelve", raw.TypeRef(raw.Runtime, "System", "ValueType"),
            TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.SequentialLayout);
        raw.Layout(twelve, 12);
        raw.Type("Data", "Blocks", raw.Object);
        var field = raw.Field("F", FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRVA, t => t.Type(twelve, isValueType: true));
        raw.FieldRva(field, offset);
        raw.Static("Touch", StaticVoid, il =>
        {
            il.OpCode(ILOpCode.Ldsflda);
            il.Token(field);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
        });

        using var lifted = new SsaLifted([raw.Save(temp.Path)]);

        var data = Assert.IsType<FieldDef>(Operand(lifted.Il("Blocks", "Touch"), ILCode.Ldsflda)).MappedData;
        Assert.Equal(block[..12], data);
    }

    /// <summary>
    /// R4-W1: a field whose wanted size (its 64-byte ClassLayout) is over <see cref="SsaBounds.MaxMappedDataBytes"/> (16)
    /// is refused before anything is read: no data. A 12-byte sibling in the same assembly still gets its bytes.
    /// </summary>
    [Fact]
    public void RvaData_OverThePerFieldCap_IsRefused_WhileASmallerSiblingIsRead()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("RvaCap");
        var bigBlock = Enumerable.Range(1, 64).Select(i => (byte)i).ToArray();
        var smallBlock = Enumerable.Range(101, 12).Select(i => (byte)i).ToArray();
        var bigOffset = raw.MappedData(bigBlock);
        var smallOffset = raw.MappedData(smallBlock);
        var valueType = raw.TypeRef(raw.Runtime, "System", "ValueType");
        const TypeAttributes Struct = TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.SequentialLayout;
        var sixtyFour = raw.Type("Data", "SixtyFour", valueType, Struct);
        raw.Layout(sixtyFour, 64);
        var twelve = raw.Type("Data", "Twelve", valueType, Struct);
        raw.Layout(twelve, 12);
        raw.Type("Data", "Blocks", raw.Object);
        const FieldAttributes Rva = FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRVA;
        var big = raw.Field("Big", Rva, t => t.Type(sixtyFour, isValueType: true));
        var small = raw.Field("Small", Rva, t => t.Type(twelve, isValueType: true));
        raw.FieldRva(big, bigOffset);
        raw.FieldRva(small, smallOffset);
        raw.Static("Touch", StaticVoid, il =>
        {
            il.OpCode(ILOpCode.Ldsflda);
            il.Token(big);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ldsflda);
            il.Token(small);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
        });

        using var lifted = new SsaLifted([raw.Save(temp.Path)], SsaBounds.Default with { MaxMappedDataBytes = 16 });

        var fields = lifted.Il("Blocks", "Touch").Instructions.Where(i => i.OpCode == ILCode.Ldsflda).Select(i => Assert.IsType<FieldDef>(i.Operand)).ToArray();
        Assert.Equal(["Big", "Small"], fields.Select(f => f.Name));
        Assert.Null(fields[0].MappedData);
        Assert.Equal(smallBlock, fields[1].MappedData);
    }

    /// <summary>
    /// R3-N1: a vararg call site (a MemberRef whose signature has a SENTINEL) and an unmanaged function-pointer
    /// <c>calli</c> (calling convention 9, a <c>modopt(CallConvCdecl)</c> on the return) are within the grammar. The
    /// vararg call lifts, or fails only in Cilica's importer.
    /// </summary>
    [Fact]
    public void AVarargCallSite_AndAnUnmanagedCalliSignature_AreParsed()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("Varargs");
        var cdecl = raw.TypeRef(raw.Runtime, "System.Runtime.CompilerServices", "CallConvCdecl");
        var unmanaged = new BlobBuilder();
        unmanaged.WriteByte(0x09);
        unmanaged.WriteCompressedInteger(1);
        unmanaged.WriteByte(0x20);
        unmanaged.WriteCompressedInteger(CodedIndex.TypeDefOrRefOrSpec(cdecl));
        unmanaged.WriteByte(0x08);
        unmanaged.WriteByte(0x08);
        var calliSignature = raw.StandaloneSignature(unmanaged.ToArray());
        raw.Type("Users", "User", raw.Object);
        var vararg = raw.Method("VA", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, Bytes(0x05, 0x01, 0x01, 0x08),
            il => il.OpCode(ILOpCode.Ret));
        var site = raw.MemberRef(vararg, "VA", Bytes(0x05, 0x02, 0x01, 0x08, 0x41, 0x08));
        raw.Static("CallsVarargs", StaticVoid, il =>
        {
            il.LoadConstantI4(1);
            il.LoadConstantI4(2);
            il.Call(site);
            il.OpCode(ILOpCode.Ret);
        });
        raw.Static("CallsUnmanaged", StaticInt, il =>
        {
            il.LoadConstantI4(5);
            il.LoadConstantI4(0);
            il.OpCode(ILOpCode.Conv_i);
            il.OpCode(ILOpCode.Calli);
            il.Token(calliSignature);
            il.OpCode(ILOpCode.Ret);
        });
        var path = raw.Save(temp.Path);

        Assert.Equal(0, Unparsed(path));
        using var lifted = new SsaLifted([path]);
        var call = lifted.Of("User", "CallsVarargs");
        Assert.True(call.IsLifted || call.Failure!.Kind == SsaFailureKind.Import, SsaText.Of(call));
        var calli = lifted.Of("User", "CallsUnmanaged");
        Assert.False(calli.Failure?.Kind is SsaFailureKind.UnresolvedFact, SsaText.Of(calli));
        Assert.DoesNotContain("differing numbers", calli.Failure?.Reason ?? "", StringComparison.Ordinal);
    }

    // The scan's count of unparsable signature blobs in one file.
    private static int Unparsed(string path)
    {
        using var facts = MetadataFacts.Open(path);
        facts.ScanEncodings(SsaBounds.Default);
        return facts.UnparsedSignatures;
    }

    private static BlobBuilder Bytes(params byte[] bytes)
    {
        var blob = new BlobBuilder();
        blob.WriteBytes(bytes);
        return blob;
    }

    private static Action<InstructionEncoder> CastNullTo(EntityHandle type) => il =>
    {
        il.OpCode(ILOpCode.Ldnull);
        il.OpCode(ILOpCode.Castclass);
        il.Token(type);
        il.OpCode(ILOpCode.Ret);
    };

    // ---- Bounds ------------------------------------------------------------------------------------------------------

    public static TheoryData<string> NonPositiveBounds() => new(nameof(SsaBounds.MaxDepth), nameof(SsaBounds.MaxInstructions),
        nameof(SsaBounds.MaxExceptionClauses), nameof(SsaBounds.MaxMappedDataBytes), nameof(SsaBounds.MaxNesting),
        nameof(SsaBounds.MaxForwarderHops), nameof(SsaBounds.MaxMappedDataBytesPerAssembly));

    [Theory]
    [MemberData(nameof(NonPositiveBounds))]
    public void Validated_ANonPositiveBound_Throws_AndOpenRejectsIt(string bound)
    {
        foreach (var value in new long[] { 0, -1 })
        {
            var bounds = With(bound, value);

            Assert.Throws<ArgumentOutOfRangeException>(() => bounds.Validated());
            Assert.Throws<ArgumentOutOfRangeException>(() => SsaSession.Open([], bounds));
        }
    }

    [Fact]
    public void Validated_TheDefaults_AreValid() => Assert.Same(SsaBounds.Default, SsaBounds.Default.Validated());

    // A copy of the defaults with one bound set (the record's init-only property, through reflection on the clone).
    private static SsaBounds With(string bound, long value)
    {
        var copy = SsaBounds.Default with { };
        var property = typeof(SsaBounds).GetProperty(bound)!;
        property.SetValue(copy, property.PropertyType == typeof(long) ? value : (object)(int)value);
        return copy;
    }

    // ---- Helpers -----------------------------------------------------------------------------------------------------

    private static Action<InstructionEncoder> TokenOf(EntityHandle type) => il =>
    {
        il.OpCode(ILOpCode.Ldtoken);
        il.Token(type);
        il.OpCode(ILOpCode.Pop);
        il.OpCode(ILOpCode.Ret);
    };

    private static Action<InstructionEncoder> NewObject(EntityHandle constructor) => il =>
    {
        il.OpCode(ILOpCode.Newobj);
        il.Token(constructor);
        il.OpCode(ILOpCode.Ret);
    };

    private static Action<InstructionEncoder> LoadStatic(EntityHandle field) => il =>
    {
        il.OpCode(ILOpCode.Ldsfld);
        il.Token(field);
        il.OpCode(ILOpCode.Ret);
    };

    private static void Returns42(InstructionEncoder il)
    {
        il.LoadConstantI4(42);
        il.OpCode(ILOpCode.Ret);
    }

    private static object? Operand(ILMethodBody body, ILCode code) => body.Instructions.Single(i => i.OpCode == code).Operand;
    #endregion

    #region Fields
    private static BlobBuilder StaticInt => RawAssembly.MethodSig(false, r => r.Type().Int32());
    private static BlobBuilder StaticVoid => RawAssembly.MethodSig(false, r => r.Void());
    private static BlobBuilder StaticObject => RawAssembly.MethodSig(false, r => r.Type().Object());
    #endregion
}
