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

    // ---- S3 (corpus findings) ----------------------------------------------------------------------------------------

    /// <summary>
    /// S3: <c>Retry.T</c>'s method list is first read from inside <c>Retry.U.M1</c>'s body (a call to <c>T.A</c>), nested
    /// deep enough that <c>T.A</c>'s signature (<c>C0&lt;int&gt;</c>, whose constraints run 8 types deep) meets
    /// <see cref="SsaBounds.MaxNesting"/>: a path-dependent failure, not memoised. When <c>T</c>'s own methods are lifted
    /// later, from shallower, the list is read again, and must not trip over a half-published first attempt ("An item
    /// with the same key has already been added"): <c>T.Before</c>, read fine the first time, is published only once.
    /// <para>
    /// The bound that separates the two reads depends on how deep the adapter nests its reads (9, when written), so the
    /// test searches for it rather than pinning it: some bound must fail <c>U.M1</c> as Bounds and still lift <c>T.A</c>,
    /// and at that bound <c>T.Before</c> lifts too. A half-published first attempt would fail <c>T.A</c> at every such
    /// bound, so no bound would qualify.
    /// </para>
    /// </summary>
    [Fact]
    public void AMemberListCutShortByTheNestingBound_IsReadAgainLater_AndItsMethodsLift()
    {
        using var temp = new SsaTempDirectory();
        var path = WriteRetryFixture(temp.Path, RetryChain);
        var seen = new List<string>();

        for (var nesting = 2; nesting <= 20; nesting++)
        {
            using var lifted = new SsaLifted([path], SsaBounds.Default with { MaxNesting = nesting });
            var (m1, a) = (lifted.Of("U", "M1"), lifted.Of("T", "A"));
            seen.Add($"MaxNesting {nesting}: " + string.Join("; ", lifted.Outcomes.Select(SsaText.Of)));
            if (m1.Failure?.Kind != SsaFailureKind.Bounds || !a.IsLifted)
                continue;

            SsaLifted.AssertLifted(lifted.Of("T", "Before"));
            Assert.DoesNotContain(lifted.Outcomes, o => o.Failure?.Reason.Contains("same key", StringComparison.Ordinal) == true);
            return;
        }
        Assert.Fail("No nesting bound failed U.M1 as Bounds while T.A lifted on its later read:" + Environment.NewLine + string.Join(Environment.NewLine, seen));
    }

    /// <summary>Writes <c>Retry.dll</c>: a constraint chain <c>C0`1</c>..., then <c>U.M1</c> (calls <c>T.A</c>), then <c>T.Before</c> and <c>T.A(C0&lt;int&gt;)</c>.</summary>
    internal static string WriteRetryFixture(string directory, int chainLength)
    {
        var raw = new RawAssembly("Retry");
        var c0 = raw.NextType();
        for (var i = 0; i < chainLength; i++)
        {
            var type = raw.Type("Chain", $"C{i}`1", raw.Object);
            var parameter = raw.GenericParameter(type, "T", 0);
            if (i < chainLength - 1)
            {
                var next = raw.NextType();
                raw.Constraint(parameter, raw.TypeSpec(t => t.GenericInstantiation(next, 1, isValueType: false).AddArgument().GenericTypeParameter(0)));
            }
        }
        // U.M1, T.Before and T.A take the next three MethodDef rows.
        var a = MetadataTokens.MethodDefinitionHandle(raw.Metadata.GetRowCount(TableIndex.MethodDef) + 3);
        raw.Type("Retry", "U", raw.Object);
        raw.Static("M1", StaticVoid, il =>
        {
            il.OpCode(ILOpCode.Ldnull);
            il.Call(a);
            il.OpCode(ILOpCode.Ret);
        });
        raw.Type("Retry", "T", raw.Object);
        raw.Static("Before", StaticInt, Returns42);
        var defined = raw.Static("A", RawAssembly.MethodSig(false, r => r.Void(), p => p.GenericInstantiation(c0, 1, isValueType: false).AddArgument().Int32()),
            il => il.OpCode(ILOpCode.Ret));
        Assert.Equal(a, defined);
        return raw.Save(directory);
    }

    /// <summary>
    /// S3: <c>A</c> forwards <c>N.T</c> to <c>B</c>, and <c>B</c> forwards it back; neither defines it. A reference through
    /// either is an unresolved type, its forwarders a cycle (not a hop bound met); a plain method beside them lifts.
    /// </summary>
    [Fact]
    public void ForwardersThatFormACycle_AreAnUnresolvedType_NotABound()
    {
        using var temp = new SsaTempDirectory();
        var a = new RawAssembly("A");
        var b = new RawAssembly("B");
        var user = new RawAssembly("CycleUser");
        var viaA = user.TypeRef(user.AssemblyRef("A"), "N", "T");
        var viaB = user.TypeRef(user.AssemblyRef("B"), "N", "T");
        user.Type("Users", "User", user.Object);
        user.Static("TokenViaA", StaticVoid, TokenOf(viaA));
        user.Static("TokenViaB", StaticVoid, TokenOf(viaB));
        user.Static("Plain", StaticInt, Returns42);

        using var lifted = new SsaLifted(
        [
            a.Save(temp.Path, EmittedAssembly.Forwarding(("N", "T", "B"))),
            b.Save(temp.Path, EmittedAssembly.Forwarding(("N", "T", "A"))),
            user.Save(temp.Path),
        ]);

        SsaLifted.AssertFailed(lifted.Of("User", "TokenViaA"), SsaFailureKind.UnresolvedFact, "its type forwarders form a cycle");
        SsaLifted.AssertFailed(lifted.Of("User", "TokenViaB"), SsaFailureKind.UnresolvedFact, "its type forwarders form a cycle");
        SsaLifted.AssertLifted(lifted.Of("User", "Plain"));
    }

    /// <summary>
    /// S3: an assembly with no TypeRefs at all (an interface-only one) has no core library in CCI's sense, which is safe:
    /// its <c>object</c>, <c>int32</c> and <c>typedref</c> are element types. It is not its own core (it defines no
    /// System.Object), so a sibling calling through its interface lifts.
    /// </summary>
    [Fact]
    public void AnAssemblyWithNoCoreLibrary_IsTrusted_AndItsInterfaceCanBeCalled()
    {
        using var temp = new SsaTempDirectory();
        var interfaces = new RawAssembly("Interfaces", withRuntime: false);
        interfaces.Type("Api", "IThing", default, TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract);
        interfaces.Abstract("Get", RawAssembly.MethodSig(true, r => r.Type().Object(), p => p.Int32()));
        interfaces.Abstract("Takes", RawAssembly.MethodSig(true, r => r.Void(), p => p.TypedReference()));
        var caller = new RawAssembly("Caller");
        var thing = caller.TypeRef(caller.AssemblyRef("Interfaces"), "Api", "IThing");
        var get = caller.MemberRef(thing, "Get", RawAssembly.MethodSig(true, r => r.Type().Object(), p => p.Int32()));
        caller.Type("Users", "User", caller.Object);
        caller.Static("CallsGet", RawAssembly.MethodSig(false, r => r.Type().Object(), p => p.Type(thing, isValueType: false)), il =>
        {
            il.LoadArgument(0);
            il.LoadConstantI4(1);
            il.OpCode(ILOpCode.Callvirt);
            il.Token(get);
            il.OpCode(ILOpCode.Ret);
        });

        using var lifted = new SsaLifted([interfaces.Save(temp.Path), caller.Save(temp.Path)]);

        var target = Assert.IsType<MethodDef>(Operand(lifted.Il("User", "CallsGet"), ILCode.Callvirt));
        Assert.Equal(("Get", "IThing"), (target.Name, target.DeclaringType.Name));
        Assert.Same(PrimType.Object, target.ReturnType);
        Assert.Same(PrimType.Int32, target.StaticParams[0].Type);
        var takes = target.DeclaringType.Methods.Single(m => m.Name == "Takes");
        Assert.Same(PrimType.TypedRef, takes.StaticParams[0].Type);
    }

    /// <summary>
    /// S3: a field left out of its type because its type cannot be resolved (<c>[Lib]Missing.Type</c>, where the folder's
    /// <c>Lib</c> has no such type) fails a reader of it with that original reason, not a generic "could not be read".
    /// </summary>
    [Fact]
    public void AFieldLeftOutOfItsType_FailsItsReaders_WithTheOriginalReason()
    {
        using var temp = new SsaTempDirectory();
        var lib = new RawAssembly("Lib");
        lib.Type("Lib", "Present", lib.Object);
        var holder = new RawAssembly("Holder");
        var missingInHolder = holder.TypeRef(holder.AssemblyRef("Lib"), "Missing", "Type");
        holder.Type("Data", "Box", holder.Object);
        holder.Field("F", FieldAttributes.Public, t => t.Type(missingInHolder, isValueType: false));
        var caller = new RawAssembly("FieldCaller");
        var box = caller.TypeRef(caller.AssemblyRef("Holder"), "Data", "Box");
        var missingInCaller = caller.TypeRef(caller.AssemblyRef("Lib"), "Missing", "Type");
        var f = caller.MemberRef(box, "F", RawAssembly.FieldSig(t => t.Type(missingInCaller, isValueType: false)));
        caller.Type("Users", "User", caller.Object);
        caller.Static("ReadsF", RawAssembly.MethodSig(false, r => r.Type().Object(), p => p.Type(box, isValueType: false)), il =>
        {
            il.LoadArgument(0);
            il.OpCode(ILOpCode.Ldfld);
            il.Token(f);
            il.OpCode(ILOpCode.Ret);
        });
        caller.Static("Plain", StaticInt, Returns42);

        using var lifted = new SsaLifted([lib.Save(temp.Path), holder.Save(temp.Path), caller.Save(temp.Path)]);

        SsaLifted.AssertFailed(lifted.Of("User", "ReadsF"), SsaFailureKind.UnresolvedFact, "Unresolved Type of 'Missing.Type'");
        SsaLifted.AssertLifted(lifted.Of("User", "Plain"));
    }

    /// <summary>
    /// A folder module's own definitions are never the host's primitives: <c>Evil.User.Echo</c> of a weakly named folder
    /// <c>System.Private.CoreLib</c> (<see cref="SsaRound2ShapeTests.WriteWeakCoreLib"/>), whose <c>System.String</c>
    /// CCI types as a primitive, lifts with that folder <c>System.String</c> as its parameter and return type, never with
    /// <see cref="PrimType.String"/>; and the session's CoreLib is still the host's.
    /// </summary>
    [Fact]
    public void AFolderModulesOwnSystemString_IsNeverTheHostsString()
    {
        using var temp = new SsaTempDirectory();

        using var lifted = new SsaLifted([SsaRound2ShapeTests.WriteWeakCoreLib(temp.Path)]);

        var echo = lifted.Of("User", "Echo");
        SsaLifted.AssertLifted(echo);
        var definition = echo.Body!.Definition;
        foreach (var type in new[] { definition.ReturnType, definition.StaticParams[0].Type })
        {
            Assert.NotSame(PrimType.String, type);
            var folderString = Assert.IsType<TypeDef>(type);
            Assert.Equal(("System", "String"), (folderString.Namespace, folderString.Name));
            Assert.StartsWith("System.Private.CoreLib [", folderString.Module.AsmName.Name);
            Assert.NotSame(definition.Module.Resolver.CoreLib, folderString.Module);
        }
    }

    /// <summary>S3: an outcome's <see cref="SsaMethodOutcome.MethodToken"/> is its MethodDef token, as System.Reflection.Metadata reads it.</summary>
    [Fact]
    public void MethodToken_IsTheMethodDefToken()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("Tokens");
        raw.Type("Users", "First", raw.Object);
        raw.Static("One", StaticInt, Returns42);
        raw.Type("Users", "Second", raw.Object);
        raw.Static("Two", StaticInt, Returns42);
        raw.Static("Three", StaticVoid, il => il.OpCode(ILOpCode.Ret));
        var path = raw.Save(temp.Path);
        Dictionary<string, uint> expected;
        using (var pe = new System.Reflection.PortableExecutable.PEReader(System.IO.File.OpenRead(path)))
        {
            var reader = pe.GetMetadataReader();
            expected = reader.MethodDefinitions.ToDictionary(h => reader.GetString(reader.GetMethodDefinition(h).Name), h => (uint)MetadataTokens.GetToken(h));
        }

        using var lifted = new SsaLifted([path]);

        Assert.Equal(3, lifted.Outcomes.Count);
        Assert.All(lifted.Outcomes, o =>
        {
            SsaLifted.AssertLifted(o);
            Assert.Equal(expected[o.Method.MethodName], o.MethodToken);
            Assert.Equal(0x06u, o.MethodToken >> 24);
        });
    }

    // ---- Bounds ------------------------------------------------------------------------------------------------------

    public static TheoryData<string> NonPositiveBounds() => new(nameof(SsaBounds.MaxDepth), nameof(SsaBounds.MaxInstructions),
        nameof(SsaBounds.MaxExceptionClauses), nameof(SsaBounds.MaxMappedDataBytes), nameof(SsaBounds.MaxNesting),
        nameof(SsaBounds.MaxForwarderHops), nameof(SsaBounds.MaxMappedDataBytesPerAssembly), nameof(SsaBounds.MaxTypeParts));

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
    // The retry fixture's constraint chain length.
    private const int RetryChain = 8;

    private static BlobBuilder StaticInt => RawAssembly.MethodSig(false, r => r.Type().Int32());
    private static BlobBuilder StaticVoid => RawAssembly.MethodSig(false, r => r.Void());
    private static BlobBuilder StaticObject => RawAssembly.MethodSig(false, r => r.Type().Object());
    #endregion
}
