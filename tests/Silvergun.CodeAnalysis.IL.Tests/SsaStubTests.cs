namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

using Cilica.AsmIO;

using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

using MethodReference = Cilica.AsmIO.MethodReference;

/// <summary>
/// The fixture for <see cref="SsaStubTests"/>: <c>StubUser</c>, written row by row, whose methods reach into
/// <c>Missing.Dependency</c>, an assembly the folder does not contain. Each method asks one question of a stub type; the
/// signatures in it are the folder's only evidence of how each missing type is encoded (CLASS or VALUETYPE).
/// </summary>
public sealed class SsaStubFixture : IDisposable
{
    #region Constructors
    public SsaStubFixture()
    {
        StubUserPath = WriteStubUser(temp.Sub("stubs"));
        Lifted = new SsaLifted([StubUserPath]);
    }
    #endregion

    #region Properties
    public string StubUserPath { get; }

    internal SsaLifted Lifted { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Lifted.Dispose();
        temp.Dispose();
    }

    /// <summary>Writes <c>StubUser.dll</c> into <paramref name="directory"/>.</summary>
    public static string WriteStubUser(string directory)
    {
        var raw = new RawAssembly("StubUser");
        var missing = raw.AssemblyRef(MissingAssembly);
        var classThing = raw.TypeRef(missing, "Missing", "ClassThing");
        var structThing = raw.TypeRef(missing, "Missing", "StructThing");
        var unencoded = raw.TypeRef(missing, "Missing", "Unencoded");
        var generic = raw.TypeRef(missing, "Missing", "Gen`1");
        // A second TypeRef row for the same name: arity disagreements are judged per row (CCI hides which use was
        // truncated, so every use of a disagreeing row fails), and this one carries the over-arity use alone.
        var genericAgain = raw.TypeRef(missing, "Missing", "Gen`1");
        var unsuffixed = raw.TypeRef(missing, "Missing", "NoArity");
        var exception = raw.TypeRef(raw.Runtime, "System", "Exception");
        var disposable = raw.TypeRef(raw.Runtime, "System", "IDisposable");

        var genericOfOne = raw.TypeSpec(t => t.GenericInstantiation(generic, 1, isValueType: false).AddArgument().Int32());
        var genericOfTwo = raw.TypeSpec(t =>
        {
            var arguments = t.GenericInstantiation(genericAgain, 2, isValueType: false);
            arguments.AddArgument().Int32();
            arguments.AddArgument().Int32();
        });
        var unsuffixedOfOne = raw.TypeSpec(t => t.GenericInstantiation(unsuffixed, 1, isValueType: false).AddArgument().Int32());
        var unencodedCtor = raw.MemberRef(unencoded, ".ctor", RawAssembly.MethodSig(true, r => r.Void()));
        var count = raw.MemberRef(classThing, "Count", RawAssembly.FieldSig(t => t.Int32()));
        var size = raw.MemberRef(classThing, "Size", RawAssembly.FieldSig(t => t.Int32()));
        var get = raw.MemberRef(classThing, "Get", RawAssembly.MethodSig(true, r => r.Type().Int32()));

        void Return(InstructionEncoder il) => il.OpCode(ILOpCode.Ret);
        void ReturnArgument(InstructionEncoder il)
        {
            il.LoadArgument(0);
            Return(il);
        }

        raw.Type("Stubs", "User", raw.Object);
        raw.Static("Plain", Sig(r => r.Type().Int32()), il =>
        {
            il.LoadConstantI4(42);
            Return(il);
        });
        // The one base-chain fact D3 grants: a reference type is assignable to object.
        raw.Static("PassAsObject", Sig(r => r.Type().Object(), p => p.Type(classThing, false)), ReturnArgument);
        // Anything further up the chain is unknown.
        raw.Static("AsException", Sig(r => r.Type().Type(exception, false), p => p.Type(classThing, false)), ReturnArgument);
        raw.Static("AsDisposable", Sig(r => r.Type().Type(disposable, false), p => p.Type(classThing, false)), ReturnArgument);
        // A value type: struct or enum (and of what), unknown.
        raw.Static("TakesStruct", Sig(r => r.Type().Int32(), p => p.Type(structThing, true)), il =>
        {
            il.LoadArgument(0);
            il.OpCode(ILOpCode.Pop);
            il.LoadConstantI4(0);
            Return(il);
        });
        // Named by no signature in the folder: not even its value-typeness is known.
        raw.Static("NewUnencoded", Sig(r => r.Type().Object()), il =>
        {
            il.OpCode(ILOpCode.Newobj);
            il.Token(unencodedCtor);
            Return(il);
        });
        // Arity is a fact of the name ("Gen`1"; none for "NoArity"), so one argument to Gen`1 is fine, and two, or any
        // to NoArity, is a contradiction.
        raw.Static("GenericWithItsArity", Sig(r => r.Type().Object()), il =>
        {
            il.OpCode(ILOpCode.Ldnull);
            il.OpCode(ILOpCode.Castclass);
            il.Token(genericOfOne);
            Return(il);
        });
        raw.Static("GenericWithTooManyArguments", Sig(r => r.Type().Object()), il =>
        {
            il.OpCode(ILOpCode.Ldnull);
            il.OpCode(ILOpCode.Castclass);
            il.Token(genericOfTwo);
            Return(il);
        });
        raw.Static("UnsuffixedNameWithAnArgument", Sig(r => r.Type().Object()), il =>
        {
            il.OpCode(ILOpCode.Ldnull);
            il.OpCode(ILOpCode.Castclass);
            il.Token(unsuffixedOfOne);
            Return(il);
        });
        // Members: a field's static-ness comes from the opcode that uses it; ldtoken has none.
        raw.Static("StaticFieldOfStub", Sig(r => r.Type().Int32()), il =>
        {
            il.OpCode(ILOpCode.Ldsfld);
            il.Token(count);
            Return(il);
        });
        raw.Static("InstanceFieldOfStub", Sig(r => r.Type().Int32(), p => p.Type(classThing, false)), il =>
        {
            il.LoadArgument(0);
            il.OpCode(ILOpCode.Ldfld);
            il.Token(size);
            Return(il);
        });
        raw.Static("TokenOfStubField", Sig(r => r.Type().Int32()), il =>
        {
            il.OpCode(ILOpCode.Ldtoken);
            il.Token(count);
            il.OpCode(ILOpCode.Pop);
            il.LoadConstantI4(0);
            Return(il);
        });
        raw.Static("CallsStubMethod", Sig(r => r.Type().Int32(), p => p.Type(classThing, false)), il =>
        {
            il.LoadArgument(0);
            il.OpCode(ILOpCode.Callvirt);
            il.Token(get);
            Return(il);
        });
        return raw.Save(directory);
    }

    /// <summary>
    /// Writes <c>Encoder.dll</c>: its only method's signature encodes <c>Missing.Unencoded</c> as CLASS, the fact
    /// <c>StubUser</c> alone lacks.
    /// </summary>
    public static string WriteEncoder(string directory)
    {
        var raw = new RawAssembly("Encoder");
        var unencoded = raw.TypeRef(raw.AssemblyRef(MissingAssembly), "Missing", "Unencoded");
        raw.Type("Stubs", "Encoder", raw.Object);
        raw.Static("Encodes", Sig(r => r.Void(), p => p.Type(unencoded, false)), il => il.OpCode(ILOpCode.Ret));
        return raw.Save(directory);
    }

    private static BlobBuilder Sig(Action<ReturnTypeEncoder> returns, params Action<SignatureTypeEncoder>[] parameters) =>
        RawAssembly.MethodSig(false, returns, parameters);
    #endregion

    #region Fields
    public const string MissingAssembly = "Missing.Dependency";

    private readonly SsaTempDirectory temp = new();
    #endregion
}

/// <summary>
/// Stub types for an assembly the folder does not contain (ruling D3, docs/agent/tasks/ssa-adapter.md): each fact a
/// reference proves holds, and each question it cannot answer fails the asking method alone, as
/// <see cref="SsaFailureKind.UnresolvedFact"/> naming the fact, while the rest of the assembly lifts.
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaStubTests : IClassFixture<SsaStubFixture>
{
    #region Constructors
    public SsaStubTests(SsaStubFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    [Fact]
    public void AClassEncodedStub_PassedOnlyAsObject_Lifts_InAStubModule()
    {
        var outcome = Lifted.Of("User", "PassAsObject");

        SsaLifted.AssertLifted(outcome);
        var parameter = Assert.IsAssignableFrom<TypeDefOrSpec>(outcome.Body!.Definition.StaticParams[0].Type);
        Assert.Equal(("Missing", "ClassThing"), (parameter.Namespace, parameter.Name));
        Assert.Equal(SsaStubFixture.MissingAssembly + " [stub]", parameter.Module.AsmName.Name);
        Assert.False(parameter.IsValueType);
    }

    [Fact]
    public void AClassEncodedStub_AsABaseClass_IsAnUnresolvedBaseType() =>
        SsaLifted.AssertFailed(Lifted.Of("User", "AsException"), SsaFailureKind.UnresolvedFact, "Unresolved BaseType of 'Missing.ClassThing'");

    [Fact]
    public void AClassEncodedStub_AsAnInterface_IsUnresolvedInterfaces() =>
        SsaLifted.AssertFailed(Lifted.Of("User", "AsDisposable"), SsaFailureKind.UnresolvedFact, "Unresolved Interfaces");

    [Fact]
    public void AValueTypeEncodedStub_IsAnUnresolvedEnumOrStruct() =>
        SsaLifted.AssertFailed(Lifted.Of("User", "TakesStruct"), SsaFailureKind.UnresolvedFact, "Unresolved EnumOrStruct of 'Missing.StructThing'");

    [Fact]
    public void AnUnencodedStub_IsAnUnresolvedValueTypeness() =>
        SsaLifted.AssertFailed(Lifted.Of("User", "NewUnencoded"), SsaFailureKind.UnresolvedFact, "Unresolved ValueTypeness of 'Missing.Unencoded'");

    /// <summary>
    /// <c>Gen`1&lt;int32&gt;</c>, CLASS-encoded, returned as <c>object</c>: the same D3 fact as
    /// <see cref="AClassEncodedStub_PassedOnlyAsObject_Lifts_InAStubModule"/>, through a generic instance.
    /// </summary>
    /// <remarks>
    /// Regression for review W3: Cilica's <c>TypeSpec.BaseType</c> re-validated its cache through
    /// <c>_baseType.Definition</c>, which <see cref="UnknownSupertype"/> throws for, so the verifier's second walk of the
    /// chain failed "Unresolved BaseType" instead of finding <c>object</c>.
    /// </remarks>
    [Fact]
    public void AGenericStub_UsedWithTheArityItsNameDeclares_IsAssignableToObject_AndLifts() =>
        SsaLifted.AssertLifted(Lifted.Of("User", "GenericWithItsArity"));

    /// <summary>A name with no arity suffix, instantiated: its uses disagree with its name.</summary>
    [Fact]
    public void AGenericStub_WhoseNameDeclaresNoArity_UsedWithAnArgument_IsAnUnresolvedArity() =>
        SsaLifted.AssertFailed(Lifted.Of("User", "UnsuffixedNameWithAnArgument"), SsaFailureKind.UnresolvedFact, "Unresolved Arity of 'Missing.NoArity'");

    /// <summary><c>Gen`1&lt;int32, int32&gt;</c>: more arguments than the name declares.</summary>
    /// <remarks>
    /// CCI's <c>SpecializeAndOrInstantiate</c> takes as many arguments as a mangled name declares and drops the rest, so the
    /// adapter is handed <c>Gen`1&lt;int32&gt;</c>; the folder's own instantiation counts (<c>MetadataFacts</c>) catch it.
    /// </remarks>
    [Fact]
    public void AGenericStub_WithMoreArgumentsThanItsNameDeclares_IsAnUnresolvedArity() =>
        SsaLifted.AssertFailed(Lifted.Of("User", "GenericWithTooManyArguments"), SsaFailureKind.UnresolvedFact, "Unresolved Arity of 'Missing.Gen`1'");

    [Fact]
    public void AStubField_LoadedWithLdsfld_IsStatic()
    {
        var field = Assert.IsAssignableFrom<FieldDesc>(Operand(Lifted.Il("User", "StaticFieldOfStub"), ILCode.Ldsfld));

        Assert.Equal(("Count", "ClassThing"), (field.Name, field.DeclaringType.Name));
        Assert.True(field.IsStatic);
        Assert.Same(PrimType.Int32, field.Type);
    }

    [Fact]
    public void AStubField_LoadedWithLdfld_IsAnInstanceField()
    {
        var field = Assert.IsAssignableFrom<FieldDesc>(Operand(Lifted.Il("User", "InstanceFieldOfStub"), ILCode.Ldfld));

        Assert.Equal(("Size", "ClassThing"), (field.Name, field.DeclaringType.Name));
        Assert.False(field.IsStatic);
    }

    /// <summary><c>ldtoken</c> says nothing about whether the field is static, so the method cannot be adapted.</summary>
    [Fact]
    public void AStubField_InLdtoken_IsAnUnresolvedMember() =>
        SsaLifted.AssertFailed(Lifted.Of("User", "TokenOfStubField"), SsaFailureKind.UnresolvedFact, "Unresolved Member of 'Missing.ClassThing'");

    /// <summary>A call into a stub keeps the call-site signature as Cilica's unproven target, a <c>MethodReference</c>.</summary>
    [Fact]
    public void AStubMethod_IsAMethodReference_WithTheCallSiteSignature()
    {
        var method = Assert.IsType<MethodReference>(Operand(Lifted.Il("User", "CallsStubMethod"), ILCode.Callvirt));

        Assert.Equal(("Get", "ClassThing"), (method.Name, method.DeclaringType.Name));
        Assert.Same(PrimType.Int32, method.ReturnSig.Type);
        Assert.True(method.Signature.IsInstance);
        Assert.Empty(method.Signature.ParamTypes);
    }

    /// <summary>
    /// Every failure above cost only its own method: the methods that need no unproven fact lifted in the same assembly,
    /// and every method that did not lift is an unresolved fact (which fact, per method, is pinned above).
    /// </summary>
    [Fact]
    public void EachUnresolvedFact_CostsOnlyItsMethod()
    {
        var outcomes = Lifted.Outcomes.Where(o => o.AssemblyPath == fixture.StubUserPath).ToArray();

        Assert.Equal(13, outcomes.Length);
        foreach (var method in new[] { "Plain", "PassAsObject", "StaticFieldOfStub", "InstanceFieldOfStub", "CallsStubMethod" })
            SsaLifted.AssertLifted(Lifted.Of("User", method));
        Assert.True(outcomes.Count(o => !o.IsLifted) >= 6, "Fewer methods failed than the fixture's unproven questions.");
        Assert.All(outcomes.Where(o => !o.IsLifted), o => Assert.True(o.Failure!.Kind == SsaFailureKind.UnresolvedFact, SsaText.Of(o)));
        Assert.Contains(fixture.Lifted.Session.Assemblies, a => a.Path == fixture.StubUserPath && a.IsLoaded);
    }

    /// <summary>
    /// Value-typeness is a folder-wide fact: one assembly's signature that encodes <c>Missing.Unencoded</c> as CLASS
    /// settles it for every assembly, so the method that failed alone lifts beside it.
    /// </summary>
    [Fact]
    public void AStubsEncoding_InAnotherAssemblyOfTheFolder_Counts()
    {
        using var temp = new SsaTempDirectory();
        var folder = temp.Sub("folder");
        using var lifted = new SsaLifted([SsaStubFixture.WriteStubUser(folder), SsaStubFixture.WriteEncoder(folder)]);

        SsaLifted.AssertLifted(lifted.Of("User", "NewUnencoded"));
    }

    private SsaLifted Lifted => fixture.Lifted;

    private static object? Operand(ILMethodBody body, ILCode code) => body.Instructions.Single(i => i.OpCode == code).Operand;
    #endregion

    #region Fields
    private readonly SsaStubFixture fixture;
    #endregion
}
