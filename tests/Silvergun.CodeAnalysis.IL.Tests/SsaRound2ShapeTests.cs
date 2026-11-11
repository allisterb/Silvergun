namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;

using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// Shapes from the second S2 review (docs/agent/tasks/ssa-adapter.md), each lifted in a CHILD process through
/// <see cref="SsaHostileShapeTests.Lift(System.Collections.Generic.IReadOnlyList{string}, int, int)"/>: untrusted core
/// libraries (R2-C1, R2-W1), enum predicates (R2-C2), failures deep in a chain (R2-C3), truncated nested instantiations
/// (R2-W2) and signature blobs the scan must survive or distrust (R2-W3).
/// </summary>
public sealed class SsaRound2ShapeTests
{
    #region Methods
    /// <summary>
    /// R2-C1: <c>coreclr</c> is a native file of the runtime directory, so not a framework assembly. A folder assembly of
    /// that name, pointed at by a sibling's System.* references, becomes CCI's core for the sibling, whose primitives then
    /// cannot be trusted.
    /// </summary>
    [Fact]
    public void AFolderAssemblyNamedLikeANativeRuntimeFile_AsCore_HasItsUsersMethodsUnknown()
    {
        Assert.True(File.Exists(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "coreclr.dll")), "Premise: the runtime directory has a native coreclr.dll.");
        using var temp = new SsaTempDirectory();
        var coreclr = new RawAssembly("coreclr");
        coreclr.Type("System", "String", coreclr.Object);
        var victim = new RawAssembly("Victim", withRuntime: false);
        var core = victim.AssemblyRef("coreclr");
        var coreObject = victim.TypeRef(core, "System", "Object");
        victim.TypeRef(core, "System", "Int32");
        victim.TypeRef(core, "System", "String");
        victim.Type("Users", "User", coreObject);
        victim.Static("Plain", StaticInt, Returns(42));

        var run = SsaHostileShapeTests.Lift([coreclr.Save(temp.Path), victim.Save(temp.Path)]);

        run.AssertFailed("Users.User::Plain", SsaFailureKind.Adapter, "primitive types cannot be trusted");
    }

    /// <summary>R2-W1: a module that is its own core answers nothing, to anyone: a field read or a call into it fails.</summary>
    [Fact]
    public void AReferenceIntoAnAssemblyThatIsItsOwnCore_FailsAsAdapter()
    {
        using var temp = new SsaTempDirectory();
        var own = new RawAssembly("OwnCore", withRuntime: false);
        var fakeObject = own.Type("System", "Object", default);
        own.Type("Evil", "Thing", fakeObject);
        own.Field("F", FieldAttributes.Public | FieldAttributes.Static, t => t.Int32());
        own.Static("M", StaticInt, Returns(1));
        var good = new RawAssembly("Good");
        var thing = good.TypeRef(good.AssemblyRef("OwnCore"), "Evil", "Thing");
        var field = good.MemberRef(thing, "F", RawAssembly.FieldSig(t => t.Int32()));
        var method = good.MemberRef(thing, "M", RawAssembly.MethodSig(false, r => r.Type().Int32()));
        good.Type("Ok", "Ok", good.Object);
        good.Static("ReadsF", StaticInt, il =>
        {
            il.OpCode(ILOpCode.Ldsfld);
            il.Token(field);
            il.OpCode(ILOpCode.Ret);
        });
        good.Static("CallsM", StaticInt, il =>
        {
            il.Call(method);
            il.OpCode(ILOpCode.Ret);
        });
        good.Static("Plain", StaticInt, Returns(42));

        var run = SsaHostileShapeTests.Lift([own.Save(temp.Path), good.Save(temp.Path)]);

        run.AssertFailed("Ok.Ok::ReadsF", SsaFailureKind.Adapter, "primitive types cannot be trusted");
        run.AssertFailed("Ok.Ok::CallsM", SsaFailureKind.Adapter, "primitive types cannot be trusted");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// R2-C2: Cilica calls any type whose base is System.Enum an enum (CCI also wants it sealed and non-generic), so the
    /// guard against a cyclic underlying type must hold for an unsealed pair (E1 ↔ E2) too.
    /// </summary>
    [Fact]
    public void UnsealedEnumsWhoseUnderlyingTypesCycle_FailTheirUsers_WithoutHanging()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("UnsealedEnums");
        var enumType = raw.TypeRef(raw.Runtime, "System", "Enum");
        var e1 = raw.NextType();
        var e2 = raw.NextType(1);
        raw.Type("Enums", "E1", enumType, TypeAttributes.Public);
        raw.Field("value__", ValueField, t => t.Type(e2, isValueType: true));
        raw.Type("Enums", "E2", enumType, TypeAttributes.Public);
        raw.Field("value__", ValueField, t => t.Type(e1, isValueType: true));
        raw.Type("Ok", "Ok", raw.Object);
        raw.Static("UsesE1", TakesAndReturnsZero(p => p.Type(e1, isValueType: true)), PopsArgument);
        raw.Static("UsesE2", TakesAndReturnsZero(p => p.Type(e2, isValueType: true)), PopsArgument);
        raw.Static("Plain", StaticInt, Returns(42));

        var run = SsaHostileShapeTests.Lift(raw.Save(temp.Path));

        run.AssertNotLifted("Ok.Ok::UsesE1");
        run.AssertNotLifted("Ok.Ok::UsesE2");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>R2-C2, generic: <c>G`1&lt;T&gt; : System.Enum</c> whose <c>value__</c> is <c>G`1&lt;T&gt;</c> itself.</summary>
    [Fact]
    public void AGenericEnumThatIsItsOwnUnderlyingType_FailsItsUsers_WithoutHanging()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("GenericEnum");
        var enumType = raw.TypeRef(raw.Runtime, "System", "Enum");
        var g = raw.Type("Enums", "G`1", enumType, TypeAttributes.Public | TypeAttributes.Sealed);
        raw.Field("value__", ValueField, t => t.GenericInstantiation(g, 1, isValueType: true).AddArgument().GenericTypeParameter(0));
        raw.GenericParameter(g, "T", 0);
        raw.Type("Ok", "Ok", raw.Object);
        raw.Static("UsesG", TakesAndReturnsZero(p => p.GenericInstantiation(g, 1, isValueType: true).AddArgument().Int32()), PopsArgument);
        raw.Static("Plain", StaticInt, Returns(42));

        var run = SsaHostileShapeTests.Lift(raw.Save(temp.Path));

        run.AssertNotLifted("Ok.Ok::UsesG");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// R2-C3: a constraint chain shorter than the nesting bound (250 links) whose last constraint names a type its module
    /// does not have. The failure is a fact about the input, memoised where it is met and unwound once: the method fails
    /// (not as Bounds), and the child neither overflows nor hangs.
    /// </summary>
    [Fact]
    public void AConstraintChainEndingInAnUnresolvedType_FailsItsMethod_NotAsBounds()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("ChainToNowhere");
        var nowhere = raw.TypeRef(EntityHandle.ModuleDefinition, "Nope", "Gone");
        for (var i = 0; i < ShortChain; i++)
        {
            var type = raw.Type("Chain", $"C{i}`1", raw.Object);
            var parameter = raw.GenericParameter(type, "T", 0);
            if (i < ShortChain - 1)
            {
                var next = raw.NextType();
                raw.Constraint(parameter, raw.TypeSpec(t => t.GenericInstantiation(next, 1, isValueType: false).AddArgument().GenericTypeParameter(0)));
            }
            else
            {
                raw.Constraint(parameter, nowhere);
            }
            if (i == 0)
                raw.Instance("M", InstanceInt, Returns(1));
        }
        raw.Type("Ok", "Ok", raw.Object);
        raw.Static("Plain", StaticInt, Returns(42));

        var run = SsaHostileShapeTests.Lift(raw.Save(temp.Path));

        run.AssertNotLifted("Chain.C0::M");
        Assert.True(run.Of("Chain.C0::M").Kind != nameof(SsaFailureKind.Bounds), "The chain is within the bound: its failure is the missing type's.");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// R2-W2: <c>Outer`1/Inner</c> (Inner adds no parameters of its own) instantiated with two arguments: CCI keeps one, as
    /// a bare specialized nested reference. Adapter for a folder type, Arity for a stub. The same shapes with one argument,
    /// on other TypeRef rows, lift.
    /// </summary>
    [Fact]
    public void ASpecializedNestedTypeWithTooManyArguments_Fails_AndWithItsArity_Lifts()
    {
        using var temp = new SsaTempDirectory();
        var folder = new RawAssembly("Nesting");
        var outer = folder.Type("Nest", "Outer`1", folder.Object);
        var inner = folder.Type(null, "Inner", folder.Object, TypeAttributes.NestedPublic | TypeAttributes.Class);
        folder.Nest(inner, outer);
        folder.GenericParameter(outer, "T", 0);
        folder.GenericParameter(inner, "T", 0);
        folder.Type("Ok", "Ok", folder.Object);
        folder.Static("CastsTwo", StaticObject, CastNullTo(folder.TypeSpec(t => TwoInts(t.GenericInstantiation(inner, 2, isValueType: false)))));

        var user = new RawAssembly("NestingUser");
        TypeReferenceHandle Inner(string assembly)
        {
            var outerRef = user.TypeRef(user.AssemblyRef(assembly), "Nest", "Outer`1");
            return user.TypeRef(outerRef, null, "Inner");
        }
        var folderInner = Inner("Nesting");
        var stubInnerTwo = Inner(SsaStubFixture.MissingAssembly);
        var stubInnerOne = Inner(SsaStubFixture.MissingAssembly);
        user.Type("Ok", "User", user.Object);
        user.Static("CastsFolderOne", StaticObject, CastNullTo(user.TypeSpec(t => t.GenericInstantiation(folderInner, 1, isValueType: false).AddArgument().Int32())));
        user.Static("CastsStubTwo", StaticObject, CastNullTo(user.TypeSpec(t => TwoInts(t.GenericInstantiation(stubInnerTwo, 2, isValueType: false)))));
        user.Static("CastsStubOne", StaticObject, CastNullTo(user.TypeSpec(t => t.GenericInstantiation(stubInnerOne, 1, isValueType: false).AddArgument().Int32())));

        var run = SsaHostileShapeTests.Lift([folder.Save(temp.Path), user.Save(temp.Path)]);

        run.AssertFailed("Ok.Ok::CastsTwo", SsaFailureKind.Adapter, "differing numbers of type arguments");
        run.AssertFailed("Ok.User::CastsStubTwo", SsaFailureKind.UnresolvedFact, "Unresolved Arity");
        run.AssertLifted("Ok.User::CastsFolderOne");
        run.AssertLifted("Ok.User::CastsStubOne");
    }

    /// <summary>R2-W3: a TypeSpec of 5,000 nested SZARRAYs (raw bytes) is read by the iterative scan without harm.</summary>
    [Fact]
    public void ADeeplyNestedSignatureBlob_DoesNotCrashTheScan()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("DeepBlob");
        raw.TypeSpecBytes([.. Enumerable.Repeat((byte)0x1D, 5_000), 0x08]);
        raw.Type("Ok", "Ok", raw.Object);
        raw.Static("Plain", StaticInt, Returns(42));

        var run = SsaHostileShapeTests.Lift(raw.Save(temp.Path));

        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// R2-W3 / R3-W2: one signature blob the scan cannot parse (a TypeSpec of the byte 0xFF) in module <c>Unparsed</c>:
    /// <list type="bullet">
    /// <item><description>every generic instantiation of that module fails (its argument counts are unproven);</description></item>
    /// <item><description>that module's own TypeRef rows read as conflicting, so a stub it references fails as
    /// ValueTypeness, here and in a clean module that encodes the same key as CLASS (a conflict proves nothing);</description></item>
    /// <item><description>a stub only clean modules reference keeps its CLASS encoding, and lifts.</description></item>
    /// </list>
    /// </summary>
    [Fact]
    public void AnUnparsableSignature_PoisonsItsModulesArities_AndOnlyTheStubKeysItReferences()
    {
        using var temp = new SsaTempDirectory();
        var broken = new RawAssembly("Unparsed");
        broken.TypeSpecBytes([0xFF]);
        var action = broken.TypeRef(broken.Runtime, "System", "Action`1");
        var sharedInBroken = broken.TypeRef(broken.AssemblyRef(SsaStubFixture.MissingAssembly), "Missing", "Shared");
        broken.Type("Ok", "Broken", broken.Object);
        broken.Static("CastsAction", StaticObject, CastNullTo(broken.TypeSpec(t => t.GenericInstantiation(action, 1, isValueType: false).AddArgument().Int32())));
        broken.Static("PassesShared", PassesAsObject(sharedInBroken), ReturnsArgument);
        broken.Static("Plain", StaticInt, Returns(42));
        var clean = new RawAssembly("Clean");
        var missing = clean.AssemblyRef(SsaStubFixture.MissingAssembly);
        var classThing = clean.TypeRef(missing, "Missing", "ClassThing");
        var sharedInClean = clean.TypeRef(missing, "Missing", "Shared");
        clean.Type("Ok", "Clean", clean.Object);
        clean.Static("PassAsObject", PassesAsObject(classThing), ReturnsArgument);
        clean.Static("PassesShared", PassesAsObject(sharedInClean), ReturnsArgument);
        clean.Static("Plain", StaticInt, Returns(42));

        var run = SsaHostileShapeTests.Lift([broken.Save(temp.Path), clean.Save(temp.Path)]);

        run.AssertFailed("Ok.Broken::CastsAction", SsaFailureKind.Adapter, "differing numbers of type arguments");
        run.AssertFailed("Ok.Broken::PassesShared", SsaFailureKind.UnresolvedFact, "Unresolved ValueTypeness of 'Missing.Shared'");
        run.AssertFailed("Ok.Clean::PassesShared", SsaFailureKind.UnresolvedFact, "Unresolved ValueTypeness of 'Missing.Shared'");
        run.AssertLifted("Ok.Clean::PassAsObject");
        run.AssertLifted("Ok.Broken::Plain");
        run.AssertLifted("Ok.Clean::Plain");
    }

    private static BlobBuilder PassesAsObject(EntityHandle type) =>
        RawAssembly.MethodSig(false, r => r.Type().Object(), p => p.Type(type, isValueType: false));

    private static void ReturnsArgument(InstructionEncoder il)
    {
        il.LoadArgument(0);
        il.OpCode(ILOpCode.Ret);
    }

    private static void TwoInts(GenericTypeArgumentsEncoder arguments)
    {
        arguments.AddArgument().Int32();
        arguments.AddArgument().Int32();
    }

    private static Action<InstructionEncoder> CastNullTo(EntityHandle type) => il =>
    {
        il.OpCode(ILOpCode.Ldnull);
        il.OpCode(ILOpCode.Castclass);
        il.Token(type);
        il.OpCode(ILOpCode.Ret);
    };

    private static BlobBuilder TakesAndReturnsZero(Action<SignatureTypeEncoder> parameter) =>
        RawAssembly.MethodSig(false, r => r.Type().Int32(), parameter);

    private static void PopsArgument(InstructionEncoder il)
    {
        il.LoadArgument(0);
        il.OpCode(ILOpCode.Pop);
        il.LoadConstantI4(0);
        il.OpCode(ILOpCode.Ret);
    }

    private static Action<InstructionEncoder> Returns(int value) => il =>
    {
        il.LoadConstantI4(value);
        il.OpCode(ILOpCode.Ret);
    };
    #endregion

    #region Fields
    // Within the default nesting bound (256).
    private const int ShortChain = 250;

    private const FieldAttributes ValueField = FieldAttributes.Public | FieldAttributes.SpecialName | FieldAttributes.RTSpecialName;

    private static BlobBuilder StaticInt => RawAssembly.MethodSig(false, r => r.Type().Int32());
    private static BlobBuilder StaticObject => RawAssembly.MethodSig(false, r => r.Type().Object());
    private static BlobBuilder InstanceInt => RawAssembly.MethodSig(true, r => r.Type().Int32());
    #endregion
}
