namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

using Cilica.AsmIO;

using Xunit;

/// <summary>
/// The SSA adapter's binding policy (docs/agent/tasks/ssa-adapter.md, "As built (S2)"): an assembly name binds to the
/// host runtime's framework assembly first, then to the folder's, then to a stub; folder modules are cached under a
/// private name, so a package can neither shadow a framework assembly nor become CoreLib; type forwarders are followed.
/// Each test writes its own folder and opens its own session; every input is read as metadata only.
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaBindingTests
{
    #region Methods
    /// <summary>
    /// A package that ships its own <c>System.Collections.dll</c> (with no <c>Stack`1</c> in it) does not shadow the
    /// host's: a reference to <c>[System.Collections]Stack`1</c> binds to the host's, and the copy is read as a folder
    /// assembly under its private name.
    /// </summary>
    [Fact]
    public void AFolderCopyOfAFrameworkAssembly_DoesNotShadowTheHosts()
    {
        Assert.Equal(Framework, typeof(Stack<>).Assembly.GetName().Name);
        using var emitted = new EmittedAssembly();
        var main = emitted.Save("ShadowMain", DefineStackUser);
        var copy = new RawAssembly(Framework);
        copy.Type("Fake", "Marker", copy.Object);
        copy.Static("M", RawAssembly.MethodSig(false, r => r.Type().Int32()), Returns42);

        using var lifted = new SsaLifted([main, copy.Save(emitted.Directory)]);

        var created = Assert.IsAssignableFrom<MethodDesc>(Operand(lifted.Il("Callers", "MakeStack"), ILCode.Newobj));
        var stack = Assert.IsAssignableFrom<TypeDefOrSpec>(created.DeclaringType);
        Assert.Equal(Framework, stack.Module.AsmName.Name);
        Assert.Null(stack.Module.FindType("Fake", "Marker", includeExports: false));
        var marker = lifted.Of("Marker", "M");
        SsaLifted.AssertLifted(marker);
        Assert.StartsWith(Framework + " [", marker.Body!.Definition.Module.AsmName.Name);
        Assert.NotSame(stack.Module, marker.Body.Definition.Module);
    }

    /// <summary>
    /// A folder assembly named <c>System.Private.CoreLib</c>, defining its own <c>System.Object</c>, is just a folder
    /// assembly: the session's CoreLib, which every <c>object</c> and <c>string</c> binds to, is the host's. (Its own System.*
    /// references go to System.Runtime, so CCI's core for it is a framework assembly and its methods lift; an assembly that
    /// is its own core is <see cref="SsaHostileShapeTests.AnAssemblyThatIsItsOwnCoreLibrary_HasEveryMethodUnknown"/>.)
    /// </summary>
    [Fact]
    public void AFolderAssemblyNamedSystemPrivateCoreLib_DoesNotBecomeCoreLib()
    {
        using var temp = new SsaTempDirectory();
        var folder = temp.Sub("folder");
        var impostor = new RawAssembly(CoreLibName);
        var fakeObject = impostor.Type("System", "Object", default);
        impostor.Type("Evil", "Thing", fakeObject);
        impostor.Static("M", RawAssembly.MethodSig(false, r => r.Type().Int32()), Returns42);
        var user = new RawAssembly("CoreLibUser");
        user.Type("Users", "User", user.Object);
        user.Static("Echo", RawAssembly.MethodSig(false, r => r.Type().Object(), p => p.Object()), ReturnsArgument);
        user.Static("Hello", RawAssembly.MethodSig(false, r => r.Type().String()), il =>
        {
            il.LoadString(user.Metadata.GetOrAddUserString("hi"));
            il.OpCode(ILOpCode.Ret);
        });

        using var lifted = new SsaLifted([impostor.Save(folder), user.Save(folder)]);

        var echo = lifted.Of("User", "Echo");
        SsaLifted.AssertLifted(echo);
        SsaLifted.AssertLifted(lifted.Of("User", "Hello"));
        var coreLib = echo.Body!.Definition.Module.Resolver.CoreLib;
        Assert.Equal(CoreLibName, coreLib.AsmName.Name);
        Assert.Null(coreLib.FindType("Evil", "Thing", includeExports: false));
        Assert.NotNull(coreLib.FindType("System", "String", includeExports: false));
        var thing = lifted.Of("Thing", "M");
        SsaLifted.AssertLifted(thing);
        Assert.StartsWith(CoreLibName + " [", thing.Body!.Definition.Module.AsmName.Name);
        Assert.NotSame(coreLib, thing.Body.Definition.Module);
    }

    /// <summary>
    /// <c>Fwd</c> forwards <c>Dep.Thing</c> to <c>DepImpl</c>, both in the folder: a reference to <c>[Fwd]Dep.Thing</c>
    /// binds to <c>DepImpl</c>'s definition, so its base (<c>System.Exception</c>) is known and the method that widens to
    /// it lifts. Unfollowed, the reference would have been a stub, and its base chain unresolved.
    /// </summary>
    [Fact]
    public void ATypeForwarderInTheFolder_IsFollowed_ToTheFolderAssemblyItNames()
    {
        using var temp = new SsaTempDirectory();
        var folder = temp.Sub("folder");
        var implementation = new RawAssembly("DepImpl");
        implementation.Type("Dep", "Thing", implementation.TypeRef(implementation.Runtime, "System", "Exception"));
        var forwarder = new RawAssembly("Fwd");
        var user = new RawAssembly("FwdUser");
        var thing = user.TypeRef(user.AssemblyRef("Fwd"), "Dep", "Thing");
        var exception = user.TypeRef(user.Runtime, "System", "Exception");
        user.Type("Users", "User", user.Object);
        user.Static("AsException", RawAssembly.MethodSig(false, r => r.Type().Type(exception, false), p => p.Type(thing, false)), ReturnsArgument);

        using var lifted = new SsaLifted(
        [
            implementation.Save(folder),
            forwarder.Save(folder, EmittedAssembly.Forwarding(("Dep", "Thing", "DepImpl"))),
            user.Save(folder),
        ]);

        var outcome = lifted.Of("User", "AsException");
        SsaLifted.AssertLifted(outcome);
        var parameter = Assert.IsAssignableFrom<TypeDefOrSpec>(outcome.Body!.Definition.StaticParams[0].Type);
        Assert.Equal(("Dep", "Thing"), (parameter.Namespace, parameter.Name));
        Assert.StartsWith("DepImpl [", parameter.Module.AsmName.Name);
    }

    /// <summary>A <c>System.Runtime</c> reference, as compiled code has, follows the host facade's forwarder to CoreLib.</summary>
    [Fact]
    public void AFrameworkFacadeReference_IsFollowed_ToTheHostsCoreLib()
    {
        using var temp = new SsaTempDirectory();
        var user = new RawAssembly("FacadeUser");
        var exception = user.TypeRef(user.Runtime, "System", "Exception");
        var invalid = user.TypeRef(user.Runtime, "System", "InvalidOperationException");
        user.Type("Users", "User", user.Object);
        user.Static("Widen", RawAssembly.MethodSig(false, r => r.Type().Type(exception, false), p => p.Type(invalid, false)), ReturnsArgument);

        using var lifted = new SsaLifted([user.Save(temp.Path)]);

        var outcome = lifted.Of("User", "Widen");
        SsaLifted.AssertLifted(outcome);
        var parameter = Assert.IsAssignableFrom<TypeDefOrSpec>(outcome.Body!.Definition.StaticParams[0].Type);
        Assert.Equal(("System", "InvalidOperationException"), (parameter.Namespace, parameter.Name));
        Assert.Same(outcome.Body.Definition.Module.Resolver.CoreLib, parameter.Module);
    }

    /// <summary>An assembly neither the host nor the folder has becomes a stub module, under a name of its own.</summary>
    [Fact]
    public void AMissingAssembly_BecomesAStubModule()
    {
        using var temp = new SsaTempDirectory();
        using var lifted = new SsaLifted([SsaStubFixture.WriteStubUser(temp.Path)]);

        var outcome = lifted.Of("User", "PassAsObject");
        SsaLifted.AssertLifted(outcome);
        var stub = Assert.IsAssignableFrom<TypeDefOrSpec>(outcome.Body!.Definition.StaticParams[0].Type).Module;
        Assert.Equal(SsaStubFixture.MissingAssembly + " [stub]", stub.AsmName.Name);
        Assert.NotSame(outcome.Body.Definition.Module.Resolver.CoreLib, stub);
        Assert.Single(lifted.Session.Assemblies);
    }

    // Callers.MakeStack: newobj Stack<int>::.ctor(); ret. PersistedAssemblyBuilder references Stack`1 where it is defined.
    private static void DefineStackUser(ModuleBuilder module)
    {
        var callers = module.DefineType("Callers", TypeAttributes.Public | TypeAttributes.Class);
        var il = callers.DefineMethod("MakeStack", MethodAttributes.Public | MethodAttributes.Static, typeof(object), Type.EmptyTypes).GetILGenerator();
        il.Emit(OpCodes.Newobj, typeof(Stack<int>).GetConstructor(Type.EmptyTypes)!);
        il.Emit(OpCodes.Ret);
        callers.CreateType();
    }

    private static void Returns42(InstructionEncoder il)
    {
        il.LoadConstantI4(42);
        il.OpCode(ILOpCode.Ret);
    }

    private static void ReturnsArgument(InstructionEncoder il)
    {
        il.LoadArgument(0);
        il.OpCode(ILOpCode.Ret);
    }

    private static object? Operand(ILMethodBody body, ILCode code) => body.Instructions.Single(i => i.OpCode == code).Operand;
    #endregion

    #region Fields
    private const string Framework = "System.Collections";
    private const string CoreLibName = "System.Private.CoreLib";
    #endregion
}
