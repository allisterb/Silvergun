namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

using Xunit;

/// <summary>
/// Hostile shapes (docs/agent/tasks/ssa-adapter.md S2, acceptance criterion 5): each costs the methods that carry it,
/// never the session, and never the process. Every shape is lifted in a CHILD process (the PathologicalSignatureProbe's
/// <c>ssa-lift</c> verb), because the failure being guarded against (a stack overflow on a cycle or a deep chain, a
/// FailFast, a hang) is one no in-process catch can observe (ADR 0021). Depth and size bounds are exercised with small
/// <see cref="SsaBounds"/> where a bound is configurable; the universe-wide nesting bound (256, not configurable) with a
/// small emitted chain of 320 types, never a compiled one.
/// </summary>
public sealed class SsaHostileShapeTests
{
    #region Methods
    /// <summary>A base-type chain that cycles (A : B : A, and Self : Self) fails the methods that need it.</summary>
    [Fact]
    public void ACyclicBaseTypeChain_FailsItsMethods_NotTheSession()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("Cyclic");
        var a = raw.NextType();
        var b = raw.NextType(1);
        raw.Type("Cyclic", "A", b);
        raw.Instance("M", InstanceInt, Returns(1));
        raw.Type("Cyclic", "B", a);
        raw.Instance("M", InstanceInt, Returns(2));
        raw.Type("Cyclic", "Self", raw.NextType());
        raw.Instance("M", InstanceInt, Returns(3));
        AddPlain(raw);

        var run = Lift(raw.Save(temp.Path));

        foreach (var type in new[] { "A", "B", "Self" })
            run.AssertFailed($"Cyclic.{type}::M", SsaFailureKind.Adapter, "cyclic");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// Two type definitions of one name (which the CLR would reject) are both kept, and their methods lift; so does a
    /// method that calls into each by MethodDef token (only a reference BY NAME is ambiguous, review W8).
    /// </summary>
    [Fact]
    public void DuplicateTypeNames_AreBothKept_AndLift()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("Dupes");
        raw.Type("Dup", "Twin", raw.Object);
        var first = raw.Static("First", StaticInt, Returns(1));
        raw.Type("Dup", "Twin", raw.Object);
        var second = raw.Static("Second", StaticInt, Returns(2));
        raw.Type("Ok", "Ok", raw.Object);
        raw.Static("CallsBoth", StaticInt, il =>
        {
            il.Call(first);
            il.Call(second);
            il.OpCode(ILOpCode.Add);
            il.OpCode(ILOpCode.Ret);
        });
        raw.Static("Plain", StaticInt, Returns(42));

        var run = Lift(raw.Save(temp.Path));

        run.AssertLifted("Dup.Twin::First");
        run.AssertLifted("Dup.Twin::Second");
        run.AssertLifted("Ok.Ok::CallsBoth");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>Tokens past the end of their tables (a method, a type, a field, a user string) each fail their method.</summary>
    [Fact]
    public void InvalidTokens_FailTheirMethods_NotTheSession()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("BadTokens");
        raw.Type("Ok", "Ok", raw.Object);
        raw.Static("CallsNowhere", StaticVoid, il =>
        {
            il.OpCode(ILOpCode.Call);
            il.Token(0x0600_FFFF);
            il.OpCode(ILOpCode.Ret);
        });
        raw.Static("NewArrayOfNothing", StaticVoid, il =>
        {
            il.LoadConstantI4(1);
            il.OpCode(ILOpCode.Newarr);
            il.Token(0x0100_FFFF);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
        });
        raw.Static("LoadsNoField", StaticVoid, il =>
        {
            il.OpCode(ILOpCode.Ldsfld);
            il.Token(0x0400_FFFF);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
        });
        raw.Static("LoadsNoString", StaticVoid, il =>
        {
            il.OpCode(ILOpCode.Ldstr);
            il.Token(0x70FF_FFFF);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
        });
        raw.Static("Plain", StaticInt, Returns(42));

        var run = Lift(raw.Save(temp.Path));

        foreach (var method in new[] { "CallsNowhere", "NewArrayOfNothing", "LoadsNoField", "LoadsNoString" })
            run.AssertFailedBeforeCilica($"Ok.Ok::{method}");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// Generic nesting past <see cref="SsaBounds.MaxDepth"/> (here 2, with <c>Action&lt;Action&lt;Action&lt;int&gt;&gt;&gt;</c>)
    /// fails as <see cref="SsaFailureKind.Bounds"/>, in a body or in a signature; a shallow method beside it lifts.
    /// </summary>
    [Fact]
    public void GenericsDeeperThanTheBound_FailTheirMethodsAsBounds()
    {
        using var temp = new SsaTempDirectory();
        var raw = NestedGenerics("Deep");

        var run = Lift(raw.Save(temp.Path), maxDepth: 2);

        run.AssertFailed("Ok.Ok::DeepInBody", SsaFailureKind.Bounds);
        run.AssertFailed("Ok.Ok::DeepInSignature", SsaFailureKind.Bounds);
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>A body with more instructions than <see cref="SsaBounds.MaxInstructions"/> (here 5) fails as Bounds.</summary>
    [Fact]
    public void AMethodOverTheInstructionBound_FailsAsBounds()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("Huge");
        raw.Type("Ok", "Ok", raw.Object);
        raw.Static("Huge", StaticInt, TwentyNops);
        raw.Static("Plain", StaticInt, Returns(42));

        var run = Lift(raw.Save(temp.Path), maxInstructions: 5);

        run.AssertFailed("Ok.Ok::Huge", SsaFailureKind.Bounds, "More than 5 instructions");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>The control for the two bound tests: with default bounds, the same shapes lift.</summary>
    [Fact]
    public void TheBoundedShapes_LiftUnderTheDefaultBounds()
    {
        using var temp = new SsaTempDirectory();
        var raw = NestedGenerics("Shallow");
        raw.Static("Huge", StaticInt, TwentyNops);

        var run = Lift(raw.Save(temp.Path));

        run.AssertLifted("Ok.Ok::DeepInBody");
        run.AssertLifted("Ok.Ok::DeepInSignature");
        run.AssertLifted("Ok.Ok::Huge");
    }

    /// <summary>
    /// Review C2: a generic-constraint chain (<c>C0&lt;T&gt; where T : C1&lt;T&gt;</c>, ... <c>C319</c>) longer than the
    /// universe-wide nesting bound fails the method that reaches it as Bounds, and the child (no stack overflow) exits 0.
    /// </summary>
    [Fact]
    public void AGenericConstraintChainLongerThanTheNestingBound_FailsAsBounds()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("Chain");
        for (var i = 0; i < ChainLength; i++)
        {
            var type = raw.Type("Chain", $"C{i}`1", raw.Object);
            var parameter = raw.GenericParameter(type, "T", 0);
            if (i < ChainLength - 1)
            {
                var next = raw.NextType();
                raw.Constraint(parameter, raw.TypeSpec(t => t.GenericInstantiation(next, 1, isValueType: false).AddArgument().GenericTypeParameter(0)));
            }
            if (i == 0)
                raw.Instance("M", InstanceInt, Returns(1));
        }
        AddPlain(raw);

        var run = Lift(raw.Save(temp.Path));

        run.AssertFailed("Chain.C0::M", SsaFailureKind.Bounds);
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// An enum whose <c>value__</c> is the other enum, and back (E1 ↔ E2): its stack type would recurse forever. Its users
    /// fail, and the child finishes (no hang, no overflow).
    /// </summary>
    [Fact]
    public void EnumsWhoseUnderlyingTypesCycle_FailTheirUsers_WithoutHanging()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("CyclicEnums");
        var enumType = raw.TypeRef(raw.Runtime, "System", "Enum");
        var e1 = raw.NextType();
        var e2 = raw.NextType(1);
        const FieldAttributes ValueField = FieldAttributes.Public | FieldAttributes.SpecialName | FieldAttributes.RTSpecialName;
        raw.Type("Enums", "E1", enumType, TypeAttributes.Public | TypeAttributes.Sealed);
        raw.Field("value__", ValueField, t => t.Type(e2, isValueType: true));
        raw.Type("Enums", "E2", enumType, TypeAttributes.Public | TypeAttributes.Sealed);
        raw.Field("value__", ValueField, t => t.Type(e1, isValueType: true));
        raw.Type("Ok", "Ok", raw.Object);
        foreach (var (name, type) in new[] { ("UsesE1", e1), ("UsesE2", e2) })
        {
            raw.Static(name, RawAssembly.MethodSig(false, r => r.Type().Int32(), p => p.Type(type, isValueType: true)), il =>
            {
                il.LoadArgument(0);
                il.OpCode(ILOpCode.Pop);
                il.LoadConstantI4(0);
                il.OpCode(ILOpCode.Ret);
            });
        }
        raw.Static("Plain", StaticInt, Returns(42));

        var run = Lift(raw.Save(temp.Path));

        run.AssertNotLifted("Ok.Ok::UsesE1");
        run.AssertNotLifted("Ok.Ok::UsesE2");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// A type initializer that cannot be adapted (here: flagged static, with an instance signature) fails its type's whole
    /// method list, since without it the type would read as having none; another type of the assembly lifts.
    /// </summary>
    [Fact]
    public void AnUnadaptableTypeInitializer_FailsEveryMethodOfItsType()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("BrokenInit");
        raw.Type("Init", "Broken", raw.Object);
        raw.Method(".cctor", MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName | MethodAttributes.HideBySig,
            RawAssembly.MethodSig(true, r => r.Void()), il => il.OpCode(ILOpCode.Ret));
        raw.Static("Plain", StaticInt, Returns(42));
        AddPlain(raw);

        var run = Lift(raw.Save(temp.Path));

        run.AssertFailed("Init.Broken::Plain", SsaFailureKind.Adapter, "type initializer");
        run.AssertNotLifted("Init.Broken::.cctor");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// Review C1: an assembly with no System.* references that defines <c>System.Object</c> is, to CCI, its own core
    /// library, so CCI's primitives for it cannot be trusted: every method of it is Unknown. A normal assembly beside it lifts.
    /// </summary>
    [Fact]
    public void AnAssemblyThatIsItsOwnCoreLibrary_HasEveryMethodUnknown()
    {
        using var temp = new SsaTempDirectory();
        var own = new RawAssembly("OwnCore", withRuntime: false);
        var fakeObject = own.Type("System", "Object", default);
        own.Static("Inside", StaticInt, Returns(1));
        own.Type("Evil", "Thing", fakeObject);
        own.Static("M", StaticInt, Returns(42));
        var normal = new RawAssembly("Normal");
        AddPlain(normal);

        var run = Lift([own.Save(temp.Path), normal.Save(temp.Path)]);

        run.AssertFailed("System.Object::Inside", SsaFailureKind.Adapter, "primitive types cannot be trusted");
        run.AssertFailed("Evil.Thing::M", SsaFailureKind.Adapter, "primitive types cannot be trusted");
        run.AssertLifted("Ok.Ok::Plain");
    }

    /// <summary>
    /// Review C1: an assembly whose System.* references mostly point at a non-framework assembly gets that assembly as
    /// CCI's core, so every method of it is Unknown.
    /// </summary>
    [Fact]
    public void AnAssemblyWhoseCoreIsNotAFrameworkAssembly_HasEveryMethodUnknown()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("EvilCore", withRuntime: false);
        var evil = raw.AssemblyRef("Evil");
        var evilObject = raw.TypeRef(evil, "System", "Object");
        raw.TypeRef(evil, "System", "Int32");
        raw.TypeRef(evil, "System", "String");
        raw.Type("Users", "User", evilObject);
        raw.Static("Plain", StaticInt, Returns(42));
        raw.Static("Other", StaticVoid, il => il.OpCode(ILOpCode.Ret));

        var run = Lift(raw.Save(temp.Path));

        run.AssertFailed("Users.User::Plain", SsaFailureKind.Adapter, "primitive types cannot be trusted");
        run.AssertFailed("Users.User::Other", SsaFailureKind.Adapter, "primitive types cannot be trusted");
    }

    // Ok.DeepInBody (ldtoken Action<Action<Action<int>>>), Ok.DeepInSignature (takes one) and Ok.Plain, the Action`1
    // referenced through System.Runtime, which forwards it to CoreLib (asserted, not assumed).
    private static RawAssembly NestedGenerics(string name)
    {
        Assert.True(Forwards("System.Runtime", "System", "Action`1"), "Premise: the host's System.Runtime forwards System.Action`1.");
        var raw = new RawAssembly(name);
        var action = raw.TypeRef(raw.Runtime, "System", "Action`1");
        void Nest(SignatureTypeEncoder type, int depth)
        {
            if (depth == 0)
                type.Int32();
            else
                Nest(type.GenericInstantiation(action, 1, isValueType: false).AddArgument(), depth - 1);
        }
        var deep = raw.TypeSpec(t => Nest(t, 3));
        raw.Type("Ok", "Ok", raw.Object);
        raw.Static("DeepInBody", StaticVoid, il =>
        {
            il.OpCode(ILOpCode.Ldtoken);
            il.Token(deep);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
        });
        raw.Static("DeepInSignature", RawAssembly.MethodSig(false, r => r.Void(), p => Nest(p, 3)), il => il.OpCode(ILOpCode.Ret));
        raw.Static("Plain", StaticInt, Returns(42));
        return raw;
    }

    /// <summary>Whether the host runtime's <paramref name="assembly"/> has an ExportedType row for the type.</summary>
    internal static bool Forwards(string assembly, string ns, string name)
    {
        using var pe = new PEReader(File.OpenRead(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), assembly + ".dll")));
        var reader = pe.GetMetadataReader();
        return reader.ExportedTypes.Select(reader.GetExportedType)
            .Any(e => reader.GetString(e.Namespace) == ns && reader.GetString(e.Name) == name);
    }

    private static void AddPlain(RawAssembly raw)
    {
        raw.Type("Ok", "Ok", raw.Object);
        raw.Static("Plain", StaticInt, Returns(42));
    }

    private static Action<InstructionEncoder> Returns(int value) => il =>
    {
        il.LoadConstantI4(value);
        il.OpCode(ILOpCode.Ret);
    };

    private static void TwentyNops(InstructionEncoder il)
    {
        for (var i = 0; i < 20; i++)
            il.OpCode(ILOpCode.Nop);
        il.LoadConstantI4(0);
        il.OpCode(ILOpCode.Ret);
    }

    internal static ProbeRun Lift(string path, int maxDepth = 0, int maxInstructions = 0) => Lift([path], maxDepth, maxInstructions);

    /// <summary>Lifts the assemblies in one child; asserts the child finished cleanly with every assembly read.</summary>
    internal static ProbeRun Lift(IReadOnlyList<string> paths, int maxDepth = 0, int maxInstructions = 0)
    {
        var result = ChildProcessProbe.Run(ProbeExe, TimeSpan.FromSeconds(180),
            [SsaLiftProbe.Verb, maxDepth.ToString(CultureInfo.InvariantCulture), maxInstructions.ToString(CultureInfo.InvariantCulture), .. paths]);
        Assert.True(result.ExitedCleanly, result.Describe());
        var lines = result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.True(lines is [.., "DONE"], "The probe did not finish its output.");
        Assert.Equal(paths.Count, lines.Count(l => l.StartsWith("ASSEMBLY True ", StringComparison.Ordinal)));
        return new ProbeRun(result.StandardOutput, lines
            .Where(l => l.StartsWith("OUTCOME ", StringComparison.Ordinal))
            .Select(l => l.Split(' ', 4))
            .Select(f => (Method: Unescape(f[1]), Kind: f[2], Reason: Unescape(f[3])))
            .ToList());
    }

    // Undoes the probe's \uXXXX escaping (SsaLiftProbe.Escape); the text is only ever compared, never printed raw.
    private static string Unescape(string text) =>
        Regex.Replace(text, @"\\u([0-9A-F]{4})", m => ((char)int.Parse(m.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture)).ToString());
    #endregion

    #region Fields
    internal static readonly string ProbeExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe");

    // Past the universe-wide nesting bound of nested source answers (256).
    private const int ChainLength = 320;

    private static BlobBuilder StaticInt => RawAssembly.MethodSig(false, r => r.Type().Int32());
    private static BlobBuilder StaticVoid => RawAssembly.MethodSig(false, r => r.Void());
    private static BlobBuilder InstanceInt => RawAssembly.MethodSig(true, r => r.Type().Int32());
    #endregion

    #region Child types
    /// <summary>One child's outcomes: (<c>Namespace.Type::Method</c>, kind or <c>Lifted</c>, reason), unescaped.</summary>
    internal sealed record ProbeRun(string Output, IReadOnlyList<(string Method, string Kind, string Reason)> Outcomes)
    {
        public (string Method, string Kind, string Reason) Of(string method)
        {
            var matches = Outcomes.Where(o => o.Method == method).ToArray();
            Assert.True(matches.Length == 1, $"Expected one outcome for {method}, found {matches.Length}:{Environment.NewLine}{Output}");
            return matches[0];
        }

        public void AssertLifted(string method)
        {
            var outcome = Of(method);
            Assert.True(outcome.Kind == "Lifted", SsaText.Printable($"{method}: {outcome.Kind} {outcome.Reason}"));
        }

        public void AssertNotLifted(string method) =>
            Assert.True(Of(method).Kind != "Lifted", $"{method} lifted.");

        public void AssertFailed(string method, SsaFailureKind kind, string? reasonPart = null)
        {
            var outcome = Of(method);
            Assert.True(outcome.Kind == kind.ToString(), SsaText.Printable($"{method}: expected {kind}, got {outcome.Kind} {outcome.Reason}"));
            if (reasonPart is not null)
                Assert.True(outcome.Reason.Contains(reasonPart, StringComparison.Ordinal), SsaText.Printable($"{method}: expected '{reasonPart}' in {outcome.Reason}"));
        }

        /// <summary>Failed in the adapter or the reader, before Cilica saw the method: the input was malformed, not Cilica's input.</summary>
        public void AssertFailedBeforeCilica(string method)
        {
            var outcome = Of(method);
            Assert.True(outcome.Kind is nameof(SsaFailureKind.Adapter) or nameof(SsaFailureKind.Unreadable) or nameof(SsaFailureKind.ReaderAssertion),
                SsaText.Printable($"{method}: expected an adapter or reader failure, got {outcome.Kind} {outcome.Reason}"));
        }
    }
    #endregion
}
