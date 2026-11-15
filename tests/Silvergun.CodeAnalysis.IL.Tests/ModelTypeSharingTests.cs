namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

using CCIProvider;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using static Silvergun.CodeAnalysis.IL.Tests.SyntheticModel;

using Cci = Microsoft.Cci;
using ModelBytecode = Model.Bytecode;
using ModelTypes = Model.Types;

/// <summary>
/// CCIProvider's <c>TypeExtractor</c> builds one Model <see cref="ModelTypes.BasicType"/> per CCI generic-instance object
/// (our fork). CCI caches a TypeSpec row's decoded type per (owner, row), so the TypeSpec DAG T_k = <c>Big.Pair&lt;T_k-1,T_k-1&gt;</c>
/// stays a DAG in the Model (about k+1 instances) instead of a 2^k tree per reference. Names and equality are unchanged.
/// Under the char bound (names-chars-and-lift-cancellation.md) the Model builds T_k whole up to T_5 (2,665 chars) and T_6
/// (5,353 chars, 255 parts) is the first oversized level, so sharing is observed at T_0..T_5.
/// </summary>
public sealed class ModelTypeSharingTests : IClassFixture<ModelTypeSharingFixture>
{
    #region Constructors
    public ModelTypeSharingTests(ModelTypeSharingFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- The Model is a DAG ---------------------------------------------------------------------------------------------

    /// <summary>At every level of T_k, both generic arguments are one object: T_k-1's (up to T_5, the largest level built).</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(ModelTypeSharingFixture.EdgeDepth)]
    public void Tk_BothArgumentsAreTheSameObject_AtEveryLevel(int k)
    {
        var level = Tokens(fixture.First)[k];

        for (var i = k; i >= 0; i--)
        {
            var type = Assert.IsType<ModelTypes.BasicType>(level);
            Assert.Null(type.Oversized);
            Assert.Equal(2, type.GenericArguments.Count);
            Assert.Same(type.GenericArguments[0], type.GenericArguments[1]);
            level = type.GenericArguments[0];
        }
        Assert.Equal("Int32", Assert.IsAssignableFrom<ModelTypes.IBasicType>(level).Name);
    }

    /// <summary>T_k reaches exactly k+1 distinct generic instances (by reference), not 2^(k+1)-1, and few objects overall.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(ModelTypeSharingFixture.EdgeDepth)]
    public void Tk_ReachesKPlusOneDistinctInstances(int k)
    {
        var reachable = Reachable(Tokens(fixture.First)[k]);

        Assert.Equal(k + 1, reachable.Count(t => t.GenericArguments.Count > 0));
        // Plus the leaf (System.Int32, possibly two objects) and nothing else through GenericArguments.
        Assert.InRange(reachable.Count, k + 2, k + 3);
    }

    /// <summary>
    /// Within one owner (the <c>Tokens</c> body) CCI shares each TypeSpec row's object, including the rows a TypeSpec blob
    /// refers to; so T_k's argument is the very Model object of T_k-1's own <c>ldtoken</c>.
    /// </summary>
    [Fact]
    public void WithinOneBody_TkArgument_IsTheSameObjectAsTkMinus1sOwnToken()
    {
        var cci = CciTokens("Tokens");
        var model = Tokens(fixture.First);

        for (var k = 1; k <= ModelTypeSharingFixture.EdgeDepth; k++)
        {
            Assert.Same(cci[k - 1], ((Cci.IGenericTypeInstanceReference)cci[k]).GenericArguments.First()); // the premise
            Assert.Same(model[k - 1], ((ModelTypes.BasicType)model[k]).GenericArguments[0]);
        }
    }

    /// <summary>
    /// <c>Repeats</c> loads T_5 and T_6 <see cref="ModelTypeSharingFixture.Repeats"/> times each: CCI hands over one object per
    /// row, and so does the Model, oversized instance included.
    /// </summary>
    [Fact]
    public void RepeatedTokensInOneBody_YieldOneModelObjectPerRow_OversizedIncluded()
    {
        var cci = CciTokens("Repeats");
        var model = TokenInstructions(fixture.First, "Repeats").Select(i => i.Token).ToArray();
        Assert.Equal(2 * ModelTypeSharingFixture.Repeats, model.Length);

        foreach (var (start, k) in new[] { (0, ModelTypeSharingFixture.EdgeDepth), (ModelTypeSharingFixture.Repeats, ModelTypeSharingFixture.OversizedDepth) })
        {
            var cciRun = cci.Skip(start).Take(ModelTypeSharingFixture.Repeats).ToArray();
            var modelRun = model.Skip(start).Take(ModelTypeSharingFixture.Repeats).ToArray();
            Assert.All(cciRun, c => Assert.Same(cciRun[0], c)); // the premise
            Assert.All(modelRun, m => Assert.Same(modelRun[0], m));
            Assert.Equal(k == ModelTypeSharingFixture.OversizedDepth, ((ModelTypes.BasicType)modelRun[0]).Oversized is not null);
        }
    }

    /// <summary>
    /// Bounded cost: the distinct BasicTypes reachable from all of <c>Repeats</c>'s 200 tokens are as many as from one T_5 and
    /// one T_6 alone (6 instances + leaf, + the oversized T_6), so they do not grow with the reference count.
    /// </summary>
    [Fact]
    public void RepeatedTokens_DoNotGrowTheNumberOfDistinctTypes()
    {
        var all = TokenInstructions(fixture.First, "Repeats").Select(i => i.Token).OfType<ModelTypes.IType>().ToArray();
        var once = TokenInstructions(fixture.First, "Once").Select(i => i.Token).OfType<ModelTypes.IType>().ToArray();
        Assert.Equal(2, once.Length);

        var fromAll = Reachable(all);
        var fromOnce = Reachable(once);

        Assert.Equal(fromOnce.Count(t => t.GenericArguments.Count > 0), fromAll.Count(t => t.GenericArguments.Count > 0));
        Assert.Equal(ModelTypeSharingFixture.EdgeDepth + 1, fromAll.Count(t => t.GenericArguments.Count > 0));
        Assert.InRange(fromAll.Count, ModelTypeSharingFixture.EdgeDepth + 3, ModelTypeSharingFixture.EdgeDepth + 4);
    }

    /// <summary>
    /// Two parameters of one signature that name the same TypeSpec row (<c>class T_5</c> twice) are one Model object, as they
    /// are one CCI object; the same for the oversized T_6.
    /// </summary>
    [Theory]
    [InlineData("TakeTwice")]
    [InlineData("TakeOversizedTwice")]
    public void TwoParametersNamingOneTypeSpec_AreTheSameModelObject(string method)
    {
        var cci = Assert.Single(fixture.CciAnalyzer.Methods, m => m.Name.Value == method).Parameters.Select(p => p.Type).ToArray();
        Assert.Equal(2, cci.Length);
        Assert.Same(cci[0], cci[1]); // the premise

        var model = Definition(fixture.First, method).Parameters.Select(p => p.Type).ToArray();
        Assert.Same(model[0], model[1]);
    }

    // ---- Names are unchanged --------------------------------------------------------------------------------------------

    /// <summary>A shared-argument type spells both arguments out in full: no cycle or unknown marker, no elision.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(ModelTypeSharingFixture.EdgeDepth)]
    public void SharedArgumentType_RendersBothArgumentsWhole(int k)
    {
        var name = ModelNames.TypeName(Tokens(fixture.First)[k]);

        Assert.Equal(OversizedTypeNameTestsSupport.Name(k), name);
        Assert.DoesNotContain(CanonicalName.UnknownPart, name, StringComparison.Ordinal);
        Assert.False(CanonicalName.HasOversized(name));
    }

    [Fact]
    public void SharedArgumentType_AtLevelOne_IsSpelledOutLiterally() =>
        Assert.Equal(
            "Big.Pair`2<Big.Pair`2<System.Int32,System.Int32>,Big.Pair`2<System.Int32,System.Int32>>",
            ModelNames.TypeName(Tokens(fixture.First)[1]));

    /// <summary>
    /// Node ids of methods over the shared DAG: within the bound the parameters render whole (both of <c>TakeTwice</c>'s, and
    /// the inline <c>Pair&lt;T_4,T_4&gt;</c>); past it, the marker carrying T_6's measured parts and hash. T_6 is within
    /// <c>MaxParts</c> (255), cut by chars alone.
    /// </summary>
    [Fact]
    public void NodeIds_OfMethodsOverTheSharedDag_AreUnchanged()
    {
        var edge = OversizedTypeNameTestsSupport.Name(ModelTypeSharingFixture.EdgeDepth);
        var oversized = CciTokens("Tokens")[ModelTypeSharingFixture.OversizedDepth];
        var marker = CanonicalName.Oversized(TypeSize.Parts(oversized), TypeSize.Hash(oversized));
        Assert.Equal(255L, TypeSize.Parts(oversized));
        Assert.Equal(5353L, TypeSize.Chars(oversized));

        Assert.Equal($"Big.Holder.TakeTwice({edge},{edge})", NodeId("TakeTwice"));
        Assert.Equal($"Big.Holder.TakeInline({edge})", NodeId("TakeInline"));
        Assert.Equal($"Big.Holder.TakeOversizedTwice({marker},{marker})", NodeId("TakeOversizedTwice"));
    }

    /// <summary>The oversized T_6 token, and T_11 past both bounds, render the marker too: memoising them did not give them arguments.</summary>
    [Theory]
    [InlineData(ModelTypeSharingFixture.OversizedDepth)]
    [InlineData(ModelTypeSharingFixture.Depth)]
    public void OversizedToken_RendersTheMarker_WithNoArguments(int k)
    {
        var model = Assert.IsType<ModelTypes.BasicType>(Tokens(fixture.First)[k]);
        var cci = CciTokens("Tokens")[k];

        Assert.Empty(model.GenericArguments);
        Assert.Equal(CanonicalName.Oversized(TypeSize.Parts(cci), TypeSize.Hash(cci)), ModelNames.TypeName(model));
    }

    // ---- BasicType.Equals -----------------------------------------------------------------------------------------------

    /// <summary>An instance equals itself: with arguments (T_0, T_5) and oversized (T_6, T_11).</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(11)]
    public void Equals_AnInstance_EqualsItself(int k)
    {
        var type = Tokens(fixture.First)[k];

        Assert.True(type.Equals(type));
        Assert.Equal(type, type);
    }

    /// <summary>
    /// Two independent loads (two extractors, nothing shared between them) build distinct T_k objects that still compare
    /// equal both ways, with equal hash codes.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(11)]
    public void Equals_TkFromTwoIndependentLoads_AreDistinctButEqual(int k)
    {
        var a = Tokens(fixture.First)[k];
        var b = Tokens(fixture.Second)[k];

        Assert.NotSame(a, b);
        Assert.True(a.Equals(b));
        Assert.True(b.Equals(a));
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    /// <summary>Different levels are not equal, shared objects or not (same load, and across loads).</summary>
    [Theory]
    [InlineData(0, 1)]
    [InlineData(4, 5)]
    [InlineData(5, 6)]
    [InlineData(10, 11)]
    public void Equals_DifferentLevels_AreNotEqual(int j, int k)
    {
        var first = Tokens(fixture.First);
        var second = Tokens(fixture.Second);

        Assert.False(first[j].Equals(first[k]));
        Assert.False(first[k].Equals(first[j]));
        Assert.False(first[j].Equals(second[k]));
        Assert.False(second[k].Equals(first[j]));
    }

    /// <summary>Hand-built: two distinct, structurally equal instances with arguments compare equal; a different argument does not.</summary>
    [Fact]
    public void Equals_HandBuiltInstances_StructuralEqualityStillHolds()
    {
        ModelTypes.BasicType Pair(string leaf) =>
            TypeRef("Big", "Pair", 2, assembly: "Lib", arguments: [TypeRef("System", leaf, assembly: "Lib"), TypeRef("System", leaf, assembly: "Lib")]);
        var a = Pair("Int32");
        var b = Pair("Int32");
        var c = Pair("String");

        Assert.NotSame(a, b);
        Assert.True(a.Equals(a));
        Assert.True(a.Equals(b));
        Assert.False(a.Equals(c));
        Assert.False(c.Equals(a));
        Assert.False(a.Equals(null));
    }

    /// <summary>
    /// The identity shortcut does not change a hand-built instance whose shared argument appears twice: it equals an unshared
    /// copy with two separate (equal) arguments.
    /// </summary>
    [Fact]
    public void Equals_SharedArgumentsAndUnsharedCopies_AreEqual()
    {
        var leaf = TypeRef("System", "Int32", assembly: "Lib");
        var shared = TypeRef("Big", "Pair", 2, assembly: "Lib", arguments: [leaf, leaf]);
        var unshared = TypeRef("Big", "Pair", 2, assembly: "Lib", arguments: [TypeRef("System", "Int32", assembly: "Lib"), TypeRef("System", "Int32", assembly: "Lib")]);

        Assert.True(shared.Equals(unshared));
        Assert.True(unshared.Equals(shared));
    }

    // ---- Helpers --------------------------------------------------------------------------------------------------------

    // Every BasicType reachable from roots through GenericArguments, by reference identity.
    private static HashSet<ModelTypes.BasicType> Reachable(params ModelTypes.IType[] roots)
    {
        var seen = new HashSet<ModelTypes.BasicType>(ReferenceEqualityComparer.Instance);
        var pending = new Stack<ModelTypes.IType>(roots);
        while (pending.TryPop(out var type))
            if (type is ModelTypes.BasicType basic && seen.Add(basic))
                foreach (var argument in basic.GenericArguments)
                    pending.Push(argument);
        return seen;
    }

    private static ModelTypes.MethodDefinition Definition(AssemblyDisassembler assembly, string name) =>
        Assert.Single(assembly.Methods, m => m.Name == name);

    private static ModelBytecode.LoadTokenInstruction[] TokenInstructions(AssemblyDisassembler assembly, string method) =>
        Definition(assembly, method).Body.Instructions.OfType<ModelBytecode.LoadTokenInstruction>().ToArray();

    // T_0..T_11 as Model types, from the Tokens body.
    private static ModelTypes.IType[] Tokens(AssemblyDisassembler assembly)
    {
        var tokens = TokenInstructions(assembly, "Tokens").Select(i => Assert.IsAssignableFrom<ModelTypes.IType>(i.Token)).ToArray();
        Assert.Equal(ModelTypeSharingFixture.Depth + 1, tokens.Length);
        return tokens;
    }

    private Cci.ITypeReference[] CciTokens(string method)
    {
        var definition = Assert.Single(fixture.CciAnalyzer.Methods, m => m.Name.Value == method);
        var body = AssemblyAnalyzer.TryReadBody(definition).Body ?? throw new InvalidOperationException($"{method} has no readable body.");
        return body.Operations.Where(o => o.OperationCode == Cci.OperationCode.Ldtoken).Select(o => (Cci.ITypeReference)o.Value).ToArray();
    }

    private string NodeId(string method) => CanonicalName.NodeId(ModelNames.Of(Definition(fixture.First, method)));
    #endregion

    #region Fields
    private readonly ModelTypeSharingFixture fixture;
    #endregion
}

/// <summary>
/// <c>ModelTypeSharing.dll</c> (<see cref="RawAssembly"/>): <c>Big.Pair`2</c>, the TypeSpec chain T_0..T_11 over <c>int32</c>,
/// and <c>Big.Holder</c> with <c>Tokens</c> (one <c>ldtoken</c> per level, in order), <c>Repeats</c> (T_5 then T_6,
/// <see cref="Repeats"/> times each), <c>Once</c> (T_5 and T_6 once), <c>TakeTwice(class T_5, class T_5)</c>,
/// <c>TakeOversizedTwice(class T_6, class T_6)</c> and <c>TakeInline(Pair&lt;class T_4, class T_4&gt;)</c>. Loaded twice
/// through CCIProvider (two independent hosts) and once through raw CCI. Metadata only; nothing runs.
/// </summary>
public sealed class ModelTypeSharingFixture : IDisposable
{
    #region Constructors
    public ModelTypeSharingFixture()
    {
        Path = Write(temp.Path);
        try
        {
            Assemblies = ModelAssemblies.Load(Path, Path);
            var cci = AssemblyAnalyzer.Load(Path);
            CciAnalyzer = cci.IsSuccess ? cci.Value : throw new InvalidOperationException($"Failed to load '{Path}': {cci.Message}", cci.Exception);
        }
        catch (Exception)
        {
            Assemblies?.Dispose();
            temp.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string Path { get; }

    public ModelAssemblies Assemblies { get; }

    public AssemblyDisassembler First => Assemblies.Disassemblers[0];

    public AssemblyDisassembler Second => Assemblies.Disassemblers[1];

    public AssemblyAnalyzer CciAnalyzer { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        CciAnalyzer.Dispose();
        Assemblies.Dispose();
        temp.Dispose();
    }

    private static string Write(string directory)
    {
        var raw = new RawAssembly("ModelTypeSharing");
        var pair = raw.Type("Big", "Pair`2", raw.Object);
        raw.GenericParameter(pair, "A", 0);
        raw.GenericParameter(pair, "B", 1);

        var t = new List<TypeSpecificationHandle>
        {
            raw.TypeSpec(s =>
            {
                var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
                arguments.AddArgument().Int32();
                arguments.AddArgument().Int32();
            }),
        };
        for (var k = 1; k <= Depth; k++)
        {
            var previous = t[^1];
            t.Add(raw.TypeSpec(s => PairOf(s, previous)));
        }

        void PairOf(SignatureTypeEncoder e, TypeSpecificationHandle argument)
        {
            var arguments = e.GenericInstantiation(pair, 2, isValueType: false);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), argument);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), argument);
        }
        void Ret(InstructionEncoder il) => il.OpCode(ILOpCode.Ret);
        void Load(InstructionEncoder il, TypeSpecificationHandle spec)
        {
            il.OpCode(ILOpCode.Ldtoken);
            il.Token(spec);
            il.OpCode(ILOpCode.Pop);
        }
        BlobBuilder None() => RawAssembly.MethodSig(false, r => r.Void());

        raw.Type("Big", "Holder", raw.Object, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        raw.Static("Tokens", None(), il =>
        {
            t.ForEach(spec => Load(il, spec));
            Ret(il);
        });
        raw.Static("Repeats", None(), il =>
        {
            foreach (var spec in new[] { t[EdgeDepth], t[OversizedDepth] })
                for (var i = 0; i < Repeats; i++)
                    Load(il, spec);
            Ret(il);
        });
        raw.Static("Once", None(), il =>
        {
            Load(il, t[EdgeDepth]);
            Load(il, t[OversizedDepth]);
            Ret(il);
        });
        raw.Static("TakeTwice", RawAssembly.MethodSig(false, r => r.Void(),
            p => SsaTypeNameDagFixture.ClassOf(p, t[EdgeDepth]), p => SsaTypeNameDagFixture.ClassOf(p, t[EdgeDepth])), Ret);
        raw.Static("TakeOversizedTwice", RawAssembly.MethodSig(false, r => r.Void(),
            p => SsaTypeNameDagFixture.ClassOf(p, t[OversizedDepth]), p => SsaTypeNameDagFixture.ClassOf(p, t[OversizedDepth])), Ret);
        raw.Static("TakeInline", RawAssembly.MethodSig(false, r => r.Void(), p => PairOf(p, t[EdgeDepth - 1])), Ret);
        return raw.Save(directory);
    }
    #endregion

    #region Fields
    /// <summary>The largest level within the bound (<c>TypeSize.MaxChars</c>): T_5, 2,665 chars.</summary>
    public const int EdgeDepth = 5;

    /// <summary>The first level past it: T_6, 5,353 chars, 255 parts (within <c>MaxParts</c>).</summary>
    public const int OversizedDepth = 6;

    /// <summary>The deepest level written: T_11, 8,191 parts, past both bounds.</summary>
    public const int Depth = 11;

    /// <summary>How many times <c>Repeats</c> loads each of T_5 and T_6.</summary>
    public const int Repeats = 100;

    private readonly SsaTempDirectory temp = new();
    #endregion
}
