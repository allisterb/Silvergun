namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using Cci = Microsoft.Cci;

/// <summary>
/// A hostile TypeSpec DAG (T_k = <c>Big.Pair&lt;T_k-1,T_k-1&gt;</c>, 2^(k+2)-1 parts as a tree) written row by row
/// (<see cref="RawAssembly"/>), with an oversized instance (more than <c>CCIProvider.TypeSize.MaxParts</c>) in several
/// signature positions, and <c>Big.Holder.Caller</c> calling each method once. Read both ways
/// (<see cref="CanonicalNameLayersFixture"/>) and as a <see cref="MethodGraph"/>. Metadata only; nothing runs.
/// docs/agent/tasks/graph-names-hostile-types.md.
/// <para>
/// <c>Big.Holder.Tokens</c> holds one <c>ldtoken</c> per <see cref="Token"/>, in that order, so a test can read a level's
/// own CCI <see cref="Cci.ITypeReference"/> (its TypeSpec row) and measure it independently of any signature.
/// </para>
/// </summary>
public sealed class OversizedTypeFixture : IDisposable
{
    #region Constructors
    public OversizedTypeFixture()
    {
        Path = Write(temp.Path, out var offsets);
        CallOffsets = offsets;
        try
        {
            Layers = new CanonicalNameLayersFixture(Path);
            Assemblies = ModelAssemblies.Load(Path);
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
        }
        catch (Exception)
        {
            Assemblies?.Dispose();
            Layers?.Dispose();
            temp.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string Path { get; }

    public CanonicalNameLayersFixture Layers { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public MethodGraph Graph { get; }

    /// <summary>The IL offset of <c>Caller</c>'s call to each method, by the method's name in <see cref="Calls"/>.</summary>
    public IReadOnlyDictionary<string, uint> CallOffsets { get; }
    #endregion

    #region Methods
    /// <summary>The <see cref="Token"/> references of <c>Tokens</c>'s body, from <paramref name="assembly"/> (any load of <see cref="Path"/>).</summary>
    public static IReadOnlyDictionary<Token, Cci.ITypeReference> Tokens(AssemblyAnalyzer assembly)
    {
        var method = Assert.Single(assembly.Methods, m => m.Name.Value == "Tokens");
        var body = AssemblyAnalyzer.TryReadBody(method).Body ?? throw new InvalidOperationException("Tokens has no readable body.");
        var types = body.Operations.Where(o => o.OperationCode == Cci.OperationCode.Ldtoken).Select(o => (Cci.ITypeReference)o.Value).ToArray();
        var order = Enum.GetValues<Token>();
        Assert.Equal(order.Length, types.Length);
        return order.Zip(types).ToDictionary(p => p.First, p => p.Second);
    }

    /// <summary>T_<paramref name="k"/>'s token.</summary>
    public static Token T(int k) => Token.T0 + k;

    public void Dispose()
    {
        Assemblies.Dispose();
        Layers.Dispose();
        temp.Dispose();
    }

    private static string Write(string directory, out IReadOnlyDictionary<string, uint> offsets)
    {
        var raw = new RawAssembly("OversizedTypes");
        var pair = raw.Type("Big", "Pair`2", raw.Object);
        raw.GenericParameter(pair, "A", 0);
        raw.GenericParameter(pair, "B", 1);
        var box = raw.Type("Big", "Box`1", raw.Object);
        raw.GenericParameter(box, "T", 0);
        var outer = raw.Type("Big", "Outer`1", raw.Object);
        raw.GenericParameter(outer, "T", 0);
        // Outer<T>.Inner: no own parameters, so its one generic parameter is the containing type's T (ECMA redeclares it).
        var inner = raw.Type(null, "Inner", raw.Object, TypeAttributes.NestedPublic | TypeAttributes.Class);
        raw.GenericParameter(inner, "T", 0);
        // Outer<T>.Inner2<U>: one parameter of its own, so an instance of it is a generic instance over both links.
        var inner2 = raw.Type(null, "Inner2`1", raw.Object, TypeAttributes.NestedPublic | TypeAttributes.Class);
        raw.GenericParameter(inner2, "T", 0);
        raw.GenericParameter(inner2, "U", 1);

        var t = Chain(raw, pair, Depth, e => e.Int32());
        var u = Chain(raw, pair, OversizedDepth, e => e.String());

        void PairOf(SignatureTypeEncoder e, TypeSpecificationHandle a, TypeSpecificationHandle b)
        {
            var arguments = e.GenericInstantiation(pair, 2, isValueType: false);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), a);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), b);
        }
        void Of(SignatureTypeEncoder e, TypeDefinitionHandle generic, TypeSpecificationHandle argument) =>
            SsaTypeNameDagFixture.ClassOf(e.GenericInstantiation(generic, 1, isValueType: false).AddArgument(), argument);

        void Inner2Of(SignatureTypeEncoder e, TypeSpecificationHandle argument)
        {
            var arguments = e.GenericInstantiation(inner2, 2, isValueType: false);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), argument);
            arguments.AddArgument().Int32();
        }

        var t11 = t[OversizedDepth];
        var t10 = t[EdgeDepth];
        var specs = new Dictionary<Token, TypeSpecificationHandle>();
        for (var k = 0; k <= Depth; k++)
            specs[T(k)] = t[k];
        specs[Token.U11] = u[OversizedDepth];
        specs[Token.PairT11T11] = raw.TypeSpec(e => PairOf(e, t11, t11));
        specs[Token.PairT11T10] = raw.TypeSpec(e => PairOf(e, t11, t10));
        specs[Token.BoxT11] = raw.TypeSpec(e => Of(e, box, t11));
        specs[Token.BoxT10] = raw.TypeSpec(e => Of(e, box, t10));
        specs[Token.InnerT11] = raw.TypeSpec(e => Of(e, inner, t11));
        specs[Token.Inner2T11] = raw.TypeSpec(e => Inner2Of(e, t11));
        specs[Token.PairT10Int] = raw.TypeSpec(e =>
        {
            var arguments = e.GenericInstantiation(pair, 2, isValueType: false);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), t10);
            arguments.AddArgument().Int32();
        });

        raw.Type("Big", "Holder", raw.Object, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        BlobBuilder Takes(Action<SignatureTypeEncoder> parameter) => RawAssembly.MethodSig(false, r => r.Void(), parameter);
        void Ret(InstructionEncoder il) => il.OpCode(ILOpCode.Ret);
        // Each parameter is written inline (a GENERICINST whose arguments are CLASS TypeSpec), as the S4.5 fixture does, so
        // the signature's outer instance is its own object, distinct from the TypeSpec row of the same shape.
        var targets = new (string Name, MethodDefinitionHandle Handle)[]
        {
            ("TakeOversized", raw.Static("TakeOversized", Takes(p => PairOf(p, t10, t10)), Ret)),
            ("TakeArray", raw.Static("TakeArray", Takes(p => PairOf(p.SZArray(), t10, t10)), Ret)),
            ("TakeByRef", raw.Static("TakeByRef", Takes(p =>
            {
                p.Builder.WriteByte((byte)SignatureTypeCode.ByReference);
                PairOf(p, t10, t10);
            }), Ret)),
            ("TakeBox", raw.Static("TakeBox", Takes(p => Of(p, box, t11)), Ret)),
            ("TakeNested", raw.Static("TakeNested", Takes(p => Of(p, inner, t11)), Ret)),
            ("TakeNestedOwn", raw.Static("TakeNestedOwn", Takes(p => Inner2Of(p, t11)), Ret)),
            ("OverT", raw.Static("Over", Takes(p => PairOf(p, t10, t10)), Ret)),
            ("OverU", raw.Static("Over", Takes(p => PairOf(p, u[EdgeDepth], u[EdgeDepth])), Ret)),
            ("TakeJustOver", raw.Static("TakeJustOver", Takes(p =>
            {
                var arguments = p.GenericInstantiation(pair, 2, isValueType: false);
                SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), t10);
                arguments.AddArgument().Int32();
            }), Ret)),
            // delegate*<T_11, void>: a FNPTR signature whose one parameter is the oversized instance.
            ("TakeFnPtr", raw.Static("TakeFnPtr", Takes(p => p.FunctionPointer().Parameters(1, r => r.Void(), ps => PairOf(ps.AddParameter().Type(), t10, t10))), Ret)),
            ("TakeEdge", raw.Static("TakeEdge", Takes(p => PairOf(p, t[EdgeDepth - 1], t[EdgeDepth - 1])), Ret)),
            ("TakeBoxEdge", raw.Static("TakeBoxEdge", Takes(p => Of(p, box, t10)), Ret)),
        };

        raw.Static("Tokens", RawAssembly.MethodSig(false, r => r.Void()), il =>
        {
            foreach (var token in Enum.GetValues<Token>())
            {
                il.OpCode(ILOpCode.Ldtoken);
                il.Token(specs[token]);
                il.OpCode(ILOpCode.Pop);
            }
            il.OpCode(ILOpCode.Ret);
        });

        var at = new Dictionary<string, uint>();
        raw.Static("Caller", RawAssembly.MethodSig(false, r => r.Void()), il =>
        {
            foreach (var (name, handle) in targets)
            {
                il.OpCode(ILOpCode.Ldnull);
                at[name] = (uint)il.Offset;
                il.Call(handle);
            }
            il.OpCode(ILOpCode.Ret);
        });
        raw.Nest(inner, outer);
        raw.Nest(inner2, outer);
        offsets = at;
        return raw.Save(directory);
    }

    /// <summary>TypeSpec rows L_0 = <c>Pair&lt;leaf,leaf&gt;</c> .. L_<paramref name="depth"/> = <c>Pair&lt;L_depth-1,L_depth-1&gt;</c>.</summary>
    private static List<TypeSpecificationHandle> Chain(RawAssembly raw, TypeDefinitionHandle pair, int depth, Action<SignatureTypeEncoder> leaf)
    {
        var specs = new List<TypeSpecificationHandle>
        {
            raw.TypeSpec(s =>
            {
                var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
                leaf(arguments.AddArgument());
                leaf(arguments.AddArgument());
            }),
        };
        for (var k = 1; k <= depth; k++)
        {
            var previous = specs[^1];
            specs.Add(raw.TypeSpec(s =>
            {
                var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
                SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), previous);
                SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), previous);
            }));
        }
        return specs;
    }
    #endregion

    #region Fields
    /// <summary>The deepest level written (T_20: about 4M parts as a tree).</summary>
    public const int Depth = 20;

    /// <summary>The largest level within the bound: T_10, 4,095 parts.</summary>
    public const int EdgeDepth = 10;

    /// <summary>The first level past it: T_11, 8,191 parts.</summary>
    public const int OversizedDepth = 11;

    /// <summary>Every method <c>Caller</c> calls, in call order (<c>OverT</c>/<c>OverU</c> are both named <c>Over</c>).</summary>
    public static readonly string[] Calls =
        ["TakeOversized", "TakeArray", "TakeByRef", "TakeBox", "TakeNested", "TakeNestedOwn", "OverT", "OverU", "TakeJustOver", "TakeFnPtr", "TakeEdge", "TakeBoxEdge"];

    private readonly SsaTempDirectory temp = new();
    #endregion

    #region Types
    /// <summary>The types <c>Tokens</c> loads, in order: T_0..T_20, then the shapes built from them.</summary>
    public enum Token
    {
        T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20,
        /// <summary>U_11: T_11's shape over <c>string</c> leaves (the same parts, another structure).</summary>
        U11,
        /// <summary><c>Pair&lt;T_11,T_11&gt;</c>, its own row: T_12's structure.</summary>
        PairT11T11,
        PairT11T10,
        /// <summary><c>Box&lt;T_11&gt;</c>: 8,192 parts.</summary>
        BoxT11,
        /// <summary><c>Box&lt;T_10&gt;</c>: exactly 4,096 parts, the bound itself.</summary>
        BoxT10,
        /// <summary><c>Outer&lt;T_11&gt;.Inner</c>.</summary>
        InnerT11,
        /// <summary><c>Outer&lt;T_11&gt;.Inner2&lt;int32&gt;</c>.</summary>
        Inner2T11,
        /// <summary><c>Pair&lt;T_10,int32&gt;</c>: 4,097 parts, one past the bound.</summary>
        PairT10Int,
    }
    #endregion
}
