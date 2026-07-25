namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The pure formatter (<see cref="CanonicalName"/>) and the two identity structs. No assembly is loaded and
/// no object model is touched, so every rule in the canonical-naming spec can be pinned exhaustively here:
/// outer-to-inner nesting, generic stripping in the classification key, arity and signature in the node id,
/// positional generic parameters, the decoration renderers, and the never-throws / never-empty contract.
/// </summary>
public sealed class CanonicalNameTests
{
    #region Methods
    // The defect this whole component exists to avoid: Analysis.Net's GetFullName reverses the containing-type
    // prefix at depth 3 or more, turning Outer.Middle.Inner into Middle.Outer.Inner.
    [Fact]
    public void ClassificationKey_NestedTypeDepthThree_IsOuterToInner()
    {
        var type = new TypeIdentity("Newtonsoft.Json", ["JsonValidatingReader", "SchemaScope", "<>c"], 0);

        var key = CanonicalName.ClassificationKey(type);

        Assert.Equal("Newtonsoft.Json.JsonValidatingReader.SchemaScope.<>c", key);
    }

    // Generic decoration never appears in a classification key: catalog entries stay human-writable.
    [Fact]
    public void ClassificationKey_GenericType_StripsDecoration()
    {
        var method = Method(Type("System.Collections.Generic", 1, "Dictionary"), "TryGetValue", 0, "!0", "!1&");

        var key = CanonicalName.ClassificationKey(method);

        Assert.Equal("System.Collections.Generic.Dictionary.TryGetValue", key);
        Assert.DoesNotContain("`", key, StringComparison.Ordinal);
    }

    // The node id carries the CLR arity suffix on both the declaring type and the method.
    [Fact]
    public void NodeId_GenericTypeAndMethod_IncludesArity()
    {
        var method = Method(Type("Silvergun", 1, "Box"), "Convert", 1, "!0", "!!0");

        Assert.Equal("Silvergun.Box`1.Convert`1(!0,!!0)", CanonicalName.NodeId(method));
        Assert.Equal("Silvergun.Box`1", CanonicalName.NodeId(method.DeclaringType));
    }

    // Overloads are what the node id exists to separate.
    [Fact]
    public void NodeId_Overloads_AreDistinct()
    {
        var ints = Method(Type("Silvergun", 0, "Shapes"), "Describe", 0, "System.Int32");
        var strings = Method(Type("Silvergun", 0, "Shapes"), "Describe", 0, "System.String");
        var arrays = Method(Type("Silvergun", 0, "Shapes"), "Describe", 0, "System.Int32[]");
        var none = Method(Type("Silvergun", 0, "Shapes"), "Describe", 0);

        var ids = new[] { ints, strings, arrays, none }.Select(CanonicalName.NodeId).ToArray();

        Assert.Equal(ids.Length, ids.Distinct(StringComparer.Ordinal).Count());
    }

    // ...and which the classification key deliberately merges.
    [Fact]
    public void ClassificationKey_Overloads_AreEqual()
    {
        var ints = Method(Type("Silvergun", 0, "Shapes"), "Describe", 0, "System.Int32");
        var strings = Method(Type("Silvergun", 0, "Shapes"), "Describe", 0, "System.String");

        Assert.Equal(CanonicalName.ClassificationKey(ints), CanonicalName.ClassificationKey(strings));
        Assert.Equal("Silvergun.Shapes.Describe", CanonicalName.ClassificationKey(ints));
    }

    // Generic parameters are positional (ECMA-335/ILDasm), because the Model layer loses their names.
    [Fact]
    public void NodeId_GenericParameters_ArePositional()
    {
        Assert.Equal("!0", CanonicalName.TypeGenericParameter(0));
        Assert.Equal("!1", CanonicalName.TypeGenericParameter(1));
        Assert.Equal("!!0", CanonicalName.MethodGenericParameter(0));
        Assert.Equal("!!2", CanonicalName.MethodGenericParameter(2));

        var method = Method(
            Type("Silvergun", 2, "Outer", "Inner"),
            "Mix",
            1,
            CanonicalName.TypeGenericParameter(0),
            CanonicalName.TypeGenericParameter(1),
            CanonicalName.MethodGenericParameter(0));

        Assert.Equal("Silvergun.Outer.Inner`2.Mix`1(!0,!1,!!0)", CanonicalName.NodeId(method));
    }

    // A negative index cannot render a malformed "!-1".
    [Fact]
    public void GenericParameter_NegativeIndex_ClampsToZero()
    {
        Assert.Equal("!0", CanonicalName.TypeGenericParameter(-3));
        Assert.Equal("!!0", CanonicalName.MethodGenericParameter(-3));
    }

    // Arrays (rank 1 and rank 3), pointers and by-ref, alone and composed.
    [Fact]
    public void Format_ArrayPointerByRefParameters_Rendered()
    {
        Assert.Equal("System.Int32[]", CanonicalName.ArrayOf("System.Int32"));
        Assert.Equal("System.Int32[]", CanonicalName.ArrayOf("System.Int32", 1));
        Assert.Equal("System.Int32[,,]", CanonicalName.ArrayOf("System.Int32", 3));
        Assert.Equal("System.Byte*", CanonicalName.PointerTo("System.Byte"));
        Assert.Equal("System.Int32&", CanonicalName.ByRefTo("System.Int32"));

        // Composed: a by-ref pointer-to-byte array of rank 3.
        Assert.Equal("System.Byte*[,,]&", CanonicalName.ByRefTo(CanonicalName.ArrayOf(CanonicalName.PointerTo("System.Byte"), 3)));

        var method = Method(
            Type("Silvergun", 0, "Shapes"),
            "Mixed",
            0,
            CanonicalName.ArrayOf("System.Int32"),
            CanonicalName.ArrayOf("System.Int32", 3),
            CanonicalName.PointerTo("System.Byte"),
            CanonicalName.ByRefTo("System.Int32"));

        Assert.Equal("Silvergun.Shapes.Mixed(System.Int32[],System.Int32[,,],System.Byte*,System.Int32&)", CanonicalName.NodeId(method));
    }

    // Ranks below 1 and absurd ranks are clamped rather than throwing or emitting a huge string.
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void ArrayOf_NonPositiveRank_ClampsToVector(int rank) =>
        Assert.Equal("System.Int32[]", CanonicalName.ArrayOf("System.Int32", rank));

    [Theory]
    [InlineData(33)]
    [InlineData(1000)]
    [InlineData(int.MaxValue)]
    public void ArrayOf_AbsurdRank_ClampsToThirtyTwo(int rank) =>
        Assert.Equal("System.Int32[" + new string(',', 31) + "]", CanonicalName.ArrayOf("System.Int32", rank));

    // Every entry point must survive hostile input: nulls, empty and whitespace parts, absent lists.
    [Fact]
    public void Format_NullOrMalformedInput_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
        {
            _ = CanonicalName.ClassificationKey(default(TypeIdentity));
            _ = CanonicalName.NodeId(default(TypeIdentity));
            _ = CanonicalName.ClassificationKey(default(MethodIdentity));
            _ = CanonicalName.NodeId(default(MethodIdentity));
            _ = CanonicalName.ClassificationKey(new TypeIdentity(null!, null!, -5));
            _ = CanonicalName.NodeId(new MethodIdentity(new TypeIdentity(null!, [null!, "  "], -5), null!, -5, [null!, string.Empty]));
            _ = CanonicalName.Signature(null);
            _ = CanonicalName.Signature([null!, " "]);
            _ = CanonicalName.GenericInstance(null, null);
            _ = CanonicalName.ArrayOf(null);
            _ = CanonicalName.PointerTo(null);
            _ = CanonicalName.ByRefTo(null);
            _ = CanonicalName.FunctionPointer(null, null);
            _ = default(MethodIdentity).ToString();
            _ = default(TypeIdentity).ToString();
            _ = default(MethodIdentity).GetHashCode();
            _ = default(TypeIdentity).GetHashCode();
            _ = default(MethodIdentity).Equals(MethodIdentity.Unknown);
            _ = default(TypeIdentity).Equals(TypeIdentity.Unknown);
        });

        Assert.Null(exception);
    }

    // Degradation must land on the documented placeholder, never on an empty string that could collide with
    // (or silently prefix-match) a real name.
    [Fact]
    public void Format_MalformedInput_RendersUnknown_AndNeverEmpty()
    {
        var malformed = new MethodIdentity(new TypeIdentity(null!, [null!, "   "], 0), "\t", 0, [null!, string.Empty, " "]);

        var key = CanonicalName.ClassificationKey(malformed);
        var node = CanonicalName.NodeId(malformed);

        Assert.Equal("<unknown>.<unknown>.<unknown>", key);
        Assert.Equal("<unknown>.<unknown>.<unknown>(<unknown>,<unknown>,<unknown>)", node);
        Assert.Equal(CanonicalName.UnknownPart, "<unknown>");
        Assert.DoesNotContain("..", key, StringComparison.Ordinal);
    }

    // A null nesting chain must not collapse the type away entirely.
    [Fact]
    public void ClassificationKey_NullOrEmptyNestingChain_RendersUnknown()
    {
        Assert.Equal("Silvergun.<unknown>", CanonicalName.ClassificationKey(new TypeIdentity("Silvergun", null!, 0)));
        Assert.Equal("Silvergun.<unknown>", CanonicalName.ClassificationKey(new TypeIdentity("Silvergun", [], 0)));
        Assert.Equal("<unknown>", CanonicalName.ClassificationKey(new TypeIdentity(string.Empty, [], 0)));
    }

    // Both placeholder identities render, and render non-empty.
    [Fact]
    public void Unknown_Identities_RenderPlaceholderNotEmpty()
    {
        Assert.Equal("<unknown>", CanonicalName.ClassificationKey(TypeIdentity.Unknown));
        Assert.Equal("<unknown>", CanonicalName.NodeId(TypeIdentity.Unknown));
        Assert.Equal("<unknown>.<unknown>", CanonicalName.ClassificationKey(MethodIdentity.Unknown));
        Assert.Equal("<unknown>.<unknown>()", CanonicalName.NodeId(MethodIdentity.Unknown));
    }

    // default(T) is reachable from any struct array/dictionary, so it must behave like Unknown, not crash.
    [Fact]
    public void Default_Identities_RenderUnknown()
    {
        Assert.Equal("<unknown>", CanonicalName.ClassificationKey(default(TypeIdentity)));
        Assert.Equal("<unknown>.<unknown>", CanonicalName.ClassificationKey(default(MethodIdentity)));
        Assert.Equal("<unknown>.<unknown>()", CanonicalName.NodeId(default(MethodIdentity)));
    }

    // The shared degradation for a containing-type walk that exceeded an adapter's 64-link bound. Both
    // adapters must funnel through this one factory, or a chain deep enough to hit the bound - which is
    // attacker-controlled - renders differently on each side and the two layers silently split.
    [Fact]
    public void Truncated_PrependsUnknownAndClearsNamespaceAndArity()
    {
        var truncated = CanonicalName.Truncated(new[] { "Level63", "Level64" });

        Assert.Equal(string.Empty, truncated.Namespace);
        Assert.Equal(new[] { CanonicalName.UnknownPart, "Level63", "Level64" }, truncated.NestingChain);
        // Arity is deliberately dropped rather than carried: CCI sums the links it walked while Model reports
        // the whole chain's cumulative count, so keeping it would re-break the very parity this exists for.
        Assert.Equal(0, truncated.GenericArity);
        // ...and the partial chain is kept, so a truncated type still discriminates rather than collapsing
        // onto the wholly unknown identity.
        Assert.NotEqual(TypeIdentity.Unknown, truncated);
    }

    // A truncated walk that read nothing at all still marks itself, never renders empty.
    [Fact]
    public void Truncated_NullOrEmptyChain_YieldsUnknownOnlyChain()
    {
        foreach (var truncated in new[] { CanonicalName.Truncated(null), CanonicalName.Truncated([]) })
        {
            Assert.Equal(new[] { CanonicalName.UnknownPart }, truncated.NestingChain);
            Assert.Equal(string.Empty, truncated.Namespace);
            Assert.Equal(0, truncated.GenericArity);
            Assert.Equal(TypeIdentity.Unknown, truncated);
        }
    }

    // The rendered strings, pinned: the marker is unmistakably outermost, there is no namespace segment and no
    // arity suffix on the declaring type, and the method's own arity and signature still render.
    [Fact]
    public void Truncated_ClassificationKeyAndNodeId_RenderAsExpected()
    {
        var truncated = CanonicalName.Truncated(new[] { "Outer", "Inner" });
        var method = new MethodIdentity(truncated, "Run", 1, ["System.Int32"]);

        Assert.Equal("<unknown>.Outer.Inner", CanonicalName.ClassificationKey(truncated));
        Assert.Equal("<unknown>.Outer.Inner", CanonicalName.NodeId(truncated));
        Assert.Equal("<unknown>.Outer.Inner.Run", CanonicalName.ClassificationKey(method));
        Assert.Equal("<unknown>.Outer.Inner.Run`1(System.Int32)", CanonicalName.NodeId(method));
        Assert.Equal("<unknown>", CanonicalName.ClassificationKey(CanonicalName.Truncated(null)));
        Assert.StartsWith(CanonicalName.UnknownPart, CanonicalName.ClassificationKey(truncated), StringComparison.Ordinal);
    }

    // The namespace join lives in the formatter so the two adapters cannot drift apart on it.
    [Fact]
    public void Namespace_JoinsPartsWithSeparator()
    {
        Assert.Equal("System", CanonicalName.Namespace(["System"]));
        Assert.Equal("System.Collections.Generic", CanonicalName.Namespace(["System", "Collections", "Generic"]));
        Assert.Equal(
            "System.Collections.Generic.Dictionary",
            CanonicalName.ClassificationKey(new TypeIdentity(CanonicalName.Namespace(["System", "Collections", "Generic"]), ["Dictionary"], 2)));
    }

    // The global namespace has no parts and must render as the empty string, not as the placeholder - it is a
    // legitimate absence, and ClassificationKey drops the segment entirely on it.
    [Fact]
    public void Namespace_NullOrEmptyParts_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, CanonicalName.Namespace(null));
        Assert.Equal(string.Empty, CanonicalName.Namespace([]));
    }

    // An unreadable part is a different thing from an absent namespace and must be visible as such.
    [Fact]
    public void Namespace_NullOrWhitespacePart_RendersUnknown()
    {
        Assert.Equal("<unknown>", CanonicalName.Namespace([null!]));
        Assert.Equal("<unknown>", CanonicalName.Namespace(["   "]));
        Assert.Equal("<unknown>", CanonicalName.Namespace([string.Empty]));
        Assert.Equal("System.<unknown>.Generic", CanonicalName.Namespace(["System", null!, "Generic"]));
        Assert.Equal("System.<unknown>.Generic", CanonicalName.Namespace(["System", "\t", "Generic"]));
        Assert.DoesNotContain("..", CanonicalName.Namespace(["System", null!, "Generic"]), StringComparison.Ordinal);
    }

    // Both new entry points share the never-throws contract with the rest of the formatter.
    [Fact]
    public void TruncatedAndNamespace_NullOrMalformedInput_DoNotThrow()
    {
        var exception = Record.Exception(() =>
        {
            _ = CanonicalName.Namespace(null);
            _ = CanonicalName.Namespace([]);
            _ = CanonicalName.Namespace([null!, string.Empty, " "]);
            _ = CanonicalName.Truncated(null);
            _ = CanonicalName.Truncated([]);
            _ = CanonicalName.Truncated([null!, "  "]);
            _ = CanonicalName.ClassificationKey(CanonicalName.Truncated([null!]));
            _ = CanonicalName.NodeId(CanonicalName.Truncated([null!]));
        });

        Assert.Null(exception);
    }

    // A whitespace-only namespace is legal in hostile metadata: it must not render as invisible padding
    // around the separator ("  .Foo"), which would silently prefix-match nothing and read as a real name.
    [Fact]
    public void ClassificationKey_WhitespaceNamespace_RendersUnknown()
    {
        Assert.Equal("<unknown>.Foo", CanonicalName.ClassificationKey(Type("  ", 0, "Foo")));
        Assert.Equal("<unknown>.Foo", CanonicalName.ClassificationKey(Type("\t", 0, "Foo")));
        Assert.Equal("<unknown>.Foo.Run", CanonicalName.ClassificationKey(Method(Type("  ", 0, "Foo"), "Run", 0)));
        Assert.Equal("<unknown>.Foo`1.Run()", CanonicalName.NodeId(Method(Type(" ", 1, "Foo"), "Run", 0)));
    }

    // The stability contract the capability catalog rests on: an ABSENT namespace (the global one) contributes
    // nothing at all - no leading dot, and emphatically not the placeholder that a whitespace one produces.
    [Fact]
    public void ClassificationKey_EmptyNamespace_OmitsSegmentEntirely()
    {
        var global = Type(string.Empty, 0, "Global", "Nested");

        Assert.Equal("Global.Nested", CanonicalName.ClassificationKey(global));
        Assert.Equal("Global.Nested", CanonicalName.ClassificationKey(Type(null!, 0, "Global", "Nested")));
        Assert.Equal("Global.Nested.Run(System.Int32)", CanonicalName.NodeId(Method(global, "Run", 0, "System.Int32")));
        Assert.DoesNotContain(CanonicalName.UnknownPart, CanonicalName.ClassificationKey(global), StringComparison.Ordinal);
        Assert.False(CanonicalName.ClassificationKey(global).StartsWith('.'));
    }

    // The global namespace must not produce a leading dot.
    [Fact]
    public void ClassificationKey_EmptyNamespace_HasNoLeadingDot()
    {
        Assert.Equal("Global", CanonicalName.ClassificationKey(Type(string.Empty, 0, "Global")));
        Assert.Equal("Global", CanonicalName.ClassificationKey(Type(null!, 0, "Global")));
        Assert.Equal("Global.Nested.Run", CanonicalName.ClassificationKey(Method(Type(string.Empty, 0, "Global", "Nested"), "Run", 0)));
        Assert.Equal("Global`1.Run()", CanonicalName.NodeId(Method(Type(string.Empty, 1, "Global"), "Run", 0)));
    }

    // An empty signature is "()", never "" and never "(,)".
    [Fact]
    public void Signature_NoParameters_IsEmptyParentheses()
    {
        Assert.Equal("()", CanonicalName.Signature([]));
        Assert.Equal("()", CanonicalName.Signature(null));
        Assert.Equal("(System.String)", CanonicalName.Signature(["System.String"]));
        Assert.Equal("(System.String,System.Int32)", CanonicalName.Signature(["System.String", "System.Int32"]));
    }

    // A nonsensical (zero or negative) arity produces no suffix at all rather than "`0" or "`-1".
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void NodeId_NonPositiveArity_HasNoAritySuffix(int arity)
    {
        var method = Method(Type("Silvergun", arity, "Shapes"), "Run", arity);

        Assert.Equal("Silvergun.Shapes.Run()", CanonicalName.NodeId(method));
        Assert.DoesNotContain("`", CanonicalName.NodeId(method), StringComparison.Ordinal);
    }

    // Spec correction of 2026-07-25: generic arguments are RETAINED in a node id's parameter types, otherwise
    // overloads differing only by an argument collide.
    [Fact]
    public void NodeId_ParameterGenericArgument_IsRetained()
    {
        var ints = Method(Type("Silvergun", 0, "Shapes"), "Accept", 0, CanonicalName.GenericInstance("System.Nullable`1", ["System.Int32"]));
        var bools = Method(Type("Silvergun", 0, "Shapes"), "Accept", 0, CanonicalName.GenericInstance("System.Nullable`1", ["System.Boolean"]));

        Assert.Equal("Silvergun.Shapes.Accept(System.Nullable`1<System.Int32>)", CanonicalName.NodeId(ints));
        Assert.Equal("Silvergun.Shapes.Accept(System.Nullable`1<System.Boolean>)", CanonicalName.NodeId(bools));
        Assert.NotEqual(CanonicalName.NodeId(ints), CanonicalName.NodeId(bools));
    }

    // Arguments nest recursively, with no spaces.
    [Fact]
    public void NodeId_NestedGenericArgument_RendersRecursively()
    {
        var inner = CanonicalName.GenericInstance("System.Collections.Generic.List`1", ["System.Int32"]);
        var outer = CanonicalName.GenericInstance("System.Collections.Generic.Dictionary`2", ["System.String", inner]);

        Assert.Equal("System.Collections.Generic.List`1<System.Int32>", inner);
        Assert.Equal("System.Collections.Generic.Dictionary`2<System.String,System.Collections.Generic.List`1<System.Int32>>", outer);
        Assert.DoesNotContain(" ", outer, StringComparison.Ordinal);
    }

    // The capability-map contract: retaining arguments in node ids must not have leaked any "<...>" into the
    // classification key, which the catalog prefix-matches against.
    [Fact]
    public void ClassificationKey_Unchanged_ByGenericArguments()
    {
        var declaring = Type("System.Collections.Generic", 2, "Dictionary");
        var bare = Method(declaring, "Add", 0, "!0", "!1");
        var instantiated = Method(
            declaring,
            "Add",
            0,
            CanonicalName.GenericInstance("System.Nullable`1", ["System.Int32"]),
            CanonicalName.GenericInstance("System.Collections.Generic.List`1", ["System.String"]));

        var key = CanonicalName.ClassificationKey(bare);

        Assert.Equal("System.Collections.Generic.Dictionary.Add", key);
        Assert.Equal(key, CanonicalName.ClassificationKey(instantiated));
        Assert.DoesNotContain("<", key, StringComparison.Ordinal);
        Assert.DoesNotContain(">", key, StringComparison.Ordinal);
        Assert.DoesNotContain("`", key, StringComparison.Ordinal);
    }

    // A generic parameter used as an argument stays positional rather than being resolved to a name.
    [Fact]
    public void NodeId_GenericParametersInsideArguments_StayPositional()
    {
        var pair = CanonicalName.GenericInstance(
            "System.Collections.Generic.KeyValuePair`2",
            [CanonicalName.TypeGenericParameter(0), CanonicalName.TypeGenericParameter(1)]);
        var sequence = CanonicalName.GenericInstance("System.Collections.Generic.IEnumerable`1", [pair]);

        var method = Method(Type("System.Collections.Generic", 2, "Dictionary"), "CopyTo", 0, sequence);

        Assert.Equal("System.Collections.Generic.IEnumerable`1<System.Collections.Generic.KeyValuePair`2<!0,!1>>", sequence);
        Assert.Equal("System.Collections.Generic.Dictionary`2.CopyTo(" + sequence + ")", CanonicalName.NodeId(method));
    }

    // No argument list must never grow an empty "<>", which would make every non-generic type unrecognizable.
    [Fact]
    public void GenericInstance_NoArguments_ReturnsDefinitionUnchanged()
    {
        Assert.Equal("System.String", CanonicalName.GenericInstance("System.String", []));
        Assert.Equal("System.String", CanonicalName.GenericInstance("System.String", null));
        Assert.Equal("System.Collections.Generic.List`1", CanonicalName.GenericInstance("System.Collections.Generic.List`1", []));
        Assert.DoesNotContain("<", CanonicalName.GenericInstance("System.String", []), StringComparison.Ordinal);
    }

    // Malformed pieces of an instantiation degrade individually.
    [Fact]
    public void GenericInstance_NullOrEmptyParts_DoNotThrow_AndRenderUnknown()
    {
        Assert.Equal("<unknown>", CanonicalName.GenericInstance(null, null));
        Assert.Equal("<unknown>", CanonicalName.GenericInstance(string.Empty, []));
        Assert.Equal("<unknown><System.Int32>", CanonicalName.GenericInstance(null, ["System.Int32"]));
        Assert.Equal("System.Nullable`1<<unknown>>", CanonicalName.GenericInstance("System.Nullable`1", [null!]));
        Assert.Equal("System.Nullable`1<<unknown>>", CanonicalName.GenericInstance("System.Nullable`1", ["   "]));
        Assert.Equal("System.Tuple`2<System.Int32,<unknown>>", CanonicalName.GenericInstance("System.Tuple`2", ["System.Int32", string.Empty]));
    }

    // A function pointer is decorated distinctly enough that it cannot be confused with a named type.
    [Fact]
    public void FunctionPointer_RendersReturnTypeAndSignature()
    {
        Assert.Equal("fnptr:System.Int32(System.String)", CanonicalName.FunctionPointer("System.Int32", ["System.String"]));
        Assert.Equal("fnptr:System.Void()", CanonicalName.FunctionPointer("System.Void", []));
        Assert.Equal("fnptr:<unknown>()", CanonicalName.FunctionPointer(null, null));
    }

    // ToString is the node id, so identities interpolate usefully into log and diff output.
    [Fact]
    public void ToString_EqualsNodeId()
    {
        var type = Type("Silvergun", 1, "Outer", "Inner");
        var method = Method(type, "Run", 1, "!0", "!!0");

        Assert.Equal(CanonicalName.NodeId(type), type.ToString());
        Assert.Equal(CanonicalName.NodeId(method), method.ToString());
        Assert.Equal("Silvergun.Outer.Inner`1.Run`1(!0,!!0)", method.ToString());
    }

    // Element-wise equality: the compiler-generated record equality would compare the lists by reference, so
    // two identities built from distinct-but-equal lists would wrongly differ.
    [Fact]
    public void TypeIdentity_Equality_IsElementWise()
    {
        var first = new TypeIdentity("Silvergun", new List<string> { "Outer", "Inner" }, 2);
        var second = new TypeIdentity("Silvergun", new[] { "Outer", "Inner" }, 2);

        Assert.Equal(first, second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
        Assert.NotEqual(first, new TypeIdentity("Silvergun", new[] { "Inner", "Outer" }, 2));
        Assert.NotEqual(first, new TypeIdentity("Silvergun", new[] { "Outer", "Inner" }, 1));
        Assert.NotEqual(first, new TypeIdentity("Other", new[] { "Outer", "Inner" }, 2));
    }

    [Fact]
    public void MethodIdentity_Equality_IsElementWise()
    {
        var first = Method(Type("Silvergun", 0, "Shapes"), "Run", 0, "System.Int32", "System.String");
        var second = new MethodIdentity(
            new TypeIdentity("Silvergun", new List<string> { "Shapes" }, 0),
            "Run",
            0,
            new List<string> { "System.Int32", "System.String" });

        Assert.Equal(first, second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
        Assert.NotEqual(first, Method(Type("Silvergun", 0, "Shapes"), "Run", 0, "System.String", "System.Int32"));
        Assert.NotEqual(first, Method(Type("Silvergun", 0, "Shapes"), "Run", 1, "System.Int32", "System.String"));
        Assert.NotEqual(first, Method(Type("Silvergun", 0, "Shapes"), "run", 0, "System.Int32", "System.String"));
    }

    // The practical consequence the graph builder depends on: identities deduplicate in a hash set.
    [Fact]
    public void MethodIdentity_DistinctButEqualLists_DedupeInHashSet()
    {
        var first = new MethodIdentity(
            new TypeIdentity("Silvergun", new List<string> { "Shapes" }, 0), "Run", 0, new List<string> { "System.Int32" });
        var second = new MethodIdentity(
            new TypeIdentity("Silvergun", new[] { "Shapes" }, 0), "Run", 0, new[] { "System.Int32" });

        var set = new HashSet<MethodIdentity> { first, second };

        Assert.Single(set);
    }

    // Null lists must be equal to empty ones, or a degraded identity would never match its own placeholder.
    [Fact]
    public void Identities_NullAndEmptyLists_AreEqual()
    {
        Assert.Equal(new TypeIdentity("Silvergun", null!, 0), new TypeIdentity("Silvergun", [], 0));
        Assert.Equal(
            new MethodIdentity(TypeIdentity.Unknown, "Run", 0, null!),
            new MethodIdentity(TypeIdentity.Unknown, "Run", 0, []));
    }

    private static TypeIdentity Type(string @namespace, int arity, params string[] chain) =>
        new(@namespace, chain, arity);

    private static MethodIdentity Method(TypeIdentity declaring, string name, int arity, params string[] parameters) =>
        new(declaring, name, arity, parameters);
    #endregion
}
