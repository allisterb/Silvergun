namespace Silvergun.CodeAnalysis.IL.Tests;

using System.Collections.Generic;
using System.Linq;

using Model.Types;

using Xunit;

/// <summary>
/// A2 S1 review 4, found while verifying W1-r4 (docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md, "S1 review 4 …
/// (S1f)"): the fork's <c>TypeHelper.GetAllTypes</c> combined containers with <c>Union</c>, and Model hashes a type
/// definition by its simple name alone (equality stays reference), so n same-named definitions cost n² — 22 s for
/// 50,000 in <c>MemberIndex.Build</c>.
/// It now uses <c>Concat</c>; the cost is pinned in <see cref="DispatchWorkBudgetTests"/>. What must NOT have changed is
/// the answer: with every definition in exactly one container (as CCIProvider's traverser builds them), <c>Union</c>
/// removed nothing, so <c>Concat</c> gives the same definitions in the same order —
/// <list type="number">
/// <item><description>a container's own types, in order;</description></item>
/// <item><description>then, for each of those that is itself a container (a class or a struct), its nested types by the
/// same rule, recursively;</description></item>
/// <item><description>then, for a namespace, each sub-namespace's, by the whole rule, in order.</description></item>
/// </list>
/// Pinned on a hand-built model with nested types (three levels, in classes and a struct), nested namespaces (two
/// levels), non-container kinds (interface, enum) and same-named definitions — both against the order spelled out by
/// hand and against the pre-S1f <c>Union</c> algorithm replayed here.
/// </summary>
public sealed class GetAllTypesParityTests
{
    #region Methods
    /// <summary>Every definition exactly once, by reference, in the documented order.</summary>
    [Fact]
    public void GetAllTypes_OnNestedTypesAndNamespaces_ReturnsEveryDefinitionOnce_InContainerThenNestedThenNamespaceOrder()
    {
        var (root, expected) = Tree();

        var all = root.GetAllTypes().ToArray();

        Assert.Equal(expected.Length, all.Length);
        Assert.Equal(all.Length, all.Distinct(ReferenceEqualityComparer.Instance).Count());
        Assert.All(expected.Zip(all), p => Assert.Same(p.First, p.Second));
    }

    /// <summary>
    /// The same sequence, by reference, as the pre-S1f algorithm (<c>Union</c> at both levels) gives on the same model:
    /// <c>Concat</c> changed the cost, not the answer. Same-named definitions are all kept by both, since Model's type
    /// definitions keep reference equality — only their hash is by name.
    /// </summary>
    [Fact]
    public void GetAllTypes_IsTheSameSequenceAsTheUnionAlgorithmItReplaced()
    {
        var (root, _) = Tree();

        var all = root.GetAllTypes().ToArray();
        var before = UnionAllTypes(root).ToArray();

        Assert.Equal(before.Length, all.Length);
        Assert.All(before.Zip(all), p => Assert.Same(p.First, p.Second));
        Assert.Equal(3, all.Count(t => t.Name == "Dup"));
    }

    /// <summary>The container overload alone, from a class: its nested types, then theirs — never the class itself.</summary>
    [Fact]
    public void GetAllTypes_OfAClass_IsItsNestedTypesThenTheirs()
    {
        var (_, expected) = Tree();
        var a1 = (ClassDefinition)expected.Single(t => t.Name == "A1");

        var all = ((ITypeDefinitionContainer)a1).GetAllTypes().Select(t => t.Name).ToArray();

        Assert.Equal(["A1a", "A1b", "A1a1", "A1b1"], all);
    }

    /// <summary>
    /// S1g (review 5 verified the fork's second <c>Concat</c>): <c>ClassDefinition.Members</c> and
    /// <c>StructDefinition.Members</c> yield, by reference, the nested types, then the fields, then the methods, each list
    /// in its order, and each definition exactly once. Before, they combined the lists with <c>Union</c>, which hashed
    /// every nested type by its simple name, so n same-named nested types cost n² in <c>MemberIndex.Build</c>. The
    /// sequence is unchanged, since no definition sits in two lists. The model holds same-named nested types, and a
    /// field and a method that share a nested type's name, so nothing may collapse.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Members_OfAClassOrStruct_IsNestedTypesThenFieldsThenMethods_EachOnce(bool isStruct)
    {
        var (definition, expected) = MembersModel(isStruct);

        var members = definition.Members.ToArray();

        Assert.Equal(expected.Length, members.Length);
        Assert.Equal(members.Length, members.Distinct(ReferenceEqualityComparer.Instance).Count());
        Assert.All(expected.Zip(members), p => Assert.Same(p.First, p.Second));
    }

    // A class or struct "Holder" with nested types Dup (class), Dup (interface), Other (struct); fields Dup, f1; methods
    // Dup, m1, Dup (an overload); and the order Members must give: types, fields, methods, each in list order.
    private static (ITypeDefinition Definition, ITypeMemberDefinition[] Expected) MembersModel(bool isStruct)
    {
        var assembly = new Model.Assembly("Members");
        var space = Space(assembly, null, "M");
        ITypeDefinition holder = isStruct
            ? new StructDefinition("Holder") { ContainingAssembly = assembly, ContainingNamespace = space }
            : new ClassDefinition("Holder") { ContainingAssembly = assembly, ContainingNamespace = space };
        var container = (ITypeDefinitionContainer)holder;
        var (fields, methods) = holder switch
        {
            StructDefinition s => (s.Fields, s.Methods),
            ClassDefinition c => (c.Fields, c.Methods),
            _ => throw new System.InvalidOperationException(),
        };

        ITypeDefinition[] nested = [new ClassDefinition("Dup"), new InterfaceDefinition("Dup"), new StructDefinition("Other")];
        foreach (var type in nested)
            container.Types.Add(type);
        FieldDefinition[] declaredFields = [new("Dup", PlatformTypes.Int32), new("f1", PlatformTypes.Int32)];
        foreach (var field in declaredFields)
            fields.Add(field);
        MethodDefinition[] declaredMethods =
        [
            new("Dup", PlatformTypes.Void),
            new("m1", PlatformTypes.Void),
            new("Dup", PlatformTypes.Int32),
        ];
        foreach (var method in declaredMethods)
            methods.Add(method);

        return (holder, [.. nested.Cast<ITypeMemberDefinition>(), .. declaredFields, .. declaredMethods]);
    }

    // The model, and the order GetAllTypes must give, by hand:
    //   ""      : R0
    //   A       : A1 (class: A1a (class: A1a1 interface), A1b (struct: A1b1 class)), Dup (interface), Dup (class), A3 (enum)
    //   A.B     : B1 (class: Dup class)
    //   C       : C1 (interface)
    //   C.D     : D1 (class)
    // root's own types; then namespace A's own types, its containers' nested types (A1's: A1a, A1b, then A1a's, A1b's;
    // the class Dup has none), then A.B's; then C's, then C.D's.
    private static (Model.Namespace Root, ITypeDefinition[] Expected) Tree()
    {
        var assembly = new Model.Assembly("Tree");
        var root = Space(assembly, null, string.Empty);
        assembly.RootNamespace = root;
        var a = Space(assembly, root, "A");
        var b = Space(assembly, a, "B");
        var c = Space(assembly, root, "C");
        var d = Space(assembly, c, "D");

        var r0 = Add(root, new ClassDefinition("R0"));
        var a1 = Add(a, new ClassDefinition("A1"));
        var dupInterface = Add(a, new InterfaceDefinition("Dup"));
        var dupClass = Add(a, new ClassDefinition("Dup"));
        var a3 = Add(a, new EnumDefinition("A3"));
        var a1a = Nest(a1, new ClassDefinition("A1a"));
        var a1b = Nest(a1, new StructDefinition("A1b"));
        var a1a1 = Nest(a1a, new InterfaceDefinition("A1a1"));
        var a1b1 = Nest(a1b, new ClassDefinition("A1b1"));
        var b1 = Add(b, new ClassDefinition("B1"));
        var dupNested = Nest(b1, new ClassDefinition("Dup"));
        var c1 = Add(c, new InterfaceDefinition("C1"));
        var d1 = Add(d, new ClassDefinition("D1"));

        return (root, [r0, a1, dupInterface, dupClass, a3, a1a, a1b, a1a1, a1b1, b1, dupNested, c1, d1]);
    }

    private static Model.Namespace Space(Model.Assembly assembly, Model.Namespace? parent, string name)
    {
        var space = new Model.Namespace(name) { ContainingAssembly = assembly, ContainingNamespace = parent! };
        parent?.Namespaces.Add(space);
        return space;
    }

    private static T Add<T>(Model.Namespace space, T type) where T : ITypeDefinition
    {
        space.Types.Add(type);
        return type;
    }

    private static T Nest<T>(ITypeDefinitionContainer outer, T type) where T : ITypeDefinition
    {
        outer.Types.Add(type);
        return type;
    }

    // TypeHelper.GetAllTypes as it was before S1f: Union at both levels, with the default comparer.
    private static IEnumerable<ITypeDefinition> UnionAllTypes(Model.Namespace space) =>
        UnionContainerTypes(space).Union(space.Namespaces.SelectMany(UnionAllTypes));

    private static IEnumerable<ITypeDefinition> UnionContainerTypes(ITypeDefinitionContainer container) =>
        container.Types.Union(container.Types.OfType<ITypeDefinitionContainer>().SelectMany(UnionContainerTypes));
    #endregion
}
