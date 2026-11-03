namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelBytecode = Model.Bytecode;
using ModelTypes = Model.Types;

/// <summary>
/// A2 S3 (docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md §4, §5, §6 and "S3 outcome") over an EMITTED assembly
/// (<see cref="InitializerShapesFixture"/>) whose every type and call site is written by hand:
/// <see cref="MemberIndex.TypeInitializerTargets(ModelTypes.IFieldReference)"/> and its
/// <see cref="MethodEdgeKind.TypeInitializer"/> edges (which instructions trigger, which types have a target, the
/// self-edge rule, the edge budget), the <see cref="MethodEdgeKind.LoadToken"/> edges of <c>ldtoken</c> (which tokens,
/// their accounting, their opacity, no fan-out), and the per-assembly module opacity of <c>AddModule</c>.
/// </summary>
public sealed class TypeInitializerAndTokenTests : IClassFixture<InitializerShapesFixture>
{
    #region Constructors
    public TypeInitializerAndTokenTests(InitializerShapesFixture shapes) => this.shapes = shapes;
    #endregion

    #region Methods
    // ---- which instructions trigger a type initializer -------------------------------------------------------------

    /// <summary>
    /// Each trigger of §4 — a load, store or address of a STATIC field, a call or <c>ldftn</c> of a STATIC method, a
    /// constructor by <c>newobj</c> or by a derived constructor's <c>call base::.ctor</c> — gets one TypeInitializer edge to
    /// the declaring type's <c>.cctor</c>, at the instruction's offset; the instance counterparts get none. Checked on the
    /// index's answer and on the graph.
    /// </summary>
    [Theory]
    [InlineData("Callers.LoadsStatic(", true)]
    [InlineData("Callers.StoresStatic(", true)]
    [InlineData("Callers.AddressesStatic(", true)]
    [InlineData("Callers.CallsStatic(", true)]
    [InlineData("Callers.LoadsStaticAddress(", true)]
    [InlineData("Callers.Creates(", true)]
    [InlineData("Derived..ctor(", true)]
    [InlineData("Callers.LoadsInstance(", false)]
    [InlineData("Callers.StoresInstance(", false)]
    [InlineData("Callers.AddressesInstance(", false)]
    [InlineData("Callers.CallsInstance(", false)]
    public void TypeInitializer_StaticMemberAccessesAndConstructorsTrigger_InstanceAccessesDoNot(string caller, bool triggers)
    {
        var (method, instruction) = shapes.Trigger(caller);
        IReadOnlyList<string> expected = triggers ? [Inits("Holder..cctor()")] : [];

        Assert.Equal(expected, shapes.TypeInitializerTargets(instruction));
        Assert.Equal(expected.Select(to => new MethodEdge(method, to, MethodEdgeKind.TypeInitializer, instruction.Offset)),
            shapes.Graph.Successors(method).Where(e => e.Kind == MethodEdgeKind.TypeInitializer));
    }

    /// <summary>
    /// A type with no <c>.cctor</c> gives nothing, for a static field or a static method of it; and so does an EXTERNAL
    /// type's static field or method (<c>string.Empty</c>, <c>string.IsNullOrEmpty</c>), which the index cannot see.
    /// </summary>
    [Theory]
    [InlineData("Callers.LoadsNoInit(")]
    [InlineData("Callers.CallsNoInit(")]
    [InlineData("Callers.LoadsExternal(")]
    [InlineData("Callers.CallsExternal(")]
    public void TypeInitializer_ATypeWithoutAStaticConstructorOrAnExternalType_GivesNothing(string caller)
    {
        var (method, instruction) = shapes.Trigger(caller);
        Assert.False(shapes.Index.IsOwnMethod(Inits("NoInit..cctor()")));

        Assert.Empty(shapes.TypeInitializerTargets(instruction));
        Assert.DoesNotContain(shapes.Graph.Successors(method), e => e.Kind == MethodEdgeKind.TypeInitializer);
    }

    /// <summary>A generic type's <c>.cctor</c> is keyed by its definition: <c>ldsfld Gen&lt;int&gt;::S</c> reaches <c>Gen`1..cctor()</c>.</summary>
    [Fact]
    public void TypeInitializer_AGenericTypesStaticConstructor_IsKeyedByItsDefinition()
    {
        var (method, instruction) = shapes.Trigger("Callers.LoadsGeneric(");
        Assert.Contains("System.Int32", ModelNames.TypeName(((ModelBytecode.LoadFieldInstruction)instruction).Field.ContainingType), StringComparison.Ordinal);

        Assert.Equal([Inits("Gen`1..cctor()")], shapes.TypeInitializerTargets(instruction));
        Assert.Equal([Inits("Gen`1..cctor()")], shapes.Graph.Successors(method).Where(e => e.Kind == MethodEdgeKind.TypeInitializer).Select(e => e.To));
    }

    /// <summary>
    /// A <c>.cctor</c> that stores its own type's static field gets no self-edge, although the index names its own
    /// <c>.cctor</c> for that field.
    /// </summary>
    [Fact]
    public void Graph_AStaticConstructorTouchingItsOwnStatics_HasNoSelfEdge()
    {
        var (method, instruction) = shapes.Trigger("Holder..cctor(");
        Assert.IsType<ModelBytecode.StoreFieldInstruction>(instruction);

        Assert.Equal([method], shapes.TypeInitializerTargets(instruction));
        Assert.DoesNotContain(shapes.Graph.Successors(method), e => e.Kind == MethodEdgeKind.TypeInitializer);
    }

    /// <summary>
    /// S3 review W3 (ECMA-335 II.10.5.3.1): an instance method of an own VALUE type runs its type's <c>.cctor</c>, so
    /// each walked one gets a TypeInitializer edge at offset 0 to its own type's <c>.cctor</c> — the callee's edge, which
    /// holds however it is reached. An instance method of a CLASS with a <c>.cctor</c> does not (its constructor or
    /// static access triggers it instead), nor does an instance method of a struct with no <c>.cctor</c>, nor a STATIC
    /// method of the struct (its callers' edges cover it).
    /// </summary>
    [Theory]
    [InlineData("Valued.Touch()", "Inits.Valued..cctor()")]
    [InlineData("Valued.StaticM()", null)]
    [InlineData("PlainValue.Touch()", null)]
    [InlineData("Holder.Instance()", null)]
    public void InstanceInitializer_AValueTypesInstanceMethod_RunsItsTypesStaticConstructor_NothingElseDoes(string method, string? cctor)
    {
        var indexed = Assert.Single(shapes.Index.Methods, m => m.NodeId == Inits(method));
        Assert.True(shapes.Index.IsOwnMethod(Inits("Holder..cctor()")));
        Assert.Equal(method.StartsWith("Holder.", StringComparison.Ordinal),
            Assert.Single(shapes.Index.Types(indexed.DeclaringTypeId)).Definition is ModelTypes.ClassDefinition);
        IReadOnlyList<string> expected = cctor is null ? [] : [cctor];

        Assert.Equal(expected, shapes.Index.InstanceInitializerTargets(indexed));
        Assert.Equal(expected.Select(to => new MethodEdge(Inits(method), to, MethodEdgeKind.TypeInitializer, 0)),
            shapes.Graph.Successors(Inits(method)).Where(e => e.Kind == MethodEdgeKind.TypeInitializer));
    }

    /// <summary>A null field or method reference is empty, never an exception.</summary>
    [Fact]
    public void TypeInitializerTargets_NullReferences_AreEmpty()
    {
        Assert.Empty(shapes.Index.TypeInitializerTargets((ModelTypes.IFieldReference?)null));
        Assert.Empty(shapes.Index.TypeInitializerTargets((ModelTypes.IMethodReference?)null));
    }

    /// <summary>
    /// TypeInitializer edges count against <see cref="GraphBudget.MaxEdges"/>, and reaching the budget on one marks the
    /// graph truncated by "edges". The last method walked (<c>Zz.Last.Loads()</c>, last by node id) only loads a static
    /// field: its TypeInitializer edge is the build's very last edge, so one edge fewer refuses exactly it.
    /// </summary>
    [Fact]
    public void Graph_TypeInitializerEdges_CountAgainstMaxEdges_AndTruncateTheGraphByEdges()
    {
        const string last = "Zz.Last.Loads()";
        Assert.Equal(last, shapes.Index.Methods.Last(m => m.Definition.HasBody).NodeId);
        var lastEdge = Assert.Single(shapes.Graph.Successors(last));
        Assert.Equal(new MethodEdge(last, Inits("Holder..cctor()"), MethodEdgeKind.TypeInitializer, 0), lastEdge);
        var all = shapes.Graph.Edges.Count;

        var truncated = MethodGraph.Build(shapes.Index, new GraphBudget(int.MaxValue, all - 1));
        var exact = MethodGraph.Build(shapes.Index, new GraphBudget(int.MaxValue, all));

        Assert.True(truncated.Coverage.Truncated);
        Assert.Equal($"edges budget of {all - 1} reached", truncated.Coverage.TruncatedBy);
        Assert.Equal(shapes.Graph.Edges.Where(e => e != lastEdge), truncated.Edges);
        Assert.False(exact.Coverage.Truncated);
        Assert.Equal(shapes.Graph.Edges, exact.Edges);
    }

    // ---- ldtoken --------------------------------------------------------------------------------------------------

    /// <summary>
    /// An <c>ldtoken</c> of an own method gets one LoadToken edge to its node, and of an external method one to the
    /// external leaf — and nothing else: no TypeInitializer edge (a token does not run anything by itself).
    /// </summary>
    [Theory]
    [InlineData("Callers.TokenOwn(", "Inits.Holder.Static()", MethodNodeKind.OwnWithBody)]
    [InlineData("Callers.TokenExternal(", "System.String.IsNullOrEmpty(System.String)", MethodNodeKind.External)]
    public void LoadToken_OfAMethod_IsOneEdgeToTheResolvedNode(string caller, string target, MethodNodeKind kind)
    {
        var (method, instruction) = shapes.Trigger(caller);
        Assert.IsAssignableFrom<ModelTypes.IMethodReference>(((ModelBytecode.LoadTokenInstruction)instruction).Token);

        Assert.Equal([new MethodEdge(method, target, MethodEdgeKind.LoadToken, instruction.Offset)], shapes.Graph.Successors(method));
        Assert.Equal(kind, shapes.Graph.Node(target)?.Kind);
    }

    /// <summary>An <c>ldtoken</c> of a field or of a type adds no edge at all.</summary>
    [Theory]
    [InlineData("Callers.TokenField(")]
    [InlineData("Callers.TokenType(")]
    public void LoadToken_OfAFieldOrAType_AddsNoEdge(string caller)
    {
        var (method, instruction) = shapes.Trigger(caller);
        Assert.IsNotAssignableFrom<ModelTypes.IMethodReference>(((ModelBytecode.LoadTokenInstruction)instruction).Token);

        Assert.Empty(shapes.Graph.Successors(method));
    }

    /// <summary>
    /// <c>ldtoken</c> of a VIRTUAL method is not fanned out: one LoadToken edge, no Dispatch — while a <c>callvirt</c> of
    /// the same method (the positive control) dispatches to the override.
    /// </summary>
    [Fact]
    public void LoadToken_OfAVirtualMethod_IsNotFannedOut()
    {
        var (method, instruction) = shapes.Trigger("Callers.TokenVirtual(");
        var (calls, _) = shapes.Trigger("Callers.CallsVirtual(");

        Assert.Equal([new MethodEdge(method, Inits("VBase.Run()"), MethodEdgeKind.LoadToken, instruction.Offset)], shapes.Graph.Successors(method));
        Assert.Contains(shapes.Graph.Successors(calls), e => e.Kind == MethodEdgeKind.Dispatch && e.To == Inits("VDerived.Run()"));
    }

    /// <summary>
    /// <see cref="GraphCoverage.TokenSites"/> counts the <c>ldtoken</c>s of METHODS (three here; the field and type
    /// tokens are not counted), while <see cref="GraphCoverage.CallSites"/> and <see cref="GraphCoverage.Resolutions"/>
    /// count exactly the call-site instructions, as without any token.
    /// </summary>
    [Fact]
    public void Coverage_TokenSitesAreCountedApart_FromCallSitesAndResolutions()
    {
        var coverage = shapes.Graph.Coverage;
        var counts = coverage.Resolutions;
        var methodTokens = shapes.Index.Methods.Where(m => m.Definition.HasBody)
            .Sum(m => m.Definition.Body.Instructions.OfType<ModelBytecode.LoadTokenInstruction>().Count(i => i.Token is ModelTypes.IMethodReference));

        Assert.Equal(3, methodTokens);
        Assert.Equal(methodTokens, coverage.TokenSites);
        Assert.Equal(methodTokens, shapes.Graph.Edges.Count(e => e.Kind == MethodEdgeKind.LoadToken));
        Assert.Equal(shapes.Sites.Count, coverage.CallSites);
        Assert.Equal(shapes.Sites.Count, counts.Exact + counts.Substituted + counts.External + counts.Ambiguous + counts.Unresolved);
    }

    /// <summary>
    /// An AMBIGUOUS token gets exactly the opacity a call site to the same method gets: the shapes loaded twice make
    /// <c>Holder.Static()</c> ambiguous, and <c>ldtoken Holder.Static</c> and <c>call Holder.Static</c> carry the same
    /// <see cref="OpacityKind.Ambiguous"/> detail, each at its own site, with an edge to the candidate.
    /// </summary>
    [Fact]
    public void LoadToken_AnAmbiguousToken_GetsTheSameOpacityAsACallSite()
    {
        using var doubled = ModelAssemblies.Load(shapes.Path, shapes.Path);
        var graph = MethodGraph.Build(doubled.Index());
        GraphOpacity Opacity(string caller) =>
            graph.Opacities.First(o => o.Kind == OpacityKind.Ambiguous && o.Site.StartsWith(Inits(caller), StringComparison.Ordinal));

        var token = Opacity("Callers.TokenOwn(");
        var call = Opacity("Callers.CallsStatic(");

        Assert.Equal(call.Detail, token.Detail);
        Assert.StartsWith(Inits("Holder.Static()"), token.Detail, StringComparison.Ordinal);
        Assert.Contains(graph.Edges, e => e.Kind == MethodEdgeKind.LoadToken && e.From == token.Site && e.To == Inits("Holder.Static()") && e.Offset == token.Offset);
        Assert.Equal(6, graph.Coverage.TokenSites);
    }

    /// <summary>
    /// An UNRESOLVED token (a hand-built reference into an indexed assembly that defines no such method) gets exactly the
    /// opacity, and the same Qualified leaf, that a call site to the same reference gets.
    /// </summary>
    [Fact]
    public void LoadToken_AnUnresolvedToken_GetsTheSameOpacityAndLeafAsACallSite()
    {
        const string assembly = "SyntheticTokens";
        var gone = SyntheticModel.Method(SyntheticModel.TypeRef("Synthetic", "Gone", assembly: assembly), "Missing");
        var index = MemberIndex.Build([(Bodies(assembly,
            ("Calls", new ModelBytecode.MethodCallInstruction(Offset, ModelBytecode.MethodCallOperation.Static, gone)),
            ("Tokens", new ModelBytecode.LoadTokenInstruction(Offset, gone))), TypeForwarders.None)]);

        var graph = MethodGraph.Build(index);

        var call = Assert.Single(graph.Opacities, o => o.Site == "Synthetic.Callers.Calls()");
        var token = Assert.Single(graph.Opacities, o => o.Site == "Synthetic.Callers.Tokens()");
        Assert.Equal(OpacityKind.Unresolved, token.Kind);
        Assert.Equal((call.Kind, call.Offset, call.Detail), (token.Kind, token.Offset, token.Detail));
        var to = Assert.Single(graph.Successors("Synthetic.Callers.Tokens()")).To;
        Assert.Equal(Assert.Single(graph.Successors("Synthetic.Callers.Calls()")).To, to);
        Assert.Equal(MethodEdgeKind.LoadToken, Assert.Single(graph.Successors("Synthetic.Callers.Tokens()")).Kind);
        Assert.Equal(1, graph.Coverage.TokenSites);
        Assert.Equal(1, graph.Coverage.CallSites);
        Assert.Equal(1, graph.Coverage.Resolutions.Unresolved);
    }

    // ---- module opacity ---------------------------------------------------------------------------------------------

    /// <summary>
    /// One opacity of each kind per assembly, sited at <c>[assembly]&lt;Module&gt;</c>, offset 0, with the counts in the
    /// detail, and the coverage counts summed over assemblies: a module initializer
    /// (<see cref="OpacityKind.ModuleInitializerInvisible"/>, the method count) and renamed MethodImpl rows
    /// (<see cref="OpacityKind.RenamedImplementation"/>); an assembly with renamed rows only adds just that one.
    /// </summary>
    [Fact]
    public void AddModule_RecordsOneOpacityPerKind_WithTheSiteAndDetail_AndSumsTheCoverage()
    {
        using var loaded = ModelAssemblies.Load(shapes.Path, MechanismFixtureAssemblies.Dependency);
        var modules = new Dictionary<string, ModuleMetadata>(StringComparer.Ordinal)
        {
            [InitializerShapesFixture.Name] = ModuleMetadata.Of(true, 3, 2),
            [MechanismFixtureAssemblies.DependencyName] = ModuleMetadata.Of(false, 0, 3),
        };
        var index = MemberIndex.Build(loaded.Disassemblers.Select(d => (d.Assembly, d.Forwarders, modules[d.Assembly.Name])));

        var graph = MethodGraph.Build(index);

        var shapesSite = MemberIndex.Qualified(InitializerShapesFixture.Name, "<Module>");
        var dependencySite = MemberIndex.Qualified(MechanismFixtureAssemblies.DependencyName, "<Module>");
        Assert.Equal(
            [new GraphOpacity(shapesSite, 0, OpacityKind.ModuleInitializerInvisible,
                 "<Module> has a module initializer, which runs when the assembly loads, and 3 methods; the model loads none of them"),
             new GraphOpacity(shapesSite, 0, OpacityKind.RenamedImplementation,
                 "MethodImpl rows that bind an implementation whose name is not the declared method's, which CHA does not follow: 2"),
             new GraphOpacity(dependencySite, 0, OpacityKind.RenamedImplementation,
                 "MethodImpl rows that bind an implementation whose name is not the declared method's, which CHA does not follow: 3")],
            graph.Opacities.Where(o => o.Site.EndsWith("]<Module>", StringComparison.Ordinal)).OrderBy(o => o.Site, StringComparer.Ordinal).ThenBy(o => o.Kind));
        Assert.Equal(1, graph.Coverage.ModuleInitializers);
        Assert.Equal(5, graph.Coverage.RenamedImplementations);
        Assert.Equal(0, graph.Coverage.ModulesUnreadable);
        var module = index.Module(InitializerShapesFixture.Name);   // merged per name, so a copy, not the same instance
        Assert.Equal((true, true, 3, 2), (module.IsReadable, module.HasModuleInitializer, module.ModuleMethods, module.RenamedImplementations));
    }

    /// <summary>
    /// Unreadable module metadata is its own record, never "no module initializer": one
    /// <see cref="OpacityKind.ModuleInitializerInvisible"/> saying it is unknown, counted in
    /// <see cref="GraphCoverage.ModulesUnreadable"/> and not in <see cref="GraphCoverage.ModuleInitializers"/>. A name the
    /// index does not hold is unreadable too.
    /// </summary>
    [Fact]
    public void AddModule_UnreadableMetadata_IsTheUnknownOpacity_CountedAsUnreadable()
    {
        using var loaded = ModelAssemblies.Load(shapes.Path);
        var index = MemberIndex.Build(loaded.Disassemblers.Select(d => (d.Assembly, d.Forwarders, ModuleMetadata.Unreadable)));

        var graph = MethodGraph.Build(index);

        Assert.Equal(
            [new GraphOpacity(MemberIndex.Qualified(InitializerShapesFixture.Name, "<Module>"), 0, OpacityKind.ModuleInitializerInvisible,
                "the module metadata could not be read: whether it has a module initializer or renamed implementations is unknown")],
            graph.Opacities);
        Assert.Equal(1, graph.Coverage.ModulesUnreadable);
        Assert.Equal(0, graph.Coverage.ModuleInitializers);
        Assert.Equal(0, graph.Coverage.RenamedImplementations);
        Assert.False(index.Module("Not.Indexed").IsReadable);
    }

    /// <summary>
    /// Module opacities are facts, not graph work: they are recorded even when the build is truncated — here at once, by
    /// a node budget of zero.
    /// </summary>
    [Fact]
    public void AddModule_RecordsTheModuleOpacities_EvenWhenTheBuildIsTruncated()
    {
        using var loaded = ModelAssemblies.Load(shapes.Path);
        var index = MemberIndex.Build(loaded.Disassemblers.Select(d => (d.Assembly, d.Forwarders, ModuleMetadata.Of(true, 1, 4))));

        var graph = MethodGraph.Build(index, new GraphBudget(0, 0));

        Assert.True(graph.Coverage.Truncated);
        Assert.Empty(graph.Edges);
        Assert.Equal([OpacityKind.ModuleInitializerInvisible, OpacityKind.RenamedImplementation], graph.Opacities.Select(o => o.Kind));
        // S3 review N1: one method is singular (the AddModule test above pins the plural).
        Assert.Equal("<Module> has a module initializer, which runs when the assembly loads, and 1 method; the model loads none of them", graph.Opacities[0].Detail);
        Assert.Equal(1, graph.Coverage.ModuleInitializers);
        Assert.Equal(4, graph.Coverage.RenamedImplementations);
    }

    /// <summary>
    /// The 2-tuple <c>Build</c> passes <see cref="ModuleMetadata.None"/>: no module opacity, even for the Release
    /// mechanism fixture, whose real <c>&lt;Module&gt;</c> has an initializer (which the disassembler's own metadata, the
    /// positive control, does report).
    /// </summary>
    [Fact]
    public void Build_WithoutModuleMetadata_IsNone_AndAddsNoModuleOpacity()
    {
        using var loaded = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture);
        var disassembler = Assert.Single(loaded.Disassemblers);
        Assert.True(disassembler.Module.HasModuleInitializer);

        var graph = MethodGraph.Build(MemberIndex.Build([(disassembler.Assembly, disassembler.Forwarders)]));

        Assert.DoesNotContain(graph.Opacities, o => o.Kind is OpacityKind.ModuleInitializerInvisible or OpacityKind.RenamedImplementation);
        Assert.Equal((0, 0, 0), (graph.Coverage.ModuleInitializers, graph.Coverage.RenamedImplementations, graph.Coverage.ModulesUnreadable));
        Assert.Contains(MethodGraph.Build(loaded.Index()).Opacities, o => o.Kind == OpacityKind.ModuleInitializerInvisible);
    }

    // ---- determinism ------------------------------------------------------------------------------------------------

    /// <summary>Two builds over fresh loads give identical edges, opacities and coverage, TypeInitializer and LoadToken included.</summary>
    [Fact]
    public void Build_TwiceOverFreshLoads_IsIdentical()
    {
        using var again = ModelAssemblies.Load(shapes.Path);
        var second = MethodGraph.Build(again.Index());

        Assert.Contains(shapes.Graph.Edges, e => e.Kind == MethodEdgeKind.TypeInitializer);
        Assert.Contains(shapes.Graph.Edges, e => e.Kind == MethodEdgeKind.LoadToken);
        Assert.Equal(shapes.Graph.Edges, second.Edges);
        Assert.Equal(shapes.Graph.Opacities, second.Opacities);
        Assert.Equal(shapes.Graph.Coverage, second.Coverage);
    }

    // A synthetic assembly holding one class Synthetic.Callers with one static, parameterless method per entry, whose
    // body is that single instruction (as SyntheticModel.CallerAssembly, for any instruction).
    private static Model.Assembly Bodies(string name, params (string Method, ModelBytecode.Instruction Instruction)[] methods)
    {
        var assembly = new Model.Assembly(name);
        var root = new Model.Namespace(string.Empty) { ContainingAssembly = assembly };
        var space = new Model.Namespace("Synthetic") { ContainingAssembly = assembly, ContainingNamespace = root };
        root.Namespaces.Add(space);
        assembly.RootNamespace = root;
        var type = new ModelTypes.ClassDefinition("Callers") { ContainingAssembly = assembly, ContainingNamespace = space };
        space.Types.Add(type);
        foreach (var (method, instruction) in methods)
        {
            var body = new ModelTypes.MethodBody(ModelTypes.MethodBodyKind.Bytecode);
            body.Instructions.Add(instruction);
            type.Methods.Add(new ModelTypes.MethodDefinition(method, ModelTypes.PlatformTypes.Void) { ContainingType = type, IsStatic = true, Body = body });
        }
        return assembly;
    }

    private static string Inits(string nodeIdWithoutNamespace) => $"Inits.{nodeIdWithoutNamespace}";
    #endregion

    #region Fields
    private const uint Offset = 0x10;

    private readonly InitializerShapesFixture shapes;
    #endregion
}

/// <summary>
/// One emitted assembly, <c>InitShapes</c> (<see cref="EmittedAssembly"/>; never loaded or run), holding the shapes of
/// <see cref="TypeInitializerAndTokenTests"/> in namespace <c>Inits</c> (and one caller in <c>Zz.Last</c>, which sorts
/// after it):
/// <list type="bullet">
/// <item><description><c>Holder</c>: static field <c>S</c>, instance field <c>I</c>, static <c>Static()</c>, instance
/// <c>Instance()</c>, a constructor, and a <c>.cctor</c> that stores <c>S</c>; <c>Derived : Holder</c>, whose constructor
/// calls <c>Holder::.ctor</c>;</description></item>
/// <item><description><c>NoInit</c>: a static field and method, no <c>.cctor</c>; <c>Gen&lt;T&gt;</c>: a static field and a
/// <c>.cctor</c>;</description></item>
/// <item><description>struct <c>Valued</c>: a <c>.cctor</c>, instance <c>Touch()</c> and static <c>StaticM()</c>; struct
/// <c>PlainValue</c>: instance <c>Touch()</c>, no <c>.cctor</c> (S3 review W3);</description></item>
/// <item><description><c>VBase</c> (virtual <c>Run()</c>) and <c>VDerived : VBase</c> overriding it;</description></item>
/// <item><description><c>Callers</c>: one static method per site, each with exactly one instruction that names a member
/// (the trigger, or the token).</description></item>
/// </list>
/// </summary>
public sealed class InitializerShapesFixture : IDisposable
{
    #region Constructors
    public InitializerShapesFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            Path = emitted.Save(Name, Define);
            Assemblies = ModelAssemblies.Load(Path);
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
            Sites = ModelCallSite.All(Index);
        }
        catch (Exception)
        {
            Assemblies?.Dispose();
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string Path { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public MethodGraph Graph { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }
    #endregion

    #region Methods
    /// <summary>
    /// The method whose node id starts with <c>Inits.{prefix}</c>, and its single instruction that names a member: a call,
    /// <c>newobj</c>, <c>ldftn</c>, field access or <c>ldtoken</c>.
    /// </summary>
    public (string Method, ModelBytecode.Instruction Instruction) Trigger(string prefix)
    {
        var method = Assert.Single(Index.Methods, m => m.NodeId.StartsWith($"Inits.{prefix}", StringComparison.Ordinal));
        var instruction = Assert.Single(method.Definition.Body.Instructions.OfType<ModelBytecode.Instruction>(), i => i is
            ModelBytecode.MethodCallInstruction or ModelBytecode.CreateObjectInstruction or ModelBytecode.LoadMethodAddressInstruction
            or ModelBytecode.LoadFieldInstruction or ModelBytecode.StoreFieldInstruction or ModelBytecode.LoadTokenInstruction);
        return (method.NodeId, instruction);
    }

    /// <summary>What <see cref="MemberIndex.TypeInitializerTargets(ModelTypes.IFieldReference)"/> answers for the member <paramref name="instruction"/> names.</summary>
    public IReadOnlyList<string> TypeInitializerTargets(ModelBytecode.Instruction instruction) => instruction switch
    {
        ModelBytecode.MethodCallInstruction call => Index.TypeInitializerTargets(call.Method),
        ModelBytecode.CreateObjectInstruction create => Index.TypeInitializerTargets(create.Constructor),
        ModelBytecode.LoadMethodAddressInstruction load => Index.TypeInitializerTargets(load.Method),
        ModelBytecode.LoadFieldInstruction field => Index.TypeInitializerTargets(field.Field),
        ModelBytecode.StoreFieldInstruction field => Index.TypeInitializerTargets(field.Field),
        _ => throw new ArgumentException($"{instruction} names no member that can trigger a type initializer"),
    };

    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void Define(ModuleBuilder module)
    {
        var objectCtor = typeof(object).GetConstructor(Type.EmptyTypes)!;

        // Holder: static and instance members, and a .cctor touching its own static field.
        var holder = module.DefineType("Inits.Holder", TypeAttributes.Public | TypeAttributes.Class);
        var s = holder.DefineField("S", typeof(int), FieldAttributes.Public | FieldAttributes.Static);
        var i = holder.DefineField("I", typeof(int), FieldAttributes.Public);
        var holderStatic = Body(holder.DefineMethod("Static", StaticMethod, typeof(void), Type.EmptyTypes));
        var holderInstance = Body(holder.DefineMethod("Instance", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(void), Type.EmptyTypes));
        var holderCtor = Constructor(holder, objectCtor);
        var cctor = holder.DefineTypeInitializer().GetILGenerator();
        cctor.Emit(OpCodes.Ldc_I4_1);
        cctor.Emit(OpCodes.Stsfld, s);
        cctor.Emit(OpCodes.Ret);
        var derived = module.DefineType("Inits.Derived", TypeAttributes.Public | TypeAttributes.Class, holder);
        Constructor(derived, holderCtor);

        // No .cctor; and a generic type with one.
        var noInit = module.DefineType("Inits.NoInit", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var noInitField = noInit.DefineField("S", typeof(int), FieldAttributes.Public | FieldAttributes.Static);
        var noInitStatic = Body(noInit.DefineMethod("Static", StaticMethod, typeof(void), Type.EmptyTypes));
        var gen = module.DefineType("Inits.Gen`1", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        gen.DefineGenericParameters("T");
        var genField = gen.DefineField("S", typeof(int), FieldAttributes.Public | FieldAttributes.Static);
        gen.DefineTypeInitializer().GetILGenerator().Emit(OpCodes.Ret);

        // S3 review W3: a struct with a .cctor (an instance and a static method), and one without (an instance method).
        var valued = module.DefineType("Inits.Valued", TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.SequentialLayout, typeof(ValueType));
        valued.DefineTypeInitializer().GetILGenerator().Emit(OpCodes.Ret);
        Body(valued.DefineMethod("Touch", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(void), Type.EmptyTypes));
        Body(valued.DefineMethod("StaticM", StaticMethod, typeof(void), Type.EmptyTypes));
        var plainValue = module.DefineType("Inits.PlainValue", TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.SequentialLayout, typeof(ValueType));
        Body(plainValue.DefineMethod("Touch", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(void), Type.EmptyTypes));

        // A virtual method and its override.
        var vbase = module.DefineType("Inits.VBase", TypeAttributes.Public | TypeAttributes.Class);
        var run = Body(vbase.DefineMethod("Run", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot, typeof(void), Type.EmptyTypes));
        var vderived = module.DefineType("Inits.VDerived", TypeAttributes.Public | TypeAttributes.Class, vbase);
        Body(vderived.DefineMethod("Run", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual, typeof(void), Type.EmptyTypes));

        var isNullOrEmpty = typeof(string).GetMethod(nameof(string.IsNullOrEmpty), [typeof(string)])!;
        var empty = typeof(string).GetField(nameof(string.Empty))!;
        var callers = module.DefineType("Inits.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        Caller(callers, "LoadsStatic", [], il => { il.Emit(OpCodes.Ldsfld, s); il.Emit(OpCodes.Pop); });
        Caller(callers, "StoresStatic", [], il => { il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Stsfld, s); });
        Caller(callers, "AddressesStatic", [], il => { il.Emit(OpCodes.Ldsflda, s); il.Emit(OpCodes.Pop); });
        Caller(callers, "LoadsInstance", [holder], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldfld, i); il.Emit(OpCodes.Pop); });
        Caller(callers, "StoresInstance", [holder], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Stfld, i); });
        Caller(callers, "AddressesInstance", [holder], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldflda, i); il.Emit(OpCodes.Pop); });
        Caller(callers, "CallsStatic", [], il => il.Emit(OpCodes.Call, holderStatic));
        Caller(callers, "CallsInstance", [holder], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, holderInstance); });
        Caller(callers, "LoadsStaticAddress", [], il => { il.Emit(OpCodes.Ldftn, holderStatic); il.Emit(OpCodes.Pop); });
        Caller(callers, "Creates", [], il => { il.Emit(OpCodes.Newobj, holderCtor); il.Emit(OpCodes.Pop); });
        Caller(callers, "LoadsNoInit", [], il => { il.Emit(OpCodes.Ldsfld, noInitField); il.Emit(OpCodes.Pop); });
        Caller(callers, "CallsNoInit", [], il => il.Emit(OpCodes.Call, noInitStatic));
        Caller(callers, "LoadsGeneric", [], il => { il.Emit(OpCodes.Ldsfld, TypeBuilder.GetField(gen.MakeGenericType(typeof(int)), genField)); il.Emit(OpCodes.Pop); });
        Caller(callers, "LoadsExternal", [], il => { il.Emit(OpCodes.Ldsfld, empty); il.Emit(OpCodes.Pop); });
        Caller(callers, "CallsExternal", [], il => { il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Call, isNullOrEmpty); il.Emit(OpCodes.Pop); });
        Caller(callers, "CallsVirtual", [vbase], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, run); });
        Caller(callers, "TokenOwn", [], il => { il.Emit(OpCodes.Ldtoken, holderStatic); il.Emit(OpCodes.Pop); });
        Caller(callers, "TokenExternal", [], il => { il.Emit(OpCodes.Ldtoken, isNullOrEmpty); il.Emit(OpCodes.Pop); });
        Caller(callers, "TokenVirtual", [], il => { il.Emit(OpCodes.Ldtoken, run); il.Emit(OpCodes.Pop); });
        Caller(callers, "TokenField", [], il => { il.Emit(OpCodes.Ldtoken, s); il.Emit(OpCodes.Pop); });
        Caller(callers, "TokenType", [], il => { il.Emit(OpCodes.Ldtoken, holder); il.Emit(OpCodes.Pop); });

        // The last method walked (node ids sort "Inits." < "Zz."), for the edge-budget test.
        var last = module.DefineType("Zz.Last", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        Caller(last, "Loads", [], il => { il.Emit(OpCodes.Ldsfld, s); il.Emit(OpCodes.Pop); });

        foreach (var type in new[] { holder, derived, noInit, gen, valued, plainValue, vbase, vderived, callers, last })
            type.CreateType();
    }

    // A public parameterless constructor: ldarg.0; call baseCtor; ret.
    private static ConstructorBuilder Constructor(TypeBuilder type, ConstructorInfo baseCtor)
    {
        var ctor = type.DefineConstructor(MethodAttributes.Public | MethodAttributes.HideBySig, CallingConventions.Standard, Type.EmptyTypes);
        var il = ctor.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Call, baseCtor);
        il.Emit(OpCodes.Ret);
        return ctor;
    }

    // A public static void method: `emit` then ret.
    private static void Caller(TypeBuilder callers, string name, Type[] parameters, Action<ILGenerator> emit)
    {
        var il = callers.DefineMethod(name, StaticMethod, typeof(void), parameters).GetILGenerator();
        emit(il);
        il.Emit(OpCodes.Ret);
    }

    // An empty void body.
    private static MethodBuilder Body(MethodBuilder method)
    {
        method.GetILGenerator().Emit(OpCodes.Ret);
        return method;
    }
    #endregion

    #region Fields
    /// <summary>The emitted assembly's name.</summary>
    public const string Name = "InitShapes";

    private const MethodAttributes StaticMethod = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Static;

    private readonly EmittedAssembly emitted;
    #endregion
}
