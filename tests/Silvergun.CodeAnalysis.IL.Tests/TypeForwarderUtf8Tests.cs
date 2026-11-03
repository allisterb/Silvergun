namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Review 5, <b>C-F</b>: a forwarded type name that is not valid UTF-8. SRM used to decode the invalid bytes to U+FFFD
/// while CCI decodes them its own way, so the forwarder row's key and the reference's name differed: <c>FwdA</c>
/// forwarding <c>N.&lt;name&gt;</c> to the indexed <c>FwdT</c> AND defining a decoy <c>N.&lt;name&gt;</c> resolved
/// Exact to the decoy, while the CLR ran FwdT's body. <see cref="TypeForwarders.Read"/> now decodes strictly, and such a
/// table is Unreadable — so the call is Unresolved, never Own, and the index is incomplete.
/// <para>
/// Every byte shape (overlong <c>C0 AE</c>, lone continuation <c>80</c>, CESU surrogate <c>ED A0 80</c>, <c>FF</c>) is
/// patched into one whole <c>#Strings</c> entry of all three assemblies, so the CLR binds the patched reference — the
/// oracle. The control keeps the ASCII placeholders, and a name with a VALID U+FFFD (<c>EF BF BD</c>) stays readable.
/// </para>
/// </summary>
public sealed class TypeForwarderUtf8Tests : IClassFixture<Utf8ForwarderFixture>
{
    #region Constructors
    public TypeForwarderUtf8Tests(Utf8ForwarderFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    public static TheoryData<int> Shapes => [.. Enumerable.Range(0, Utf8ForwarderFixture.Shapes.Length)];

    /// <summary>
    /// The premise: the shape is in FwdA's forwarder row (and nowhere a placeholder is left), and SRM's DEFAULT decoder
    /// reads it without complaint — substituting U+FFFD — which is what the strict decoder now refuses.
    /// </summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public void Premise_TheShapeIsInTheForwarderRow_AndALenientReadAcceptsIt(int shape)
    {
        var variant = fixture.Shape(shape);
        using var pe = new PEReader(new MemoryStream(File.ReadAllBytes(variant.FwdA)));
        var metadata = pe.GetMetadataReader();

        var names = metadata.ExportedTypes.Select(metadata.GetExportedType).Select(e => metadata.GetString(e.Name)).ToArray();

        Assert.Equal(Utf8ForwarderFixture.Names.Length, names.Length);
        Assert.DoesNotContain(Utf8ForwarderFixture.Names[shape], names);
        Assert.Contains('�', Assert.Single(names, n => n.StartsWith(Utf8ForwarderFixture.Names[shape][..2], StringComparison.Ordinal)));
    }

    /// <summary>The oracle: the CLR follows the forwarder of the patched name and runs FwdT's body, not the decoy.</summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public void Runtime_AnInvalidUtf8ForwardedName_RunsTheTargetsBody(int shape) =>
        Assert.Equal(Utf8ForwarderFixture.Target, Run(fixture.Shape(shape), Method(shape)));

    /// <summary>C-F: FwdA's forwarders are Unreadable — not None, and not a table missing the patched row.</summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public void Read_AForwardedNameThatIsNotValidUtf8_IsUnreadable(int shape)
    {
        var variant = fixture.Shape(shape);

        TypeForwarders? forwarders = null;
        Assert.Null(Record.Exception(() => forwarders = TypeForwarders.Read(variant.FwdA)));

        Assert.False(forwarders!.IsReadable);
        Assert.True(TypeForwarders.Read(variant.FwdT).IsReadable);
        Assert.True(TypeForwarders.Read(variant.Caller).IsReadable);
    }

    /// <summary>
    /// C-F: the call into FwdA is Unresolved because FwdA's forwarders could not be read — never the decoy (Own), the
    /// answer before the fix — the index counts exactly that one table, and the graph never edges into own code.
    /// </summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public void Resolve_AnInvalidUtf8ForwardedNameWithADecoy_IsUnresolved_NeverOwn(int shape)
    {
        var variant = fixture.Shape(shape);
        using var loaded = ModelAssemblies.Load(variant.FwdA, variant.FwdT, variant.Caller);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);
        Assert.False(loaded.Disassemblers[0].Forwarders.IsReadable);

        var site = Site(index, Method(shape));
        var resolution = index.Resolve(site.Target);

        Assert.Equal(new IndexCoverage(0, 0, 0, 1), index.Coverage);
        Assert.Equal(1, index.Coverage.ForwardersUnreadable);
        Assert.Equal("FwdA", site.DeclaringAssembly);
        Assert.True(resolution.Kind == ResolutionKind.Unresolved,
            $"{resolution.NodeId} resolved {resolution.Kind} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); expected Unresolved.");
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Empty(resolution.Candidates);
        Assert.Equal(("FwdA", "the type forwarders of FwdA could not be read"), (resolution.Assembly, resolution.Reason));
        Assert.All(graph.Successors(Caller(shape)), e => Assert.False(index.IsOwnMethod(e.To), $"{Caller(shape)} edges into own {e.To}."));
        Assert.Contains(graph.Opacities, o => o.Site == Caller(shape) && o.Kind == OpacityKind.Unresolved);
    }

    /// <summary>
    /// The control: the same three assemblies with the ASCII placeholders. FwdA is readable with every name, and each
    /// call is Ambiguous — the decoy and FwdT's definition share one node id — never the decoy alone; the CLR runs FwdT.
    /// </summary>
    [Fact]
    public void Control_AsciiNames_AreReadable_AndAmbiguous_AndRunTheTarget()
    {
        var variant = fixture.Control;
        using var loaded = ModelAssemblies.Load(variant.FwdA, variant.FwdT, variant.Caller);
        var index = loaded.Index();
        var forwarders = loaded.Disassemblers[0].Forwarders;

        Assert.Equal((true, Utf8ForwarderFixture.Names.Length), (forwarders.IsReadable, forwarders.Count));
        Assert.True(index.Coverage.IsComplete);
        for (var i = 0; i < Utf8ForwarderFixture.Names.Length; i++)
        {
            Assert.Equal(["FwdT"], forwarders.Targets("N", Utf8ForwarderFixture.Names[i]));
            var site = Site(index, Method(i));
            var resolution = index.Resolve(site.Target);

            Assert.True(resolution.Kind == ResolutionKind.Ambiguous,
                $"{resolution.NodeId} resolved {resolution.Kind} ({resolution.Reason}); expected Ambiguous.");
            Assert.False(resolution.IsOwn);
            Assert.Equal([site.ReferenceNodeId], resolution.Candidates);
            Assert.Equal(["FwdA", "FwdT"], index.Methods.Where(m => m.NodeId == site.ReferenceNodeId).Select(m => m.Assembly).Order(StringComparer.Ordinal));
            Assert.Equal("FwdA forwards this type, and it resolves into FwdA, FwdT", resolution.Reason);
            Assert.Equal(Utf8ForwarderFixture.Target, Run(variant, Method(i)));
        }
    }

    /// <summary>
    /// A VALID U+FFFD (<c>EF BF BD</c>) in a forwarded name is not an invalid byte: the table stays readable, the row is
    /// keyed on U+FFFD, CCI renders the reference with the same U+FFFD, and so the forward is matched (Ambiguous with
    /// the decoy), not missed.
    /// </summary>
    [Fact]
    public void Read_AValidReplacementCharacterInAForwardedName_IsReadable_AndMatched()
    {
        var variant = fixture.Control;
        var name = Utf8ForwarderFixture.Names[^1];
        Assert.Contains('�', name);
        using var loaded = ModelAssemblies.Load(variant.FwdA, variant.FwdT, variant.Caller);
        var index = loaded.Index();
        var site = Site(index, Method(Utf8ForwarderFixture.Names.Length - 1));

        var resolution = index.Resolve(site.Target);

        Assert.Equal(["FwdT"], TypeForwarders.Read(variant.FwdA).Targets("N", name));
        Assert.Equal($"N.{name}.GetEnvironmentVariable(System.String)", site.ReferenceNodeId);
        Assert.Equal((ResolutionKind.Ambiguous, "FwdA forwards this type, and it resolves into FwdA, FwdT"), (resolution.Kind, resolution.Reason));
    }

    /// <summary>Two builds over the same loads, and one over the files loaded in reversed order, agree site by site and node by node.</summary>
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Build_OverTheSameInputs_InEitherOrder_IsIdentical(int shape)
    {
        var variant = shape < 0 ? fixture.Control : fixture.Shape(shape);
        string[] paths = [variant.FwdA, variant.FwdT, variant.Caller];
        using var forward = ModelAssemblies.Load(paths);
        using var reversed = ModelAssemblies.Load([.. Enumerable.Reverse(paths)]);

        var (first, again, backwards) = (forward.Index(), forward.Index(), reversed.Index());

        var expected = Answers(first);
        Assert.NotEmpty(expected);
        Assert.Equal(expected, Answers(again));
        Assert.Equal(expected, Answers(backwards));
        Assert.Equal(first.Coverage, backwards.Coverage);

        var graph = MethodGraph.Build(first);
        foreach (var other in new[] { MethodGraph.Build(again), MethodGraph.Build(backwards) })
        {
            Assert.Equal(graph.Nodes, other.Nodes);
            Assert.Equal(graph.Edges, other.Edges);
            Assert.Equal(graph.Opacities, other.Opacities);
            Assert.Equal(graph.Coverage, other.Coverage);
        }
    }

    private static string Method(int shape) => $"M{shape + 1}";

    private static string Caller(int shape) => $"Client.Utf8Caller.{Method(shape)}()";

    private static ModelCallSite Site(MemberIndex index, string method) =>
        Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId == $"Client.Utf8Caller.{method}()");

    private static string[] Answers(MemberIndex index) =>
        [.. ModelCallSite.All(index)
            .Select(s => (Site: s, Resolution: index.Resolve(s.Target)))
            .Select(x => string.Join(" | ",
                x.Site.Caller.NodeId, x.Site.Offset, x.Site.Kind, x.Resolution.Kind, x.Resolution.NodeId, x.Resolution.ClassificationKey,
                x.Resolution.Assembly, x.Resolution.IsOwn, x.Resolution.Reason, string.Join(", ", x.Resolution.Candidates)))
            .Order(StringComparer.Ordinal)];

    // Runs Client.Utf8Caller.method() with FwdA and FwdT pinned to the variant's files.
    private static object? Run(Utf8ForwarderFixture.Variant variant, string method)
    {
        using var context = new IsolatedLoadContext(new Dictionary<string, string> { ["FwdA"] = variant.FwdA, ["FwdT"] = variant.FwdT });
        var caller = context.LoadBytes(variant.Caller);
        return caller.GetType("Client.Utf8Caller", throwOnError: true)!.GetMethod(method)!.Invoke(null, null);
    }
    #endregion

    #region Fields
    private readonly Utf8ForwarderFixture fixture;
    #endregion
}

/// <summary>
/// The emitted assemblies of <see cref="TypeForwarderUtf8Tests"/>. Every type is <c>N.&lt;name&gt;</c> with a static
/// <c>GetEnvironmentVariable(string)</c> returning a constant, for each of <see cref="Names"/> (four ASCII placeholders,
/// one per byte shape, and one valid U+FFFD name):
/// <list type="bullet">
/// <item><description>the stub <c>FwdA</c> (decoys) the caller <c>FwdB</c> is emitted against: <c>Client.Utf8Caller.M1..M5</c>
/// each call one name;</description></item>
/// <item><description><see cref="Control"/> — <c>FwdA</c> with the decoys AND a forwarder of every name to <c>FwdT</c>,
/// which defines them returning <see cref="Target"/>, and the caller;</description></item>
/// <item><description><see cref="Shape"/>(i) — copies of the control with placeholder i overwritten by
/// <see cref="Shapes"/>[i] in all three files (the reviewer's whole-entry patch).</description></item>
/// </list>
/// </summary>
public sealed class Utf8ForwarderFixture : IDisposable
{
    #region Constructors
    public Utf8ForwarderFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            var stub = emitted.Save("FwdA", module => Define(module, Decoy), "stub");
            string caller;
            using (var context = new IsolatedLoadContext())
            {
                var loaded = context.LoadBytes(stub);
                caller = emitted.Save("FwdB", module => DefineCaller(module, loaded), "caller");
            }

            Control = new(
                emitted.Save("FwdA", module => Define(module, Decoy), EmittedAssembly.Forwarding([.. Names.Select(n => ("N", n, "FwdT"))]), "ascii"),
                emitted.Save("FwdT", module => Define(module, Target), "ascii"),
                Copy(caller, "ascii"));

            shapes = [.. Shapes.Select((bytes, i) =>
            {
                var variant = new Variant(Copy(Control.FwdA, $"shape{i}"), Copy(Control.FwdT, $"shape{i}"), Copy(Control.Caller, $"shape{i}"));
                foreach (var path in new[] { variant.FwdA, variant.FwdT, variant.Caller })
                {
                    var patched = EmittedAssembly.PatchString(path, Names[i], bytes);
                    if (patched != 1)
                        throw new InvalidOperationException($"'{Names[i]}' patched {patched} times in {path}; expected one #Strings entry.");
                }
                return variant;
            })];
        }
        catch (Exception)
        {
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public Variant Control { get; }
    #endregion

    #region Methods
    public Variant Shape(int index) => shapes[index];

    public void Dispose() => emitted.Dispose();

    private string Copy(string path, string subdirectory)
    {
        var directory = Directory.CreateDirectory(Path.Combine(emitted.Directory, subdirectory)).FullName;
        var copy = Path.Combine(directory, Path.GetFileName(path));
        File.Copy(path, copy);
        return copy;
    }

    private static void Define(ModuleBuilder module, string value)
    {
        foreach (var name in Names)
        {
            var type = module.DefineType("N." + name, StaticClass);
            var il = type.DefineMethod("GetEnvironmentVariable", StaticMethod, typeof(string), [typeof(string)]).GetILGenerator();
            il.Emit(OpCodes.Ldstr, value);
            il.Emit(OpCodes.Ret);
            type.CreateType();
        }
    }

    private static void DefineCaller(ModuleBuilder module, Assembly stub)
    {
        var caller = module.DefineType("Client.Utf8Caller", StaticClass);
        for (var i = 0; i < Names.Length; i++)
        {
            var il = caller.DefineMethod($"M{i + 1}", MethodAttributes.Public | MethodAttributes.Static, typeof(string), Type.EmptyTypes).GetILGenerator();
            il.Emit(OpCodes.Ldstr, "unused");
            il.Emit(OpCodes.Call, stub.GetType("N." + Names[i], throwOnError: true)!.GetMethod("GetEnvironmentVariable")!);
            il.Emit(OpCodes.Ret);
        }
        caller.CreateType();
    }
    #endregion

    #region Fields
    /// <summary>What the decoys return.</summary>
    public const string Decoy = "DECOY-BODY";

    /// <summary>What FwdT's definitions return.</summary>
    public const string Target = "FWDT-BODY";

    /// <summary>The type names: placeholders as long as their shapes (same order), then a valid U+FFFD name.</summary>
    public static readonly string[] Names = ["Ea##Zq", "Eb#Zq", "Ec###Zq", "Ed#Zq", "Ee�Zq"];

    /// <summary>The invalid UTF-8 each placeholder becomes: overlong '.', lone continuation, CESU surrogate, 0xFF.</summary>
    public static readonly byte[][] Shapes =
    [
        [(byte)'E', (byte)'a', 0xC0, 0xAE, (byte)'Z', (byte)'q'],
        [(byte)'E', (byte)'b', 0x80, (byte)'Z', (byte)'q'],
        [(byte)'E', (byte)'c', 0xED, 0xA0, 0x80, (byte)'Z', (byte)'q'],
        [(byte)'E', (byte)'d', 0xFF, (byte)'Z', (byte)'q'],
    ];

    private const TypeAttributes StaticClass = TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class;
    private const MethodAttributes StaticMethod = MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig;

    private readonly EmittedAssembly emitted;
    private readonly Variant[] shapes;
    #endregion

    #region Child types
    public sealed record Variant(string FwdA, string FwdT, string Caller);
    #endregion
}
