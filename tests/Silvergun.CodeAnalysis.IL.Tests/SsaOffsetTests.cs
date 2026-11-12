namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

using ArrayAddrInst = Cilica.IR.ArrayAddrInst;
using CallInst = Cilica.IR.CallInst;
using CilIntrinsic = Cilica.IR.CilIntrinsic;
using FuncAddrInst = Cilica.IR.FuncAddrInst;
using ILCode = Cilica.AsmIO.ILCode;
using ILImporter = Cilica.Frontend.ILImporter;
using IrBody = Cilica.IR.MethodBody;
using IrInstruction = Cilica.IR.Instruction;
using LocalSlot = Cilica.IR.LocalSlot;
using MDArrayMethod = Cilica.AsmIO.MDArrayMethod;
using MemoryInst = Cilica.IR.MemoryInst;
using NewObjInst = Cilica.IR.NewObjInst;
using PhiInst = Cilica.IR.PhiInst;
using SR = System.Reflection;

/// <summary>
/// IL offsets on lifted SSA (docs/agent/tasks/ssa-facts-s4.md S4.1): <see cref="SsaMethodOutcome.ILOffsets"/> is the join
/// key, with the node id, from an SSA call site to its <see cref="MethodEdge"/>. Over one folder (an emitted assembly of
/// the shapes under test, the compiled netstandard2.0 fixture, and the three mechanism fixtures) lifted once and built
/// once as a <see cref="MethodGraph"/>, the graph is the oracle for call sites, and System.Reflection.Metadata's reading
/// of the IL bytes the oracle for offsets the graph has no edge at (MD-array accessors, <c>readonly. ldelema</c>).
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaOffsetTests : IClassFixture<SsaOffsetFixture>
{
    #region Constructors
    public SsaOffsetTests(SsaOffsetFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- The join to MethodGraph ---------------------------------------------------------------------------------------

    /// <summary>
    /// The per-site join (S4.5's, on fixtures): for every method that lifted and whose node id is an own node with a body,
    /// every <c>CallInst</c>, <c>NewObjInst</c>, <c>FuncAddrInst</c> and <c>CilIntrinsic.InitializeArray</c> has an offset,
    /// and the multiset of (node id, offset, kind) over them equals that of the graph's call-site edges from those nodes
    /// (<see cref="MethodEdgeKind.Call"/>, <see cref="MethodEdgeKind.CallVirt"/>, <see cref="MethodEdgeKind.NewObj"/>,
    /// <see cref="MethodEdgeKind.Ldftn"/>, <see cref="MethodEdgeKind.Ldvirtftn"/>).
    /// <para>Left out, each for a stated reason:</para>
    /// <list type="bullet">
    /// <item><description>Calls and <c>newobj</c>s of an MD array's <c>Get</c>/<c>Set</c>/<c>Address</c>/<c>.ctor</c>: CCI
    /// reads them as its <c>Array_*</c> pseudo-operations, so the graph has no edge for them (the known gap pinned by
    /// <see cref="MultiDimensionalArrayCallSiteGapTests"/>). <see cref="Offsets_MdArrayAccessors_Mapped"/> covers them
    /// against the IL instead.</description></item>
    /// <item><description><see cref="MethodEdgeKind.Dispatch"/> edges: CHA's fan-out, added beside a site's own edge at
    /// the same offset, so not a site of their own. Checked here to sit on an SSA site.</description></item>
    /// <item><description><see cref="MethodEdgeKind.StateMachine"/> and <see cref="MethodEdgeKind.TypeInitializer"/>
    /// edges: implied by an instruction (or, for a value type's instance method, at offset 0), never a call the IR
    /// holds.</description></item>
    /// <item><description><see cref="MethodEdgeKind.LoadToken"/> edges: an <c>ldtoken</c> of a method is a
    /// <c>CilIntrinsic.LoadHandle</c> in the IR, not a call.</description></item>
    /// <item><description>Methods that did not lift (no IR), and node ids shared with one that did not.</description></item>
    /// </list>
    /// An Ambiguous site (<see cref="OpacityKind.Ambiguous"/>) has one edge per candidate, all at its instruction's
    /// offset, so it counts as one graph site (the mechanism fixture's <c>Resolution</c> callers hold four).
    /// </summary>
    [Fact]
    public void Offsets_CallNewobjLdftn_MatchMethodEdgeOffsets()
    {
        var joined = fixture.JoinedNodeIds;
        var ssa = new List<string>();
        foreach (var outcome in fixture.Lifted.Outcomes.Where(o => joined.Contains(o.NodeId)))
        {
            foreach (var (instruction, kind) in CallSites(outcome.Body!))
            {
                var offset = outcome.OffsetOf(instruction);
                Assert.True(offset is not null, $"{SsaText.Of(outcome)}: a {instruction.GetType().Name} has no IL offset.");
                ssa.Add(Site(outcome.NodeId, offset!.Value, kind));
            }
        }
        // An Ambiguous site has one edge per candidate, all at its one instruction's offset: one site.
        var ambiguous = AmbiguousSites();
        var graph = fixture.Graph.Edges.Where(e => joined.Contains(e.From) && callSiteKinds.Contains(e.Kind))
            .GroupBy(e => Site(e.From, e.Offset, e.Kind), StringComparer.Ordinal)
            .SelectMany(g => Enumerable.Repeat(g.Key, ambiguous.Contains((g.First().From, g.First().Offset)) ? 1 : g.Count()))
            .ToList();

        // Vacuity: a real folder, with every kind of site, Ambiguous ones, and the InitializeArray intrinsic among the Call sites.
        Assert.True(joined.Count > 100, $"Only {joined.Count} joined methods.");
        Assert.NotEmpty(ambiguous);
        Assert.All(callSiteKinds, kind => Assert.Contains(ssa, s => s.EndsWith(" | " + kind, StringComparison.Ordinal)));
        Assert.Contains(fixture.Lifted.Outcomes.Where(o => joined.Contains(o.NodeId)), o => o.Body!.Instructions().Any(i => i is CilIntrinsic.InitializeArray));

        AssertSameMultiset(graph, ssa, "graph edge", "SSA site");
    }

    /// <summary>
    /// The preconditions the multiset comparison above rests on, and S4.5's node-id join on these fixtures: every method
    /// that lifted joins to an own node with a body, except <c>&lt;Module&gt;</c>'s (which the model does not load,
    /// <see cref="OpacityKind.ModuleInitializerInvisible"/>); and the only offsets of a joined node with more than one
    /// call-site edge are Ambiguous sites (one edge per candidate), which the join counts once.
    /// </summary>
    [Fact]
    public void Offsets_JoinPreconditions_EveryLiftedMethodJoins_OnlyAmbiguousSitesFanOut()
    {
        var bodied = fixture.Graph.Nodes.Where(n => n.Kind == MethodNodeKind.OwnWithBody).Select(n => n.NodeId).ToHashSet(StringComparer.Ordinal);
        var ambiguous = AmbiguousSites();

        var unjoined = fixture.Lifted.Outcomes.Where(o => o.IsLifted && !bodied.Contains(o.NodeId) && o.Method.DeclaringType.NestingChain[^1] != "<Module>")
            .Select(SsaText.Of).ToArray();
        var fannedOut = fixture.Graph.Edges.Where(e => fixture.JoinedNodeIds.Contains(e.From) && callSiteKinds.Contains(e.Kind))
            .GroupBy(e => (e.From, e.Offset)).Where(g => g.Count() > 1).Select(g => g.Key).ToArray();

        Assert.True(unjoined.Length == 0, "Lifted methods with no own node:\n" + string.Join("\n", unjoined));
        Assert.NotEmpty(fannedOut);
        Assert.All(fannedOut, site => Assert.True(ambiguous.Contains(site), $"{SsaText.Printable(site.From)} has several call-site edges at IL_{site.Offset:X4} and no Ambiguous opacity."));
    }

    /// <summary>A <see cref="MethodEdgeKind.Dispatch"/> edge sits beside its site's own edge, so on an SSA site.</summary>
    [Fact]
    public void Offsets_EveryDispatchEdge_SitsOnAnSsaCallSite()
    {
        var sites = fixture.Lifted.Outcomes.Where(o => fixture.JoinedNodeIds.Contains(o.NodeId))
            .SelectMany(o => CallSites(o.Body!).Select(s => (o.NodeId, o.OffsetOf(s.Instruction) ?? uint.MaxValue))).ToHashSet();
        var dispatch = fixture.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.Dispatch && fixture.JoinedNodeIds.Contains(e.From)).ToArray();

        Assert.NotEmpty(dispatch);
        Assert.All(dispatch, e => Assert.True(sites.Contains((e.From, e.Offset)), $"Dispatch edge {SsaText.Printable(e.From)} -> {SsaText.Printable(e.To)} at IL_{e.Offset:X4} has no SSA site."));
    }

    // ---- Prefixes ------------------------------------------------------------------------------------------------------

    /// <summary>
    /// The open prefix question (spec §1): a prefixed call's edge sits at the prefixed opcode's own offset, not the
    /// prefix's, and the SSA site's offset is the same. Checked for <c>constrained. callvirt</c> on a generic receiver,
    /// <c>tail. call</c>, and <c>constrained. callvirt</c> after a <c>readonly. ldelema</c>.
    /// </summary>
    [Theory]
    [InlineData("ConstrainedToString", 0xFE16, 0x6F, MethodEdgeKind.CallVirt)]
    [InlineData("TailCall", 0xFE14, 0x28, MethodEdgeKind.Call)]
    [InlineData("ReadonlyElementToString", 0xFE16, 0x6F, MethodEdgeKind.CallVirt)]
    public void Offsets_PrefixedCall_UsesTheModelsConvention(string method, int prefix, int opcode, MethodEdgeKind kind)
    {
        var outcome = fixture.Lifted.Of(SsaOffsetFixture.SitesType, method);
        SsaLifted.AssertLifted(outcome);
        var (prefixAt, opcodeAt) = Prefixed(fixture.EmittedPath, method, (short)prefix, (short)opcode);

        var edges = fixture.Graph.Successors(outcome.NodeId).Where(e => callSiteKinds.Contains(e.Kind)).ToArray();
        var call = Assert.Single(CallSites(outcome.Body!));

        Assert.Equal(new[] { (kind, (uint)opcodeAt) }, edges.Select(e => (e.Kind, e.Offset)));
        Assert.Equal((uint?)opcodeAt, outcome.OffsetOf(call.Instruction));
        Assert.NotEqual((uint?)prefixAt, outcome.OffsetOf(call.Instruction));
    }

    /// <summary><c>readonly. ldelema</c> (no edge): the <c>ArrayAddrInst</c> takes the <c>ldelema</c>'s offset.</summary>
    [Fact]
    public void Offsets_ReadonlyLdelema_IsTheLdelemasOffset()
    {
        var outcome = fixture.Lifted.Of(SsaOffsetFixture.SitesType, "ReadonlyElementToString");
        var (prefixAt, ldelemaAt) = Prefixed(fixture.EmittedPath, "ReadonlyElementToString", unchecked((short)0xFE1E), 0x8F);

        var address = Assert.Single(outcome.Body!.Instructions().OfType<ArrayAddrInst>());

        Assert.True(address.IsReadOnly);
        Assert.Equal((uint?)ldelemaAt, outcome.OffsetOf(address));
        Assert.NotEqual((uint?)prefixAt, outcome.OffsetOf(address));
    }

    /// <summary>
    /// Folder-wide: every recorded offset is the start of an IL instruction of the method, and never a prefix's (so no
    /// prefixed instruction anywhere, of any kind, takes its prefix's offset).
    /// </summary>
    [Fact]
    public void Offsets_EveryRecordedOffset_IsAnInstructionStart_NeverAPrefix()
    {
        var checkedOffsets = 0;
        foreach (var outcome in fixture.Lifted.Outcomes.Where(o => o.IsLifted))
        {
            var starts = outcome.Body!.Definition.ILBody!.Instructions.ToDictionary(i => i.Offset, i => i.OpCode);
            foreach (var offset in outcome.ILOffsets.Values)
            {
                Assert.True(starts.TryGetValue(offset, out var code), $"{SsaText.Of(outcome)}: IL_{offset:X4} is not an instruction start.");
                Assert.False(prefixes.Contains(code), $"{SsaText.Of(outcome)}: IL_{offset:X4} is a {code} prefix.");
                checkedOffsets++;
            }
        }
        Assert.True(checkedOffsets > 1000, $"Only {checkedOffsets} offsets checked.");
    }

    // ---- MD arrays -----------------------------------------------------------------------------------------------------

    /// <summary>
    /// MD-array <c>Get</c>, <c>Set</c>, <c>Address</c> (also <c>readonly.</c>-prefixed) and both <c>newobj</c> forms (CCI's
    /// <c>Array_*</c> pseudo-operations; Cilica's <c>MDArrayMethod</c>) take their call's or <c>newobj</c>'s offset, in csc's
    /// shape and an emitted one. The graph has no edge at any of them: why the join above leaves them out.
    /// </summary>
    [Theory]
    [InlineData(SsaOffsetFixture.SitesType, "MdArrays")]
    [InlineData("MultiDimArrayOps", "CopiesMatrixCellsAndReadsAFile")]
    public void Offsets_MdArrayAccessors_Mapped(string type, string method)
    {
        var outcome = fixture.Lifted.Of(type, method);
        SsaLifted.AssertLifted(outcome);
        var expected = MdArraySites(outcome.AssemblyPath, type, method);

        var actual = outcome.Body!.Instructions()
            .Select(i => (Instruction: i, Name: i switch
            {
                CallInst { Method: MDArrayMethod m } => m.Name,
                NewObjInst { Constructor: MDArrayMethod m } => m.Name,
                _ => null,
            }))
            .Where(p => p.Name is not null)
            .Select(p => $"{p.Name} @ IL_{outcome.OffsetOf(p.Instruction):X4}")
            .ToList();

        Assert.Contains(expected, s => s.StartsWith("Get ", StringComparison.Ordinal));
        Assert.Contains(expected, s => s.StartsWith("Set ", StringComparison.Ordinal));
        Assert.Contains(expected, s => s.StartsWith("Address ", StringComparison.Ordinal));
        Assert.Contains(expected, s => s.StartsWith(".ctor ", StringComparison.Ordinal));
        AssertSameMultiset(expected, actual, "IL accessor", "SSA accessor");
        var edgeOffsets = fixture.Graph.Successors(outcome.NodeId).Where(e => callSiteKinds.Contains(e.Kind)).Select(e => $"IL_{e.Offset:X4}").ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain(expected, s => edgeOffsets.Contains(s[(s.IndexOf('@') + 2)..]));
    }

    /// <summary>The emitted <c>readonly. call int32[,]::Address</c> takes the call's offset, not the prefix's.</summary>
    [Fact]
    public void Offsets_ReadonlyMdArrayAddress_IsTheCallsOffset()
    {
        var outcome = fixture.Lifted.Of(SsaOffsetFixture.SitesType, "MdArrays");
        var (prefixAt, callAt) = Prefixed(fixture.EmittedPath, "MdArrays", unchecked((short)0xFE1E), 0x28);

        var address = Assert.Single(outcome.Body!.Instructions().OfType<CallInst>(), c => c.Method is MDArrayMethod { Kind: MDArrayMethod.OpKind.Address });

        Assert.True(address.IsReadOnly);
        Assert.Equal((uint?)callAt, outcome.OffsetOf(address));
        Assert.NotEqual((uint?)prefixAt, outcome.OffsetOf(address));
    }

    // ---- SSA promotion -------------------------------------------------------------------------------------------------

    /// <summary>
    /// A local that holds a call's result across blocks: the importer stores and loads it through a slot (recorded with
    /// offsets), and promotion replaces those with a phi. The call keeps its offset, and the table holds only instructions
    /// still in the body.
    /// </summary>
    [Fact]
    public void Offsets_SurviveSsaPromotion()
    {
        var outcome = fixture.Lifted.Of(SsaOffsetFixture.SitesType, "Promoted");
        SsaLifted.AssertLifted(outcome);
        var body = outcome.Body!;
        var callAt = Decode(fixture.EmittedPath, SsaOffsetFixture.SitesType, "Promoted").Single(op => op.Code == 0x28).Offset;

        // The importer's own table, before promotion, held slot loads and stores.
        var raw = new Dictionary<IrInstruction, int>(ReferenceEqualityComparer.Instance);
        ILImporter.ParseCode(body.Definition, raw);
        Assert.Contains(raw.Keys, i => i is MemoryInst { Address: LocalSlot });

        // Promotion removed them and put a phi in.
        var instructions = body.Instructions().ToHashSet<IrInstruction>(ReferenceEqualityComparer.Instance);
        Assert.DoesNotContain(instructions, i => i is MemoryInst { Address: LocalSlot });
        Assert.Contains(instructions, i => i is PhiInst);

        var call = Assert.Single(instructions.OfType<CallInst>());
        Assert.Equal((uint?)callAt, outcome.OffsetOf(call));
        Assert.All(outcome.ILOffsets.Keys, i => Assert.Contains(i, instructions));
        Assert.True(raw.Count > outcome.ILOffsets.Count, $"The importer recorded {raw.Count}, the outcome kept {outcome.ILOffsets.Count}.");
    }

    /// <summary>Folder-wide: every lifted outcome's table holds only instructions of its own body.</summary>
    [Fact]
    public void Offsets_EveryTable_HoldsOnlyItsBodysInstructions()
    {
        var lifted = fixture.Lifted.Outcomes.Where(o => o.IsLifted).ToArray();

        Assert.NotEmpty(lifted);
        foreach (var outcome in lifted)
        {
            var instructions = outcome.Body!.Instructions().ToHashSet<IrInstruction>(ReferenceEqualityComparer.Instance);
            Assert.True(outcome.ILOffsets.Keys.All(instructions.Contains), $"{SsaText.Of(outcome)} has offsets for instructions not in its body.");
        }
    }

    // ---- Not lifted, and no entry --------------------------------------------------------------------------------------

    /// <summary>A method that did not lift (<c>jmp</c>, which Cilica does not import) has no body and an empty table.</summary>
    [Fact]
    public void Offsets_NotLifted_EmptyTable()
    {
        var unknown = fixture.Lifted.Of(SsaOffsetFixture.SitesType, "Jumper");
        var promoted = fixture.Lifted.Of(SsaOffsetFixture.SitesType, "Promoted");

        Assert.False(unknown.IsLifted, $"{SsaText.Of(unknown)} lifted: the fixture no longer gives an Unknown.");
        Assert.Null(unknown.Body);
        Assert.Empty(unknown.ILOffsets);
        Assert.Null(unknown.OffsetOf(promoted.Body!.Instructions().First()));
        Assert.All(fixture.Lifted.Outcomes.Where(o => !o.IsLifted), o => Assert.Empty(o.ILOffsets));
        Assert.Empty(new SsaMethodOutcome("x.dll", 0, promoted.Method, new SsaFailure(SsaFailureKind.Import, "x"), null).ILOffsets);
    }

    /// <summary>An instruction the importer synthesized (the phi) or that belongs to another body has no offset.</summary>
    [Fact]
    public void Offsets_InstructionNotInTable_IsNull()
    {
        var promoted = fixture.Lifted.Of(SsaOffsetFixture.SitesType, "Promoted");
        var other = fixture.Lifted.Of(SsaOffsetFixture.SitesType, "TailCall");

        Assert.Null(promoted.OffsetOf(promoted.Body!.Instructions().OfType<PhiInst>().First()));
        Assert.Null(promoted.OffsetOf(CallSites(other.Body!).Single().Instruction));
    }

    // ---- Option off ----------------------------------------------------------------------------------------------------

    /// <summary>Importing without a table gives the same body, instruction for instruction, as importing with one.</summary>
    [Fact]
    public void Offsets_OptionOff_BodyUnchanged()
    {
        var outcomes = fixture.Lifted.Outcomes.Where(o => o.IsLifted && o.AssemblyPath == fixture.EmittedPath).ToArray();

        Assert.True(outcomes.Length >= 8, $"Only {outcomes.Length} emitted methods lifted.");
        foreach (var outcome in outcomes)
        {
            var without = ILImporter.ParseCode(outcome.Body!.Definition);
            var with = ILImporter.ParseCode(outcome.Body.Definition, new Dictionary<IrInstruction, int>(ReferenceEqualityComparer.Instance));
            Assert.Equal(Shape(without), Shape(with));
        }
    }

    // ---- Determinism ---------------------------------------------------------------------------------------------------

    /// <summary>Two sessions over the folder record the same (node id, offset, instruction kind) list, in body order.</summary>
    [Fact]
    public void Offsets_TwoLifts_AreIdentical()
    {
        string[] Run()
        {
            using var lifted = new SsaLifted(fixture.Paths);
            return lifted.Outcomes.Where(o => o.IsLifted)
                .SelectMany(o => o.Body!.Instructions().Where(o.ILOffsets.ContainsKey).Select(i => $"{o.NodeId} | {o.OffsetOf(i)} | {i.GetType().Name}"))
                .ToArray();
        }
        var first = Run();
        var second = Run();

        Assert.True(first.Length > 1000, $"Only {first.Length} offsets recorded.");
        Assert.Equal(first, second);
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    // The IR's call sites, with the edge kind the graph gives the same IL: an MD-array accessor is none (no edge).
    private static IEnumerable<(IrInstruction Instruction, MethodEdgeKind Kind)> CallSites(IrBody body)
    {
        foreach (var instruction in body.Instructions())
        {
            MethodEdgeKind? kind = instruction switch
            {
                CallInst { Method: MDArrayMethod } or NewObjInst { Constructor: MDArrayMethod } => null,
                CallInst call => call.IsVirtual ? MethodEdgeKind.CallVirt : MethodEdgeKind.Call,
                NewObjInst => MethodEdgeKind.NewObj,
                FuncAddrInst function => function.IsVirtual ? MethodEdgeKind.Ldvirtftn : MethodEdgeKind.Ldftn,
                CilIntrinsic.InitializeArray => MethodEdgeKind.Call,
                _ => null,
            };
            if (kind is { } k)
                yield return (instruction, k);
        }
    }

    private static string Site(string nodeId, uint offset, MethodEdgeKind kind) => $"{nodeId} | IL_{offset:X4} | {kind}";

    // The (node id, offset) of every Ambiguous call site of a joined node.
    private HashSet<(string From, uint Offset)> AmbiguousSites() =>
        fixture.Graph.Opacities.Where(o => o.Kind == OpacityKind.Ambiguous && fixture.JoinedNodeIds.Contains(o.Site)).Select(o => (o.Site, o.Offset)).ToHashSet();

    // Multiset equality, failing with what each side has that the other has not.
    private static void AssertSameMultiset(IReadOnlyList<string> expected, IReadOnlyList<string> actual, string expectedName, string actualName)
    {
        static Dictionary<string, int> Count(IEnumerable<string> items) =>
            items.GroupBy(s => s, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);
        var (e, a) = (Count(expected), Count(actual));
        var onlyExpected = e.Where(p => a.GetValueOrDefault(p.Key) < p.Value).Select(p => $"{p.Key} x{p.Value - a.GetValueOrDefault(p.Key)}").Order(StringComparer.Ordinal).ToArray();
        var onlyActual = a.Where(p => e.GetValueOrDefault(p.Key) < p.Value).Select(p => $"{p.Key} x{p.Value - e.GetValueOrDefault(p.Key)}").Order(StringComparer.Ordinal).ToArray();
        Assert.True(onlyExpected.Length == 0 && onlyActual.Length == 0,
            SsaText.Printable($"{expected.Count} {expectedName}s, {actual.Count} {actualName}s.") + "\n"
            + $"{onlyExpected.Length} {expectedName}(s) with no {actualName}:\n  " + string.Join("\n  ", onlyExpected.Take(40).Select(SsaText.Printable)) + "\n"
            + $"{onlyActual.Length} {actualName}(s) with no {expectedName}:\n  " + string.Join("\n  ", onlyActual.Take(40).Select(SsaText.Printable)));
    }

    // The block-by-block shape of a body: instruction types, operand counts and result types.
    private static List<string> Shape(IrBody body)
    {
        var shape = new List<string>();
        foreach (var block in body)
        {
            shape.Add("block");
            foreach (var instruction in block)
                shape.Add($"{instruction.GetType().Name}/{instruction.Operands.Length}/{instruction.ResultType}");
        }
        return shape;
    }

    // The offsets of a prefix and of the instruction right after it, asserting what that instruction is.
    private static (int Prefix, int Prefixed) Prefixed(string path, string method, short prefix, short opcode)
    {
        var ops = Decode(path, SsaOffsetFixture.SitesType, method);
        var at = ops.FindIndex(op => op.Code == prefix);
        Assert.True(at >= 0 && at + 1 < ops.Count, $"{method} has no 0x{prefix:X4} prefix.");
        Assert.Equal(opcode, ops[at + 1].Code);
        return (ops[at].Offset, ops[at + 1].Offset);
    }

    // The MD-array accessor sites of a method, read from its IL: InlineMethod operands that are MemberRefs on an ARRAY TypeSpec.
    private static List<string> MdArraySites(string path, string type, string method)
    {
        using var pe = new PEReader(File.OpenRead(path));
        var reader = pe.GetMetadataReader();
        return Decode(pe, reader, type, method)
            .Where(op => op.Token != 0 && MetadataTokens.EntityHandle(op.Token) is { Kind: HandleKind.MemberReference } handle
                && reader.GetMemberReference((MemberReferenceHandle)handle) is { Parent.Kind: HandleKind.TypeSpecification } member
                && reader.GetBlobReader(reader.GetTypeSpecification((TypeSpecificationHandle)member.Parent).Signature).ReadByte() == 0x14)
            .Select(op => $"{reader.GetString(reader.GetMemberReference((MemberReferenceHandle)MetadataTokens.EntityHandle(op.Token)).Name)} @ IL_{op.Offset:X4}")
            .ToList();
    }

    internal static List<IlOp> Decode(string path, string type, string method)
    {
        using var pe = new PEReader(File.OpenRead(path));
        return Decode(pe, pe.GetMetadataReader(), type, method);
    }

    // One method body's instructions, decoded with operand sizes from System.Reflection.Emit.OpCodes (plus no., which it
    // lacks), so no operand byte is read as an opcode. The token is kept for InlineMethod operands.
    private static List<IlOp> Decode(PEReader pe, MetadataReader reader, string type, string method)
    {
        var definitions = reader.TypeDefinitions.Select(reader.GetTypeDefinition).Where(t => reader.GetString(t.Name) == type)
            .SelectMany(t => t.GetMethods()).Select(reader.GetMethodDefinition).Where(m => reader.GetString(m.Name) == method).ToArray();
        Assert.True(definitions.Length == 1, $"Expected one {type}::{method}, found {definitions.Length}.");
        var il = pe.GetMethodBody(definitions[0].RelativeVirtualAddress).GetILContent();

        var ops = new List<IlOp>();
        for (var i = 0; i < il.Length;)
        {
            var start = i;
            var code = il[i] == 0xFE ? unchecked((short)(0xFE00 | il[i + 1])) : il[i];
            i += il[i] == 0xFE ? 2 : 1;
            var operand = code == NoPrefix ? SR.Emit.OperandType.ShortInlineI
                : operandTypes.TryGetValue(code, out var known) ? known
                : throw new InvalidOperationException($"Unknown IL opcode 0x{code:X4} at IL_{start:X4}: the decoder is out of step.");
            ops.Add(new IlOp(start, code, operand == SR.Emit.OperandType.InlineMethod ? BitConverter.ToInt32(il.AsSpan()[i..(i + 4)]) : 0));
            i += operand switch
            {
                SR.Emit.OperandType.InlineNone => 0,
                SR.Emit.OperandType.ShortInlineBrTarget or SR.Emit.OperandType.ShortInlineI or SR.Emit.OperandType.ShortInlineVar => 1,
                SR.Emit.OperandType.InlineVar => 2,
                SR.Emit.OperandType.InlineI8 or SR.Emit.OperandType.InlineR => 8,
                SR.Emit.OperandType.InlineSwitch => 4 + 4 * BitConverter.ToInt32(il.AsSpan()[i..(i + 4)]),
                _ => 4,
            };
        }
        return ops;
    }
    #endregion

    #region Fields
    private const short NoPrefix = unchecked((short)0xFE19);

    private static readonly MethodEdgeKind[] callSiteKinds =
        [MethodEdgeKind.Call, MethodEdgeKind.CallVirt, MethodEdgeKind.NewObj, MethodEdgeKind.Ldftn, MethodEdgeKind.Ldvirtftn];

    private static readonly HashSet<ILCode> prefixes =
        [ILCode.Constrained_, ILCode.Tail_, ILCode.Readonly_, ILCode.Volatile_, ILCode.Unaligned_, ILCode.No_];

    private static readonly IReadOnlyDictionary<short, SR.Emit.OperandType> operandTypes = typeof(OpCodes)
        .GetFields(SR.BindingFlags.Public | SR.BindingFlags.Static)
        .Select(f => (OpCode)f.GetValue(null)!)
        .DistinctBy(o => o.Value)
        .ToDictionary(o => o.Value, o => o.OperandType);

    private readonly SsaOffsetFixture fixture;
    #endregion

    #region Child types
    internal sealed record IlOp(int Offset, short Code, int Token);
    #endregion
}

/// <summary>
/// One folder, lifted once and built once as a <see cref="MethodGraph"/> (both read it as metadata only):
/// <list type="bullet">
/// <item><description><c>SsaOffsets</c>, emitted with <see cref="PersistedAssemblyBuilder"/>: the prefixed calls, both
/// function-pointer loads, <c>RuntimeHelpers.InitializeArray</c>, MD-array accessors (one <c>readonly.</c>), a local that
/// promotion rewrites, and a <c>jmp</c> (which Cilica does not import, so an Unknown);</description></item>
/// <item><description>the compiled netstandard2.0 fixture (csc's MD-array accessors);</description></item>
/// <item><description>the mechanism fixture, its Dependency and its Debug build (delegates, lambdas, generics, dispatch,
/// state machines).</description></item>
/// </list>
/// </summary>
public sealed class SsaOffsetFixture : IDisposable
{
    #region Constructors
    public SsaOffsetFixture()
    {
        EmittedPath = emitted.Save("SsaOffsets", DefineSites);
        Paths = [EmittedPath, SsaBodyFixture.CompiledFixturePath, MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency, MechanismFixtureAssemblies.DebugFixture];
        using (var model = ModelAssemblies.Load(Paths))
            Graph = MethodGraph.Build(model.Index());
        Lifted = new SsaLifted(Paths);

        var bodied = Graph.Nodes.Where(n => n.Kind == MethodNodeKind.OwnWithBody).Select(n => n.NodeId).ToHashSet(StringComparer.Ordinal);
        var unknown = Lifted.Outcomes.Where(o => !o.IsLifted).Select(o => o.NodeId).ToHashSet(StringComparer.Ordinal);
        JoinedNodeIds = Lifted.Outcomes.Where(o => o.IsLifted && bodied.Contains(o.NodeId) && !unknown.Contains(o.NodeId))
            .Select(o => o.NodeId).ToHashSet(StringComparer.Ordinal);
    }
    #endregion

    #region Properties
    public string EmittedPath { get; }

    public string[] Paths { get; }

    public MethodGraph Graph { get; }

    /// <summary>Node ids whose every definition lifted, and that are own nodes with a body in <see cref="Graph"/>.</summary>
    public IReadOnlySet<string> JoinedNodeIds { get; }

    internal SsaLifted Lifted { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Lifted.Dispose();
        emitted.Dispose();
    }

    private static void DefineSites(ModuleBuilder module)
    {
        var sites = module.DefineType("Offsets." + SitesType, SR.TypeAttributes.Public | SR.TypeAttributes.Class);
        var toString = typeof(object).GetMethod(nameof(ToString), Type.EmptyTypes)!;

        var target = Static(sites, "Target", typeof(int), typeof(int));
        Body(target, il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ret);
        });

        // constrained. callvirt object::ToString on a T receiver.
        var constrained = sites.DefineMethod("ConstrainedToString", SR.MethodAttributes.Public | SR.MethodAttributes.Static);
        var t = constrained.DefineGenericParameters("T")[0];
        constrained.SetSignature(typeof(string), null, null, [t], null, null);
        Body(constrained, il =>
        {
            il.Emit(OpCodes.Ldarga_S, (byte)0);
            il.Emit(OpCodes.Constrained, t);
            il.Emit(OpCodes.Callvirt, toString);
            il.Emit(OpCodes.Ret);
        });

        // readonly. ldelema !!0, then constrained. callvirt: csc's shape for a call on a T[] element.
        var element = sites.DefineMethod("ReadonlyElementToString", SR.MethodAttributes.Public | SR.MethodAttributes.Static);
        var e = element.DefineGenericParameters("T")[0];
        element.SetSignature(typeof(string), null, null, [e.MakeArrayType()], null, null);
        Body(element, il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Readonly);
            il.Emit(OpCodes.Ldelema, e);
            il.Emit(OpCodes.Constrained, e);
            il.Emit(OpCodes.Callvirt, toString);
            il.Emit(OpCodes.Ret);
        });

        Body(Static(sites, "TailCall", typeof(int), typeof(int)), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Tailcall);
            il.Emit(OpCodes.Call, target);
            il.Emit(OpCodes.Ret);
        });

        Body(Static(sites, "VirtualFunction", typeof(string), typeof(object)), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldvirtftn, toString);
            il.Emit(OpCodes.Newobj, typeof(Func<string>).GetConstructor([typeof(object), typeof(IntPtr)])!);
            il.Emit(OpCodes.Callvirt, typeof(Func<string>).GetMethod("Invoke")!);
            il.Emit(OpCodes.Ret);
        });

        Body(Static(sites, "StaticFunction", typeof(object)), il =>
        {
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ldftn, target);
            il.Emit(OpCodes.Newobj, typeof(Func<int, int>).GetConstructor([typeof(object), typeof(IntPtr)])!);
            il.Emit(OpCodes.Ret);
        });

        // new int[] { 1, 2, 3, 4 }, as csc writes it: Cilica imports the call as CilIntrinsic.InitializeArray.
        var data = sites.DefineInitializedData("Data", [1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0], SR.FieldAttributes.Assembly | SR.FieldAttributes.Static);
        Body(Static(sites, "InitializedArray", typeof(int[])), il =>
        {
            il.Emit(OpCodes.Ldc_I4_4);
            il.Emit(OpCodes.Newarr, typeof(int));
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldtoken, data);
            il.Emit(OpCodes.Call, typeof(System.Runtime.CompilerServices.RuntimeHelpers).GetMethod("InitializeArray", [typeof(Array), typeof(RuntimeFieldHandle)])!);
            il.Emit(OpCodes.Ret);
        });

        // A call's result in a local stored in two blocks and loaded in a third: a slot, until promotion makes it a phi.
        Body(Static(sites, "Promoted", typeof(int), typeof(int)), il =>
        {
            var join = il.DefineLabel();
            il.DeclareLocal(typeof(int));
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Call, target);
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Brfalse_S, join);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Add);
            il.Emit(OpCodes.Stloc_0);
            il.MarkLabel(join);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ret);
        });

        // Every MD-array accessor: both constructors, Set, readonly. Address, Get.
        Body(Static(sites, "MdArrays", typeof(int)), il =>
        {
            var matrix = typeof(int[,]);
            il.DeclareLocal(matrix);
            il.Emit(OpCodes.Ldc_I4_2);
            il.Emit(OpCodes.Ldc_I4_3);
            il.Emit(OpCodes.Newobj, matrix.GetConstructor([typeof(int), typeof(int)])!);
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Ldc_I4_7);
            il.Emit(OpCodes.Call, matrix.GetMethod("Set")!);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Readonly);
            il.Emit(OpCodes.Call, matrix.GetMethod("Address")!);
            il.Emit(OpCodes.Ldind_I4);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Call, matrix.GetMethod("Get")!);
            il.Emit(OpCodes.Add);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Ldc_I4_2);
            il.Emit(OpCodes.Ldc_I4_3);
            il.Emit(OpCodes.Ldc_I4_4);
            il.Emit(OpCodes.Newobj, matrix.GetConstructor([typeof(int), typeof(int), typeof(int), typeof(int)])!);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });

        // jmp: valid IL that Cilica's importer does not take, so the method is Unknown.
        Body(Static(sites, "Jumper", typeof(int), typeof(int)), il => il.Emit(OpCodes.Jmp, target));

        sites.CreateType();
    }

    private static MethodBuilder Static(TypeBuilder type, string name, Type returns, params Type[] parameters) =>
        type.DefineMethod(name, SR.MethodAttributes.Public | SR.MethodAttributes.Static, returns, parameters);

    private static void Body(MethodBuilder method, Action<ILGenerator> emit) => emit(method.GetILGenerator());
    #endregion

    #region Fields
    public const string SitesType = "OffsetSites";

    private readonly EmittedAssembly emitted = new();
    #endregion
}
