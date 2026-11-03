namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <see cref="TypeForwarders"/> on its own (review 4, C-E): reading the <c>ExportedType</c> table of a file — never
/// throwing, and never mistaking "could not read" for "forwards nothing" — and the coarse (namespace, name) key that
/// <see cref="MemberIndex.Resolve"/> matches references against. How the index USES the table is pinned in
/// <see cref="TypeForwarderResolutionTests"/>.
/// </summary>
public sealed class TypeForwarderTests
{
    #region Methods
    // ---- Read --------------------------------------------------------------------------------------------------------

    [Fact]
    public void Read_AnAssemblyWithAForwarder_IsReadable_WithItsTarget()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.Save("Forwards", Marker, EmittedAssembly.Forwarding(("System", "Environment", Core)));

        var forwarders = TypeForwarders.Read(path);

        Assert.True(forwarders.IsReadable);
        Assert.Equal(1, forwarders.Count);
        Assert.Equal([Core], forwarders.Targets("System", "Environment"));
        Assert.Empty(forwarders.Targets("System", "Console"));
    }

    [Fact]
    public void Read_AnAssemblyWithoutForwarders_IsReadable_AndEmpty()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.Save("Plain", Marker);

        var forwarders = TypeForwarders.Read(path);

        Assert.True(forwarders.IsReadable);
        Assert.Equal(0, forwarders.Count);
        Assert.Empty(forwarders.Targets("System", "Environment"));
    }

    /// <summary>
    /// Only TOP-LEVEL rows are kept: one whose implementation is another ASSEMBLY as a forward (<see cref="TypeForwarders.Targets"/>),
    /// one implemented by a File row — a type exported from another module of this assembly — as a module export
    /// (<see cref="TypeForwarders.Modules"/>, review 5 W-B), never as a forward. A nested exported type (implementation:
    /// its enclosing ExportedType row — exported with it) is dropped either way.
    /// </summary>
    [Fact]
    public void Read_KeepsTopLevelRows_ForwardsAsTargets_FileExportsAsModules_DropsNestedRows()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.Save("Mixed", Marker, metadata =>
        {
            var environment = EmittedAssembly.Forward(metadata, "System", "Environment", EmittedAssembly.Reference(metadata, Core));
            metadata.AddExportedType(TypeAttributes.NestedPublic, default, metadata.GetOrAddString("SpecialFolder"), environment, 0);
            var module = metadata.AddAssemblyFile(metadata.GetOrAddString("Other.netmodule"), metadata.GetOrAddBlob(new byte[20]), containsMetadata: true);
            var thing = metadata.AddExportedType(TypeAttributes.Public, metadata.GetOrAddString("Other"), metadata.GetOrAddString("Thing"), module, 0);
            metadata.AddExportedType(TypeAttributes.NestedPublic, default, metadata.GetOrAddString("Inner"), thing, 0);
        });

        var forwarders = TypeForwarders.Read(path);

        Assert.True(forwarders.IsReadable);
        Assert.Equal(2, forwarders.Count);
        Assert.Equal([Core], forwarders.Targets("System", "Environment"));
        Assert.Empty(forwarders.Modules("System", "Environment"));
        Assert.Equal(["Other.netmodule"], forwarders.Modules("Other", "Thing"));
        Assert.Empty(forwarders.Targets("Other", "Thing"));
        foreach (var (space, name) in new[] { ("", "SpecialFolder"), ("System", "SpecialFolder"), ("", "Inner"), ("Other", "Inner") })
        {
            Assert.Empty(forwarders.Targets(space, name));
            Assert.Empty(forwarders.Modules(space, name));
        }
    }

    /// <summary>An assembly whose only exported row is a module export is readable, with that one name.</summary>
    [Fact]
    public void Read_AnAssemblyWithOnlyAModuleExport_CountsIt()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.Save("Modular", Marker, EmittedAssembly.ExportingFromModule("Modular2.netmodule", ("System", "Environment"), ("P", "Q`1")));

        var forwarders = TypeForwarders.Read(path);

        Assert.Equal((true, 2), (forwarders.IsReadable, forwarders.Count));
        Assert.Equal(["Modular2.netmodule"], forwarders.Modules("System", "Environment"));
        Assert.Equal(["Modular2.netmodule"], forwarders.Modules(".P", "Q`2"));
        Assert.Empty(forwarders.Targets("System", "Environment"));
    }

    // ---- the end of the #Strings heap (review 5 C-F, scoped by review 6 W-C) -----------------------------------------
    //
    // CCI's string reader drops the last byte of a string that runs to the end of the heap with no NUL, so such a
    // string decodes differently there than in SRM. Only strings a KEPT row uses (namespace, name, AssemblyRef or File
    // name of a top-level row) can mislead the index, so only those make the table Unreadable. The last entry is placed
    // by name: MetadataBuilder orders #Strings by reversed text, so a string ending in '~' (above every letter) is last —
    // and each test checks that premise on the file before patching it.

    /// <summary>
    /// The last <c>#Strings</c> entry is a string a kept row uses — its namespace, its name, the forward's target
    /// assembly, or the module export's file — and it is made to run unterminated to the end of the heap: Unreadable.
    /// The premise checks SRM still opens the file and reads the row leniently, so the terminator is the only reason.
    /// </summary>
    [Theory]
    [InlineData("namespace")]
    [InlineData("name")]
    [InlineData("assembly")]
    [InlineData("module")]
    public void Read_AnUnterminatedLastStringThatAKeptRowUses_IsUnreadable(string part)
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.Save("Unterminated", Marker, part switch
        {
            "namespace" => EmittedAssembly.Forwarding((Last, "Environment", Core)),
            "name" => EmittedAssembly.Forwarding(("System", Last, Core)),
            "assembly" => EmittedAssembly.Forwarding(("System", "Environment", Last)),
            _ => EmittedAssembly.ExportingFromModule(Last, ("System", "Environment")),
        });
        Assert.Equal((true, 1), (TypeForwarders.Read(path).IsReadable, TypeForwarders.Read(path).Count));

        Assert.Equal(Last, EmittedAssembly.UnterminateLastStringsEntry(path));

        AssertSrmStillReadsOneExportedRow(path);
        TypeForwarders? forwarders = null;
        Assert.Null(Record.Exception(() => forwarders = TypeForwarders.Read(path)));
        Assert.False(forwarders!.IsReadable);
    }

    /// <summary>
    /// W-C: the unterminated last entry is a string NO kept row uses — a TypeDef's name, a NESTED exported row's name
    /// (nested rows are never matched), or anything in an assembly with no exported rows at all: readable, with the kept
    /// rows intact.
    /// </summary>
    [Theory]
    [InlineData("typedef", 1)]
    [InlineData("nested-row", 1)]
    [InlineData("no-rows", 0)]
    public void Read_AnUnterminatedLastStringThatNoKeptRowUses_IsReadable(string placement, int count)
    {
        using var emitted = new EmittedAssembly();
        void Define(System.Reflection.Emit.ModuleBuilder module) =>
            module.DefineType(placement == "nested-row" ? "Plain.Marker" : "Plain." + Last, TypeAttributes.Public | TypeAttributes.Class).CreateType();
        var path = placement switch
        {
            "no-rows" => emitted.Save("Unterminated", Define),
            "nested-row" => emitted.Save("Unterminated", Define, metadata =>
            {
                var environment = EmittedAssembly.Forward(metadata, "System", "Environment", EmittedAssembly.Reference(metadata, Core));
                metadata.AddExportedType(TypeAttributes.NestedPublic, default, metadata.GetOrAddString(Last), environment, 0);
            }),
            _ => emitted.Save("Unterminated", Define, EmittedAssembly.Forwarding(("System", "Environment", Core))),
        };

        Assert.Equal(Last, EmittedAssembly.UnterminateLastStringsEntry(path));

        AssertStringsHeapEndsIn(path, (byte)'X');
        var forwarders = TypeForwarders.Read(path);
        Assert.True(forwarders.IsReadable);
        Assert.Equal(count, forwarders.Count);
        Assert.Equal(count == 0 ? Array.Empty<string>() : [Core], forwarders.Targets("System", "Environment"));
    }

    /// <summary>
    /// W-C: junk after the last terminator — only the final alignment-padding byte of <c>#Strings</c> is non-NUL, every
    /// string is terminated. Readable, with the forward intact (this was Unreadable under the review 5 check).
    /// </summary>
    [Fact]
    public void Read_JunkPaddingAfterTheLastTerminator_IsReadable_WithItsRowsIntact()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.SaveWithJunkStringsPadding("Junk", Marker, EmittedAssembly.Forwarding(("System", "Environment", Core)), "junk");

        AssertStringsHeapEndsIn(path, (byte)'X');
        AssertSrmStillReadsOneExportedRow(path);
        var forwarders = TypeForwarders.Read(path);

        Assert.Equal((true, 1), (forwarders.IsReadable, forwarders.Count));
        Assert.Equal([Core], forwarders.Targets("System", "Environment"));
    }

    /// <summary>
    /// W-C: only KEPT rows are decoded. A nested exported row whose name is not valid UTF-8, under a valid top-level
    /// forwarder, leaves the table readable — nested rows are never matched — and the top-level forward still matches.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Read_AnInvalidUtf8NestedRowName_UnderAValidForwarder_IsReadable(int shape)
    {
        using var emitted = new EmittedAssembly();
        var placeholder = Utf8ForwarderFixture.Names[shape];
        var path = emitted.Save("NestedUtf8", Marker, metadata =>
        {
            var environment = EmittedAssembly.Forward(metadata, "System", "Environment", EmittedAssembly.Reference(metadata, Core));
            metadata.AddExportedType(TypeAttributes.NestedPublic, default, metadata.GetOrAddString(placeholder), environment, 0);
        });
        Assert.Equal(1, EmittedAssembly.PatchString(path, placeholder, Utf8ForwarderFixture.Shapes[shape]));
        using (var pe = new PEReader(new MemoryStream(File.ReadAllBytes(path))))
        {
            var metadata = pe.GetMetadataReader();
            var nested = metadata.ExportedTypes.Select(metadata.GetExportedType).Single(e => e.Implementation.Kind == HandleKind.ExportedType);
            Assert.Contains('�', metadata.GetString(nested.Name));
        }

        var forwarders = TypeForwarders.Read(path);

        Assert.Equal((true, 1), (forwarders.IsReadable, forwarders.Count));
        Assert.Equal([Core], forwarders.Targets("System", "Environment"));
    }

    /// <summary>The contrast: the same invalid name on a TOP-LEVEL forwarder next to the valid one makes the table Unreadable.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Read_AnInvalidUtf8TopLevelRowName_NextToAValidForwarder_IsUnreadable(int shape)
    {
        using var emitted = new EmittedAssembly();
        var placeholder = Utf8ForwarderFixture.Names[shape];
        var path = emitted.Save("TopUtf8", Marker, EmittedAssembly.Forwarding(("System", "Environment", Core), ("N", placeholder, Core)));
        Assert.Equal(2, TypeForwarders.Read(path).Count);
        Assert.Equal(1, EmittedAssembly.PatchString(path, placeholder, Utf8ForwarderFixture.Shapes[shape]));

        Assert.False(TypeForwarders.Read(path).IsReadable);
    }

    /// <summary>
    /// A real facade: the running platform's own System.Runtime.dll forwards (nearly) everything to
    /// System.Private.CoreLib, nested types included as nested rows — which are not kept as top-level names.
    /// </summary>
    [Fact]
    public void Read_ThePlatformsSystemRuntimeFacade_ForwardsEnvironmentToCoreLib()
    {
        var facade = Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "System.Runtime.dll");
        Assert.True(File.Exists(facade), $"No System.Runtime.dll next to CoreLib at '{facade}'.");

        var forwarders = TypeForwarders.Read(facade);

        Assert.True(forwarders.IsReadable);
        Assert.True(forwarders.Count > 100, $"Only {forwarders.Count} forwarded names in System.Runtime.");
        Assert.Equal([Core], forwarders.Targets("System", "Environment"));
        Assert.Equal([Core], forwarders.Targets("System", "Nullable`1"));
        Assert.Equal([Core], forwarders.Targets("System", "Nullable"));
        Assert.Empty(forwarders.Targets("", "SpecialFolder"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("does-not-exist.dll")]
    public void Read_AMissingPath_IsUnreadable_NotNone(string? name)
    {
        using var emitted = new EmittedAssembly();
        var path = name is "does-not-exist.dll" ? Path.Combine(emitted.Directory, name) : name;

        TypeForwarders? forwarders = null;
        Assert.Null(Record.Exception(() => forwarders = TypeForwarders.Read(path)));

        Assert.False(forwarders!.IsReadable);
        Assert.Equal(0, forwarders.Count);
        Assert.NotSame(TypeForwarders.None, forwarders);
    }

    [Fact]
    public void Read_ADirectory_IsUnreadable()
    {
        using var emitted = new EmittedAssembly();

        Assert.False(TypeForwarders.Read(emitted.Directory).IsReadable);
    }

    /// <summary>
    /// Bytes that are not a managed PE — text, random bytes, an empty file, a bare MZ stub, a managed PE cut off in
    /// the middle of its metadata — are Unreadable, never None.
    /// </summary>
    [Theory]
    [InlineData("text")]
    [InlineData("random")]
    [InlineData("empty")]
    [InlineData("mz-only")]
    [InlineData("truncated")]
    public void Read_AFileThatIsNotAWholeManagedPE_IsUnreadable(string kind)
    {
        using var emitted = new EmittedAssembly();
        var whole = File.ReadAllBytes(emitted.Save("Whole", Marker, EmittedAssembly.Forwarding(("System", "Environment", Core))));
        byte[] bytes = kind switch
        {
            "text" => "This is not an assembly."u8.ToArray(),
            "random" => RandomBytes(4096),
            "empty" => [],
            "mz-only" => [(byte)'M', (byte)'Z', .. new byte[62]],
            _ => whole[..MidMetadata(whole)],
        };
        var path = Path.Combine(emitted.Directory, kind + ".dll");
        File.WriteAllBytes(path, bytes);

        TypeForwarders? forwarders = null;
        Assert.Null(Record.Exception(() => forwarders = TypeForwarders.Read(path)));

        Assert.False(forwarders!.IsReadable, $"{kind}: read as {forwarders.Count} forwarded names.");
        Assert.Equal(1, TypeForwarders.Read(Path.Combine(emitted.Directory, "Whole.dll")).Count);
    }

    /// <summary>A native PE (no CLI header) has no metadata, so whether it forwards anything is unknown: Unreadable.</summary>
    [Fact]
    public void Read_APEWithoutMetadata_IsUnreadable()
    {
        using var emitted = new EmittedAssembly();
        var path = Path.Combine(emitted.Directory, "native.dll");
        var blob = new BlobBuilder();
        new NativeImage().Serialize(blob);
        File.WriteAllBytes(path, blob.ToArray());
        using (var pe = new PEReader(File.OpenRead(path)))
            Assert.False(pe.HasMetadata);

        Assert.False(TypeForwarders.Read(path).IsReadable);
    }

    /// <summary>
    /// Every compiled fixture the index tests load forwards nothing and is read in full — both straight from the file
    /// and as <see cref="AssemblyDisassembler.Forwarders"/> — so the pinned baselines built over them see no change.
    /// </summary>
    [Fact]
    public void Read_EveryCompiledIndexFixture_IsReadable_AndForwardsNothing()
    {
        string[] paths = [MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency, SharedFixtureMethodGraphFixture.Path, ShadowFixtureAssembly.Path];

        Assert.All(paths, path =>
        {
            var forwarders = TypeForwarders.Read(path);
            Assert.True(forwarders.IsReadable && forwarders.Count == 0, $"{path}: readable {forwarders.IsReadable}, {forwarders.Count} forwarded names.");
        });

        using var loaded = ModelAssemblies.Load(paths);
        Assert.All(loaded.Disassemblers, d =>
            Assert.True(d.Forwarders.IsReadable && d.Forwarders.Count == 0, $"{d.AssemblyPath}: readable {d.Forwarders.IsReadable}, {d.Forwarders.Count} forwarded names."));
        Assert.True(loaded.Index().Coverage.IsComplete);
    }

    // ---- None / Unreadable --------------------------------------------------------------------------------------------

    [Fact]
    public void None_IsReadable_AndEmpty_UnreadableIsNot()
    {
        Assert.True(TypeForwarders.None.IsReadable);
        Assert.Equal(0, TypeForwarders.None.Count);
        Assert.Empty(TypeForwarders.None.Targets("System", "Environment"));

        Assert.False(TypeForwarders.Unreadable.IsReadable);
        Assert.Equal(0, TypeForwarders.Unreadable.Count);
        Assert.Empty(TypeForwarders.Unreadable.Targets("System", "Environment"));
    }

    // ---- the coarse key -----------------------------------------------------------------------------------------------

    /// <summary>
    /// The key ignores leading dots of the namespace and everything from the first backtick of the name, on BOTH sides:
    /// CCI drops exactly those parts of a reference's names, inconsistently.
    /// </summary>
    [Theory]
    [InlineData("System", "Environment", "System", "Environment")]
    [InlineData("System", "Environment", ".System", "Environment")]
    [InlineData(".System", "Environment", "System", "Environment")]
    [InlineData("..System", "Environment", ".System", "Environment")]
    [InlineData("P", "Q`1", "P", "Q")]
    [InlineData("P", "Q`1", "P", "Q`1")]
    [InlineData("P", "Q`1", "P", "Q`2")]
    [InlineData("P", "Q", "P", "Q`1")]
    [InlineData("P", "Q`1`2", "P", "Q")]
    public void Targets_MatchCoarsely(string rowSpace, string rowName, string space, string name) =>
        Assert.Equal(["Target"], TypeForwarders.Of([(rowSpace, rowName, "Target")]).Targets(space, name));

    /// <summary>Coarse, not loose: a different namespace or a different name before the backtick never matches.</summary>
    [Theory]
    [InlineData("P", "R")]
    [InlineData("P", "QQ`1")]
    [InlineData("P", "Q1")]
    [InlineData("P.Q", "Q`1")]
    [InlineData("R", "Q`1")]
    [InlineData("Q", "P`1")]
    [InlineData("", "Q`1")]
    public void Targets_DoNotMatchAnotherName(string space, string name) =>
        Assert.Empty(TypeForwarders.Of([("P", "Q`1", "Target")]).Targets(space, name));

    // ---- Of -------------------------------------------------------------------------------------------------------

    [Fact]
    public void Of_NoRows_IsReadable_AndEmpty()
    {
        var forwarders = TypeForwarders.Of([]);

        Assert.True(forwarders.IsReadable);
        Assert.Equal(0, forwarders.Count);
    }

    /// <summary>
    /// One coarse name forwarded to several assemblies (e.g. <c>Q`1</c> and <c>Q`2</c>, which share a key) keeps every
    /// target, ordinal-sorted; assembly names are deduplicated case-insensitively, keeping the ordinal-least spelling —
    /// whatever the row order.
    /// </summary>
    [Fact]
    public void Of_UnionsTargetsPerCoarseName_SortedAndDedupedCaseInsensitively_InAnyOrder()
    {
        (string?, string?, string?)[] rows =
        [
            ("P", "Q`1", "zeta"),
            ("P", "Q`2", "alpha"),
            ("P", "Q", "ZETA"),
            (".P", "Q", "Alpha"),
            ("System", "Environment", Core),
        ];

        var forwarders = TypeForwarders.Of(rows);
        var reversed = TypeForwarders.Of(Enumerable.Reverse(rows));

        Assert.Equal(2, forwarders.Count);
        Assert.Equal(["Alpha", "ZETA"], forwarders.Targets("P", "Q"));
        Assert.Equal(forwarders.Targets("P", "Q"), reversed.Targets("P", "Q"));
        Assert.Equal([Core], forwarders.Targets("System", "Environment"));
    }

    /// <summary>A row part that could not be read is kept as <see cref="CanonicalName.UnknownPart"/>, never dropped.</summary>
    [Fact]
    public void Of_KeepsUnreadablePartsAsUnknown()
    {
        var forwarders = TypeForwarders.Of([(null, null, null), ("System", "Environment", null)]);

        Assert.Equal(2, forwarders.Count);
        Assert.Equal([CanonicalName.UnknownPart], forwarders.Targets(null, null));
        Assert.Equal([CanonicalName.UnknownPart], forwarders.Targets(CanonicalName.UnknownPart, CanonicalName.UnknownPart));
        Assert.Equal([CanonicalName.UnknownPart], forwarders.Targets("System", "Environment"));
    }

    // ---- Of: module exports (review 5 W-B) ------------------------------------------------------------------------

    [Fact]
    public void None_And_Unreadable_HaveNoModules()
    {
        Assert.Empty(TypeForwarders.None.Modules("System", "Environment"));
        Assert.Empty(TypeForwarders.Unreadable.Modules("System", "Environment"));
        Assert.Empty(TypeForwarders.Of([("System", "Environment", Core)]).Modules("System", "Environment"));
    }

    /// <summary>A module row is a module export, never a forward target; it counts as one name.</summary>
    [Fact]
    public void Of_AModuleRow_IsAModule_NotATarget()
    {
        var forwarders = TypeForwarders.Of([], [("System", "Environment", "A2.netmodule")]);

        Assert.True(forwarders.IsReadable);
        Assert.Equal(1, forwarders.Count);
        Assert.Equal(["A2.netmodule"], forwarders.Modules("System", "Environment"));
        Assert.Empty(forwarders.Targets("System", "Environment"));
        Assert.Empty(forwarders.Modules("System", "Console"));
    }

    /// <summary>
    /// <see cref="TypeForwarders.Count"/> counts coarse names having EITHER kind: one name both forwarded and
    /// module-exported counts once and keeps both; names of one kind each count separately.
    /// </summary>
    [Fact]
    public void Count_CountsNamesWithEitherKind_Once()
    {
        var both = TypeForwarders.Of([("System", "Environment", Core)], [(".System", "Environment", "A2.netmodule")]);
        var apart = TypeForwarders.Of([("System", "Environment", Core)], [("P", "Q`1", "A2.netmodule")]);

        Assert.Equal(1, both.Count);
        Assert.Equal([Core], both.Targets("System", "Environment"));
        Assert.Equal(["A2.netmodule"], both.Modules("System", "Environment"));
        Assert.Equal(2, apart.Count);
        Assert.Empty(apart.Modules("System", "Environment"));
        Assert.Empty(apart.Targets("P", "Q"));
        Assert.Equal(["A2.netmodule"], apart.Modules("P", "Q"));
    }

    /// <summary>Module exports are matched with the same coarse key as forwards, on both sides.</summary>
    [Theory]
    [InlineData("System", "Environment", ".System", "Environment")]
    [InlineData("..System", "Environment", "System", "Environment")]
    [InlineData("P", "Q`1", "P", "Q`2")]
    [InlineData("P", "Q", "P", "Q`1")]
    public void Modules_MatchCoarsely(string rowSpace, string rowName, string space, string name) =>
        Assert.Equal(["M.netmodule"], TypeForwarders.Of([], [(rowSpace, rowName, "M.netmodule")]).Modules(space, name));

    [Theory]
    [InlineData("P", "R")]
    [InlineData("P", "QQ`1")]
    [InlineData("R", "Q`1")]
    [InlineData("", "Q`1")]
    public void Modules_DoNotMatchAnotherName(string space, string name) =>
        Assert.Empty(TypeForwarders.Of([], [("P", "Q`1", "M.netmodule")]).Modules(space, name));

    /// <summary>Module files per coarse name are ordinal-sorted and deduplicated case-insensitively to the ordinal-least spelling, in any row order.</summary>
    [Fact]
    public void Of_UnionsModulesPerCoarseName_SortedAndDedupedCaseInsensitively_InAnyOrder()
    {
        (string?, string?, string?)[] rows = [("P", "Q`1", "b.netmodule"), ("P", "Q", "B.NETMODULE"), (".P", "Q`2", "a.netmodule"), ("P", "Q", "A.netmodule")];

        var forwarders = TypeForwarders.Of([], rows);
        var reversed = TypeForwarders.Of([], Enumerable.Reverse(rows));

        Assert.Equal(1, forwarders.Count);
        Assert.Equal(["A.netmodule", "B.NETMODULE"], forwarders.Modules("P", "Q"));
        Assert.Equal(forwarders.Modules("P", "Q"), reversed.Modules("P", "Q"));
    }

    /// <summary>
    /// An unreadable NAME part of a module row is kept as <see cref="CanonicalName.UnknownPart"/> (as for forwards); an
    /// unreadable MODULE FILE name must stay a module export — kept as <see cref="CanonicalName.UnknownPart"/> among the
    /// modules — and must never turn into a forward to an assembly called <c>&lt;unknown&gt;</c>.
    /// </summary>
    [Fact]
    public void Of_KeepsUnreadableModuleRowPartsAsUnknownModules()
    {
        var forwarders = TypeForwarders.Of([], [(null, null, "M.netmodule"), ("System", "Environment", null)]);

        Assert.Equal(2, forwarders.Count);
        Assert.Equal(["M.netmodule"], forwarders.Modules(CanonicalName.UnknownPart, CanonicalName.UnknownPart));
        Assert.Empty(forwarders.Targets(null, null));
        Assert.Empty(forwarders.Targets("System", "Environment"));
        Assert.Equal([CanonicalName.UnknownPart], forwarders.Modules("System", "Environment"));
    }

    // ---- Merge -------------------------------------------------------------------------------------------------------

    /// <summary>Merge unions module exports per coarse name too, deduplicated case-insensitively, in either order; Count spans both kinds.</summary>
    [Fact]
    public void Merge_UnionsModulesToo_InEitherOrder()
    {
        var first = TypeForwarders.Of([("System", "Environment", Core)], [("P", "Q", "m.netmodule")]);
        var second = TypeForwarders.Of([], [("P", "Q`1", "M.NETMODULE"), ("System", "Environment", "x.netmodule"), ("A", "B", "y.netmodule")]);

        var merged = TypeForwarders.Merge([first, TypeForwarders.None, second]);
        var reversed = TypeForwarders.Merge([second, first]);

        Assert.True(merged.IsReadable);
        Assert.Equal(3, merged.Count);
        Assert.Equal(["M.NETMODULE"], merged.Modules("P", "Q"));
        Assert.Equal([Core], merged.Targets("System", "Environment"));
        Assert.Equal(["x.netmodule"], merged.Modules("System", "Environment"));
        Assert.Equal(["y.netmodule"], merged.Modules("A", "B"));
        Assert.Empty(merged.Targets("A", "B"));
        Assert.Equal(merged.Count, reversed.Count);
        Assert.All(new[] { ("P", "Q"), ("System", "Environment"), ("A", "B") }, key =>
        {
            Assert.Equal(merged.Modules(key.Item1, key.Item2), reversed.Modules(key.Item1, key.Item2));
            Assert.Equal(merged.Targets(key.Item1, key.Item2), reversed.Targets(key.Item1, key.Item2));
        });
    }

    [Fact]
    public void Merge_AModulePartWithAnUnreadablePart_IsUnreadable() =>
        Assert.Same(TypeForwarders.Unreadable, TypeForwarders.Merge([TypeForwarders.Of([], [("P", "Q", "m.netmodule")]), TypeForwarders.Unreadable]));

    [Fact]
    public void Merge_Nothing_IsReadable_AndEmpty()
    {
        var merged = TypeForwarders.Merge([]);

        Assert.True(merged.IsReadable);
        Assert.Equal(0, merged.Count);
    }

    /// <summary>One unreadable or missing (null) part makes the whole merge unreadable: it might forward anything.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Merge_WithAnUnreadableOrMissingPart_IsUnreadable(bool missing)
    {
        var part = missing ? null : TypeForwarders.Unreadable;

        Assert.Same(TypeForwarders.Unreadable, TypeForwarders.Merge([TypeForwarders.Of([("System", "Environment", Core)]), part]));
        Assert.Same(TypeForwarders.Unreadable, TypeForwarders.Merge([part, TypeForwarders.None]));
        Assert.Same(TypeForwarders.Unreadable, TypeForwarders.Merge([part]));
    }

    /// <summary>
    /// Readable parts (one assembly name loaded twice) union per coarse name, case-insensitively deduplicated to the
    /// ordinal-least spelling, the same in either order.
    /// </summary>
    [Fact]
    public void Merge_ReadableParts_UnionTheirTargets_InEitherOrder()
    {
        var first = TypeForwarders.Of([("P", "Q`1", "b"), ("System", "Environment", Core)]);
        var second = TypeForwarders.Of([("P", "Q", "B"), ("P", "Q`2", "a"), ("NS", "T", "FwdT")]);

        var merged = TypeForwarders.Merge([first, TypeForwarders.None, second]);
        var reversed = TypeForwarders.Merge([second, first]);

        Assert.True(merged.IsReadable);
        Assert.Equal(3, merged.Count);
        Assert.Equal(["B", "a"], merged.Targets("P", "Q"));
        Assert.Equal([Core], merged.Targets("System", "Environment"));
        Assert.Equal(["FwdT"], merged.Targets("NS", "T"));
        Assert.Equal(merged.Count, reversed.Count);
        Assert.All(new[] { ("P", "Q"), ("System", "Environment"), ("NS", "T") }, key =>
            Assert.Equal(merged.Targets(key.Item1, key.Item2), reversed.Targets(key.Item1, key.Item2)));
    }

    private static void Marker(System.Reflection.Emit.ModuleBuilder module) =>
        module.DefineType("Plain.Marker", TypeAttributes.Public | TypeAttributes.Class).CreateType();

    private static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        new Random(20261102).NextBytes(bytes);
        return bytes;
    }

    // SRM still opens the patched file, sees one exported row and decodes it (leniently).
    private static void AssertSrmStillReadsOneExportedRow(string path)
    {
        using var pe = new PEReader(new MemoryStream(File.ReadAllBytes(path)));
        var metadata = pe.GetMetadataReader();
        Assert.Single(metadata.ExportedTypes.Select(metadata.GetExportedType).Where(e => e.Implementation.Kind != HandleKind.ExportedType)
            .Select(e => $"{metadata.GetString(e.Namespace)}.{metadata.GetString(e.Name)}").ToArray());
    }

    // The last byte of the #Strings heap as SRM sees it (it trims trailing NULs only, so a non-NUL tail is kept).
    private static void AssertStringsHeapEndsIn(string path, byte expected)
    {
        using var pe = new PEReader(new MemoryStream(File.ReadAllBytes(path)));
        var metadata = pe.GetMetadataReader();
        Assert.Equal(expected, pe.GetMetadata().GetContent(metadata.GetHeapMetadataOffset(HeapIndex.String) + metadata.GetHeapSize(HeapIndex.String) - 1, 1)[0]);
    }

    // A file offset halfway through the image's metadata: the headers still parse, the tables cannot be read.
    private static int MidMetadata(byte[] image)
    {
        using var pe = new PEReader(new MemoryStream(image));
        return pe.PEHeaders.MetadataStartOffset + pe.PEHeaders.MetadataSize / 2;
    }
    #endregion

    #region Fields
    private const string Core = "System.Private.CoreLib";

    // Sorts last in a MetadataBuilder #Strings heap (see the heap-end tests).
    private const string Last = "Last~";
    #endregion

    #region Child types
    /// <summary>A minimal native DLL image: one code section, no CLI header.</summary>
    private sealed class NativeImage() : PEBuilder(new PEHeaderBuilder(imageCharacteristics: Characteristics.Dll), deterministicIdProvider: null)
    {
        protected override ImmutableArray<Section> CreateSections() =>
            [new Section(".text", SectionCharacteristics.ContainsCode | SectionCharacteristics.MemRead | SectionCharacteristics.MemExecute)];

        protected override BlobBuilder SerializeSection(string name, SectionLocation location)
        {
            var section = new BlobBuilder();
            section.WriteBytes(0xC3, 16);
            return section;
        }

        protected override PEDirectoriesBuilder GetDirectories() => new();
    }
    #endregion
}
